package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VerifiedFreshInstallTarget
import com.velumtegra.xuimobile.core.domain.WorkingDatabaseRestoreConfirmation
import com.velumtegra.xuimobile.core.domain.RestoredPanelStartConfirmation
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartPostVerifySshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRecoveryDiagnosisSshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRecoveryRepairSshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartSshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationReinstallPostVerifySshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationReinstallSshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationUninstallSshAdapter
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationUninstallAbsenceSshAdapter
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallSshVerifier
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory

sealed interface ExactRuntimeSessionCloseResult {
    data object Closed : ExactRuntimeSessionCloseResult
    data object StaleOrAlreadyClosed : ExactRuntimeSessionCloseResult
    data class ContractViolation(val reason: String) : ExactRuntimeSessionCloseResult
}

/**
 * Process-scoped Phase 4 runtime orchestration boundary.
 *
 * Android/UI execution hosts must route operation-runtime callbacks through one process-scoped
 * instance of this coordinator. Durable truth remains in [OperationJournal]; this class owns only
 * the shared ephemeral runtime state that must not fork inside one app process:
 * - one exact OperationId runtime-lease registry;
 * - one connectivity generation/reconnect-permit gate.
 *
 * The coordinator composes the already-proven Phase 4.4 bootstrap, admission, reconnect,
 * stale-CAS and reconciliation barriers. Phase 8.7 adds the typed Installer path; Phase 9.4 adds exact RESTART, Phase 9.5 adds read-only-first RECOVERY repair, and Phase 9.6 adds exact UNINSTALL with absence-only verification, and Phase 9.7 adds compound managed REINSTALL with verified same-row republish:
 * exact reviewed plan, fresh process-local authority, durable/process mutation barriers and exact
 * operation-owned SSH. It exposes no arbitrary remote-command surface and does not make a
 * foreground Service durable state.
 */
class OperationRuntimeCoordinator(
    journal: OperationJournal,
    accessRepository: ServerAccessRepository,
    connectionFactory: SshConnectionFactory,
    private val sessionRegistry: ExactSessionRegistry,
    installationRepository: XuiInstallationRepository? = null,
    managementAccessRepository: ManagementAccessRepository? = null,
    managementEnrollmentPublisher: ManagementEnrollmentPublisher? = null,
    featureReconciliationPort: FeatureReconciliationPort = FeatureReconciliationPort {
        FeatureReconciliationPortResult.Unsupported
    },
    initialConnectivityState: ConnectivityState = ConnectivityState.UNKNOWN,
    nanoTime: () -> Long = System::nanoTime,
) {
    /** Shares the existing same-server gate with recovery writers. No new runtime/store or replay.
     * Caller validates exact completed source and durable barriers inside the lease before credentials.
     */
    suspend fun <T : Any> withRecoveryPanelReadLease(
        serverId: com.velumtegra.xuimobile.core.model.ServerId,
        sourceOperationId: OperationId,
        read: suspend () -> T,
    ): T? {
        val acquired = serverMutationRegistry.tryAcquire(serverId, sourceOperationId)
            as? ServerMutationAcquireResult.Acquired ?: return null
        return try { read() } finally { serverMutationRegistry.release(acquired.lease) }
    }

    /** Explicit compensating return uses the SAME server gate. Caller keeps the exact uncertain
     * parent barrier and must checkpoint/consume authority before dispatch; no replay entry. */
    suspend fun <T : Any> withBeforeCopyReturnLease(serverId: com.velumtegra.xuimobile.core.model.ServerId,
        sourceOperationId: OperationId, action: suspend () -> T): T? =
        withRecoveryPanelReadLease(serverId, sourceOperationId, action)

    private val runtimeRegistry = OperationRuntimeLeaseRegistry()

    /** Process serialization only, never durable consent, dispatch authority or outcome proof.
     * Dedicated debug setup must independently check current journal and exact pinned ownership. */
    suspend fun <T : Any> withExclusiveServerMaintenanceLease(
        serverId: com.velumtegra.xuimobile.core.model.ServerId,
        operationId: OperationId,
        action: suspend () -> T,
    ): T? {
        val acquired = serverMutationRegistry.tryAcquire(serverId, operationId)
            as? ServerMutationAcquireResult.Acquired ?: return null
        return try { action() } finally { serverMutationRegistry.release(acquired.lease) }
    }

    private val serverMutationRegistry = ServerMutationLeaseRegistry()
    private val installerEntryRegistry = InstallerRuntimeEntryRegistry()
    private val restartEntryRegistry = ExistingInstallationRestartEntryRegistry()
    private val recoveryEntryRegistry = ExistingInstallationRecoveryEntryRegistry()
    private val uninstallEntryRegistry = ExistingInstallationUninstallEntryRegistry()
    private val reinstallEntryRegistry = ExistingInstallationReinstallEntryRegistry()
    private val connectivityGate = ConnectivityReconnectPermitGate(initialConnectivityState)

    private val recoveryBootstrap = OperationRecoveryBootstrap(journal)
    private val recoveryAdmission = OperationRecoveryAdmissionGate(journal, runtimeRegistry)
    private val reconnectOrchestrator = ExactReconnectOrchestrator(
        runtimeRegistry = runtimeRegistry,
        connectivityGate = connectivityGate,
        accessRepository = accessRepository,
        connectionFactory = connectionFactory,
        sessionRegistry = sessionRegistry,
        nanoTime = nanoTime,
    )
    private val staleCasReload = OperationStaleCasReloadGate(journal)
    private val discovery = DiscoveryRuntimeCoordinator(
        journal = journal,
        runtimeRegistry = runtimeRegistry,
        sessionRegistry = sessionRegistry,
    )
    private val management = if (installationRepository != null && managementAccessRepository != null) {
        ManagementRuntimeCoordinator(
            journal = journal,
            installationRepository = installationRepository,
            managementAccessRepository = managementAccessRepository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
        )
    } else {
        null
    }
    private val deepDiagnostic = if (installationRepository != null && managementAccessRepository != null) {
        DeepDiagnosticRuntimeCoordinator(
            journal = journal,
            installationRepository = installationRepository,
            managementAccessRepository = managementAccessRepository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
        )
    } else {
        null
    }
    private val serviceLogs = if (installationRepository != null && managementAccessRepository != null) {
        ServiceLogRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
            runtimeRegistry, sessionRegistry, accessRepository = accessRepository)
    } else null
    private val updatePreflight = if (installationRepository != null && managementAccessRepository != null) {
        UpdatePreflightRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
            runtimeRegistry, sessionRegistry, accessRepository = accessRepository)
    } else null
    private val installationBackup = InstallationBackupRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
        accessRepository, runtimeRegistry, sessionRegistry, serverMutationRegistry)
    private val restoreCheck = RestoreCheckRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
        accessRepository, runtimeRegistry, sessionRegistry, serverMutationRegistry)
    private val workingDatabaseRestore = WorkingDatabaseRestoreRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
        accessRepository, runtimeRegistry, sessionRegistry, serverMutationRegistry)
    private val restoredPanelStart = RestoredPanelStartRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
        accessRepository, runtimeRegistry, sessionRegistry, serverMutationRegistry)
    private val restoreCompatibility = RestoreCompatibilityRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
        accessRepository, runtimeRegistry, sessionRegistry, serverMutationRegistry)
    private val databaseBackup = DatabaseBackupRuntimeCoordinator(journal, installationRepository, managementAccessRepository,
        accessRepository, runtimeRegistry, sessionRegistry, serverMutationRegistry)
    private val restart = installationRepository?.let { repository ->
        ExistingInstallationRestartRuntimeCoordinator(
            journal = journal,
            installationRepository = repository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = restartEntryRegistry,
            dispatchPort = ExistingInstallationRestartDispatchPort { preflight, plan, current, session ->
                ExistingInstallationRestartSshAdapter(journal).dispatch(preflight, plan, current, session)
            },
            postVerifyPort = ExistingInstallationRestartPostVerifyPort { current, installation, session ->
                ExistingInstallationRestartPostVerifySshAdapter().verify(current, installation, session)
            },
            accessRepository = accessRepository,
            preflightPort = ExistingInstallationRestartPreflightPort { current, installation, access, session, barrier ->
                com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartPreflightSshAdapter().verify(current, installation, access, session, barrier)
            },
        )
    }

    private val existingInstallationRecovery = installationRepository?.let { repository ->
        ExistingInstallationRecoveryRuntimeCoordinator(
            journal = journal,
            installationRepository = repository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = recoveryEntryRegistry,
            diagnosisPort = ExistingInstallationRecoveryDiagnosisPort { preflight, current, installation, session ->
                ExistingInstallationRecoveryDiagnosisSshAdapter().diagnose(preflight, current, installation, session)
            },
            repairPort = ExistingInstallationRecoveryRepairPort { repair, current, session ->
                ExistingInstallationRecoveryRepairSshAdapter(journal).dispatch(repair, current, session)
            },
            postVerifyPort = ExistingInstallationRecoveryPostVerifyPort { current, installation, session ->
                ExistingInstallationRestartPostVerifySshAdapter(expectedAction = com.velumtegra.xuimobile.core.model.OperationType.RECOVERY)
                    .verify(current, installation, session)
            },
        )
    }

    private val uninstall = installationRepository?.let { repository ->
        ExistingInstallationUninstallRuntimeCoordinator(
            journal = journal,
            installationRepository = repository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = uninstallEntryRegistry,
            dispatchPort = ExistingInstallationUninstallDispatchPort { preflight, plan, current, session ->
                ExistingInstallationUninstallSshAdapter(journal).dispatch(preflight, plan, current, session)
            },
            absencePort = ExistingInstallationUninstallAbsencePort { current, installation, session ->
                ExistingInstallationUninstallAbsenceSshAdapter().verify(current, installation, session)
            },
        )
    }

    private val reinstall = if (installationRepository != null && managementEnrollmentPublisher != null) {
        ExistingInstallationReinstallRuntimeCoordinator(
            journal = journal,
            installationRepository = installationRepository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = reinstallEntryRegistry,
            dispatchPort = ExistingInstallationReinstallDispatchPort { preflight, plan, current, session ->
                ExistingInstallationReinstallSshAdapter(journal).dispatch(preflight, plan, current, session)
            },
            postVerifyPort = ExistingInstallationReinstallPostVerifyPort { current, managedInstallId, session ->
                ExistingInstallationReinstallPostVerifySshAdapter().verify(current, managedInstallId, session)
            },
            publisher = managementEnrollmentPublisher,
        )
    } else {
        null
    }

    private val installer = managementEnrollmentPublisher?.let { publisher ->
        val postInstallCoordinator = InstallerPostInstallCoordinator(
            remoteVerifier = InstallerPostInstallSshVerifier(),
            publisher = publisher,
            journal = journal,
        )
        InstallerRuntimeCoordinator(
            journal = journal,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = installerEntryRegistry,
            mutationExecutor = InstallerMutationExecutionPort { plan, current, session ->
                InstallerSshExecutionAdapter(journal).execute(plan, current, session)
            },
            detachedLaunch = InstallerDetachedLaunchPort { plan, current, session ->
                InstallerSshExecutionAdapter(journal).launchDetached(plan, current, session)
            },
            accessPort = InstallerFreshAccessPort { id ->
                when (val result = accessRepository.get(id)) {
                    is com.velumtegra.xuimobile.core.domain.RepositoryResult.Success -> result.value
                    else -> null
                }
            },
            postInstall = object : InstallerPostInstallRuntimePort {
                override suspend fun reconcileAndPublish(
                    current: com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot,
                    session: com.velumtegra.xuimobile.core.ssh.SshSessionHandle,
                ): InstallerPostInstallCoordinatorResult =
                    postInstallCoordinator.reconcileAndPublish(current, session)

                override suspend fun finishCommitted(
                    current: com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot,
                ): InstallerPostInstallCoordinatorResult = postInstallCoordinator.finishCommitted(current)
            },
        )
    }

    private val reconciliation = FeatureReconciliationCoordinator(
        journal = journal,
        runtimeRegistry = runtimeRegistry,
        sessionRegistry = sessionRegistry,
        port = featureReconciliationPort,
    )

    /** Current process-local connectivity scheduling evidence. */
    fun connectivitySnapshot(): ConnectivityObservation = connectivityGate.snapshot()

    /**
     * Accept one already-normalized Android connectivity state and advance the shared generation.
     * This is scheduling evidence only; it never proves endpoint reachability or command outcome.
     */
    fun observeConnectivity(state: ConnectivityState): ConnectivityObservation =
        connectivityGate.observe(state)

    /** Journal-first cold-start planning. No runtime lease is acquired here. */
    suspend fun bootstrapRecovery(exitProvenance: RecoveryExitProvenance): RecoveryBootstrapResult =
        recoveryBootstrap.plan(exitProvenance)

    /** Exact runtime admission with revision/target recheck under the shared OperationId registry. */
    suspend fun admitRecovery(
        plan: ColdStartRecoveryPlan,
        authority: RecoveryAdmissionAuthority,
    ): RecoveryAdmissionResult = recoveryAdmission.tryAdmit(plan, authority)

    /** Exact-token release; stale cleanup cannot release a replacement admission. */
    fun release(admission: RecoveryRuntimeAdmission): OperationRuntimeReleaseResult =
        recoveryAdmission.release(admission)

    /** Begin one bounded exact-owner reconnect sequence in the shared connectivity generation. */
    suspend fun beginReconnect(
        admission: RecoveryRuntimeAdmission,
        observation: ConnectivityObservation,
        budget: RetryBudget,
    ): ExactReconnectResult = reconnectOrchestrator.begin(admission, observation, budget)

    /** Consume exactly one retry continuation returned by [beginReconnect] or an earlier retry. */
    suspend fun retryReconnect(permit: ExactReconnectRetryPermit): ExactReconnectResult =
        reconnectOrchestrator.retry(permit)

    /**
     * Close only the exact operation-owned SessionId published for this admission target.
     *
     * Cleanup is intentionally allowed even when the runtime admission has just become stale: an
     * Android host may lose ownership concurrently with teardown. The exact SessionId guard in the
     * shared registry prevents that stale cleanup from removing a newer replacement session.
     */
    fun closeExactSession(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ExactRuntimeSessionCloseResult {
        val expectedOwner = SessionOwner.Operation(admission.plan.operationId)
        if (binding.owner != expectedOwner) {
            return ExactRuntimeSessionCloseResult.ContractViolation(
                "Session cleanup binding belongs to a different operation owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ExactRuntimeSessionCloseResult.ContractViolation(
                "Session cleanup binding uses a different ServerAccessId than the admitted target",
            )
        }

        return if (
            sessionRegistry.remove(
                owner = expectedOwner,
                accessId = admission.plan.target.serverAccessId,
                sessionId = binding.sessionId,
                close = true,
            )
        ) {
            ExactRuntimeSessionCloseResult.Closed
        } else {
            ExactRuntimeSessionCloseResult.StaleOrAlreadyClosed
        }
    }

    /**
     * Execute the Phase 5 read-only Discovery consumer through the exact session already published
     * by this process runtime. No second session/retry/runtime owner is introduced.
     */
    suspend fun executeDiscovery(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): DiscoveryRuntimeExecutionResult = discovery.execute(admission, sessionBinding)

    /** Execute the Phase 6 QUICK_INSPECT consumer through the same exact operation-owned session. */
    suspend fun executeManagementQuickInspect(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ManagementRuntimeExecutionResult = management?.execute(admission, sessionBinding)
        ?: ManagementRuntimeExecutionResult.ContractViolation(
            "Management repositories are not installed in this runtime composition",
        )

    /** Execute explicit bounded DEEP_DIAGNOSTIC through that same exact operation-owned session. */
    suspend fun executeDeepDiagnostic(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): DeepDiagnosticRuntimeExecutionResult = deepDiagnostic?.execute(admission, sessionBinding)
        ?: DeepDiagnosticRuntimeExecutionResult.ContractViolation(
            "Management repositories are not installed in this runtime composition",
        )

    suspend fun executeServiceLogs(admission: RecoveryRuntimeAdmission, sessionBinding: SessionBinding): ServiceLogRuntimeExecutionResult =
        serviceLogs?.execute(admission, sessionBinding) ?: ServiceLogRuntimeExecutionResult.ContractViolation(
            "Management repositories are unavailable")
    suspend fun executeUpdatePreflight(admission: RecoveryRuntimeAdmission, sessionBinding: SessionBinding): UpdatePreflightRuntimeExecutionResult =
        updatePreflight?.execute(admission, sessionBinding) ?: UpdatePreflightRuntimeExecutionResult.ContractViolation(
            "Management repositories are unavailable")

    fun registerDatabaseBackupConfirmation(confirmation: com.velumtegra.xuimobile.core.domain.DatabaseBackupConfirmation): Boolean =
        databaseBackup.register(confirmation)
    fun discardDatabaseBackupConfirmation(id: com.velumtegra.xuimobile.core.model.OperationId): Boolean = databaseBackup.discard(id)
    fun databaseBackupSlotInventory(serverId: com.velumtegra.xuimobile.core.model.ServerId, profile: com.velumtegra.xuimobile.core.model.ServerAccess) = databaseBackup.slotInventory(serverId, profile)
    fun installationBackupSlotInventory(serverId: com.velumtegra.xuimobile.core.model.ServerId, profile: com.velumtegra.xuimobile.core.model.ServerAccess) = installationBackup.slotInventory(serverId, profile)
    suspend fun prepareDatabaseBackup(admission: RecoveryRuntimeAdmission): DatabaseBackupRuntimeResult = databaseBackup.prepare(admission)
    suspend fun executeDatabaseBackup(admission: RecoveryRuntimeAdmission, binding: SessionBinding): DatabaseBackupRuntimeResult =
        databaseBackup.execute(admission, binding)

    fun registerInstallationBackupConfirmation(confirmation: com.velumtegra.xuimobile.core.domain.InstallationBackupConfirmation): Boolean =
        installationBackup.register(confirmation)
    fun discardInstallationBackupConfirmation(id: com.velumtegra.xuimobile.core.model.OperationId): Boolean = installationBackup.discard(id)
    suspend fun prepareInstallationBackup(admission: RecoveryRuntimeAdmission): InstallationBackupRuntimeResult = installationBackup.prepare(admission)
    suspend fun executeInstallationBackup(admission: RecoveryRuntimeAdmission, binding: SessionBinding): InstallationBackupRuntimeResult =
        installationBackup.execute(admission, binding)

    fun registerRestoreCheckConfirmation(confirmation: com.velumtegra.xuimobile.core.domain.RestoreCheckConfirmation): Boolean =
        restoreCheck.register(confirmation)
    fun discardRestoreCheckConfirmation(id: com.velumtegra.xuimobile.core.model.OperationId): Boolean = restoreCheck.discard(id)
    suspend fun prepareRestoreCheck(admission: RecoveryRuntimeAdmission): RestoreCheckRuntimeResult = restoreCheck.prepare(admission)
    suspend fun executeRestoreCheck(admission: RecoveryRuntimeAdmission, binding: SessionBinding): RestoreCheckRuntimeResult =
        restoreCheck.execute(admission, binding)
    suspend fun prepareWorkingDatabaseRestore(admission: RecoveryRuntimeAdmission): WorkingDatabaseRestoreRuntimeResult = workingDatabaseRestore.prepare(admission)
    suspend fun executeWorkingDatabaseRestore(admission: RecoveryRuntimeAdmission, binding: SessionBinding): WorkingDatabaseRestoreRuntimeResult = workingDatabaseRestore.execute(admission, binding)
    fun registerWorkingDatabaseRestoreConfirmation(c:WorkingDatabaseRestoreConfirmation):Boolean=workingDatabaseRestore.register(c)
    fun discardWorkingDatabaseRestoreConfirmation(id:OperationId):Boolean=workingDatabaseRestore.discard(id)
    suspend fun prepareRestoredPanelStart(admission: RecoveryRuntimeAdmission): RestoredPanelStartRuntimeResult = restoredPanelStart.prepare(admission)
    suspend fun executeRestoredPanelStart(admission: RecoveryRuntimeAdmission, binding: SessionBinding): RestoredPanelStartRuntimeResult = restoredPanelStart.execute(admission, binding)
    fun registerRestoredPanelStartConfirmation(c:RestoredPanelStartConfirmation):Boolean=restoredPanelStart.register(c)
    fun discardRestoredPanelStartConfirmation(id:OperationId):Boolean=restoredPanelStart.discard(id)
    suspend fun prepareRestoreCompatibility(admission: RecoveryRuntimeAdmission): RestoreCompatibilityRuntimeResult = restoreCompatibility.prepare(admission)
    suspend fun executeRestoreCompatibility(admission: RecoveryRuntimeAdmission, binding: SessionBinding): RestoreCompatibilityRuntimeResult =
        restoreCompatibility.execute(admission, binding)

    /**
     * Register one process-local, already-verified fresh-install authority. It is never persisted and
     * is consumed exactly once immediately before the mutation executor boundary.
     */
    fun registerInstallerFreshAuthorization(
        target: VerifiedFreshInstallTarget,
    ): InstallerRuntimeEntryRegistrationResult = installer?.registerFreshAuthorization(target)
        ?: InstallerRuntimeEntryRegistrationResult.Rejected(
            "Installer publication/runtime dependencies are not installed in this runtime composition",
        )

    /**
     * UI entry for a real install: register the user's explicit, one-shot confirmation for one exact
     * durable INSTALL operation/revision and complete reviewed ServerAccess (TTL <= 2 minutes). The
     * runtime re-observes the target read-only under the server lease before any write.
     */
    fun registerInstallerExplicitInstallConsent(
        consent: InstallerExplicitInstallConsent,
    ): InstallerExplicitConsentRegistrationResult = installer?.registerExplicitInstallConsent(consent)
        ?: InstallerExplicitConsentRegistrationResult.Rejected(
            "Installer publication/runtime dependencies are not installed in this runtime composition",
        )

    fun discardInstallerExplicitInstallConsent(operationId: OperationId): Boolean =
        installer?.discardExplicitInstallConsent(operationId) ?: false

    fun discardInstallerFreshAuthorization(operationId: com.velumtegra.xuimobile.core.model.OperationId): Boolean =
        installer?.discardFreshAuthorization(operationId) ?: false

    /** Local-only Installer decision that may finish COMMIT_VERIFIED without opening SSH. */
    suspend fun prepareInstallerTransport(
        admission: RecoveryRuntimeAdmission,
    ): InstallerRuntimePreparationResult = installer?.prepareTransport(admission)
        ?: InstallerRuntimePreparationResult.ContractViolation(
            "Installer publication/runtime dependencies are not installed in this runtime composition",
        )

    /** Execute fresh mutation or read-only Installer reconciliation through the exact live session. */
    suspend fun executeInstaller(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): InstallerRuntimeExecutionResult = installer?.execute(admission, sessionBinding)
        ?: InstallerRuntimeExecutionResult.ContractViolation(
            "Installer publication/runtime dependencies are not installed in this runtime composition",
        )

    /**
     * Register one process-local exact Phase 9 RESTART preflight. It is consumed once immediately
     * before restart dispatch and is never recreated from durable state after process death.
     */
    fun registerExistingInstallationRestartConfirmation(confirmation: com.velumtegra.xuimobile.core.domain.ExistingInstallationRestartConfirmation): Boolean =
        restart?.registerConfirmation(confirmation) ?: false

    fun registerExistingInstallationRestartPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationRestartEntryRegistrationResult = restart?.registerPreflight(preflight)
        ?: ExistingInstallationRestartEntryRegistrationResult.Rejected(
            "Installation repository is not installed in this runtime composition",
        )

    fun discardExistingInstallationRestartPreflight(
        operationId: com.velumtegra.xuimobile.core.model.OperationId,
    ): Boolean = restart?.discardPreflight(operationId) ?: false

    /** Local restart entry decision before transport is opened. */
    suspend fun prepareExistingInstallationRestartTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationRestartPreparationResult = restart?.prepareTransport(admission)
        ?: ExistingInstallationRestartPreparationResult.ContractViolation(
            "Installation repository is not installed in this runtime composition",
        )

    /**
     * Execute fresh RESTART dispatch or post-reconnect read-only verification through the same exact
     * operation-owned Phase 4 session. This method never creates its own reconnect loop.
     */
    suspend fun executeExistingInstallationRestart(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationRestartRuntimeResult = restart?.execute(admission, sessionBinding)
        ?: ExistingInstallationRestartRuntimeResult.ContractViolation(
            "Installation repository is not installed in this runtime composition",
        )

    /** Register one process-local exact Phase 9.6 destructive UNINSTALL preflight. */
    fun registerExistingInstallationUninstallPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationUninstallEntryRegistrationResult = uninstall?.registerPreflight(preflight)
        ?: ExistingInstallationUninstallEntryRegistrationResult.Rejected(
            "Installation repository is not installed in this runtime composition",
        )

    fun discardExistingInstallationUninstallPreflight(
        operationId: com.velumtegra.xuimobile.core.model.OperationId,
    ): Boolean = uninstall?.discardPreflight(operationId) ?: false

    /** Local exact UNINSTALL decision before transport is opened. */
    suspend fun prepareExistingInstallationUninstallTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationUninstallPreparationResult = uninstall?.prepareTransport(admission)
        ?: ExistingInstallationUninstallPreparationResult.ContractViolation(
            "Installation repository is not installed in this runtime composition",
        )

    /** Execute one-shot UNINSTALL or read-only absence verification through the shared Phase 4 session. */
    suspend fun executeExistingInstallationUninstall(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationUninstallRuntimeResult = uninstall?.execute(admission, sessionBinding)
        ?: ExistingInstallationUninstallRuntimeResult.ContractViolation(
            "Installation repository is not installed in this runtime composition",
        )

    /** Register one process-local exact Phase 9.7 MANAGED REINSTALL preflight. */
    fun registerExistingInstallationReinstallPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationReinstallEntryRegistrationResult = reinstall?.registerPreflight(preflight)
        ?: ExistingInstallationReinstallEntryRegistrationResult.Rejected(
            "Installation repository/publisher are not installed in this runtime composition",
        )

    fun discardExistingInstallationReinstallPreflight(
        operationId: com.velumtegra.xuimobile.core.model.OperationId,
    ): Boolean = reinstall?.discardPreflight(operationId) ?: false

    /** Local exact REINSTALL decision before transport is opened. */
    suspend fun prepareExistingInstallationReinstallTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationReinstallPreparationResult = reinstall?.prepareTransport(admission)
        ?: ExistingInstallationReinstallPreparationResult.ContractViolation(
            "Installation repository/publisher are not installed in this runtime composition",
        )

    /** Execute one compound REINSTALL or read-only verification/republish through the shared Phase 4 session. */
    suspend fun executeExistingInstallationReinstall(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationReinstallRuntimeResult = reinstall?.execute(admission, sessionBinding)
        ?: ExistingInstallationReinstallRuntimeResult.ContractViolation(
            "Installation repository/publisher are not installed in this runtime composition",
        )

    /** Register one process-local exact Phase 9 RECOVERY preflight. */
    fun registerExistingInstallationRecoveryPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationRecoveryEntryRegistrationResult = existingInstallationRecovery?.registerPreflight(preflight)
        ?: ExistingInstallationRecoveryEntryRegistrationResult.Rejected(
            "Installation repository is not installed in this runtime composition",
        )

    fun discardExistingInstallationRecoveryPreflight(
        operationId: com.velumtegra.xuimobile.core.model.OperationId,
    ): Boolean = existingInstallationRecovery?.discardPreflight(operationId) ?: false

    /** Local read-only-first recovery entry decision before transport is opened. */
    suspend fun prepareExistingInstallationRecoveryTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationRecoveryPreparationResult = existingInstallationRecovery?.prepareTransport(admission)
        ?: ExistingInstallationRecoveryPreparationResult.ContractViolation(
            "Installation repository is not installed in this runtime composition",
        )

    /** Execute exact RECOVERY diagnosis/repair or post-reconnect verification on the shared session. */
    suspend fun executeExistingInstallationRecovery(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationRecoveryRuntimeResult = existingInstallationRecovery?.execute(admission, sessionBinding)
        ?: ExistingInstallationRecoveryRuntimeResult.ContractViolation(
            "Installation repository is not installed in this runtime composition",
        )

    /** Reload latest durable truth after a proven stale OperationJournal CAS conflict. */
    suspend fun reloadAfterStaleCas(conflict: StaleCasConflict): StaleCasReloadResult =
        staleCasReload.reloadForReplan(conflict)

    /**
     * Run the feature-owned read-only reconciliation boundary against the exact session published by
     * this process runtime. The generic coordinator still performs no feature mutation.
     */
    suspend fun reconcile(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): FeatureReconciliationResult = reconciliation.reconcile(admission, sessionBinding)
}
