package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.*
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 9.8 real-Android/JSch acceptance against the host-only finite Phase 9 witness.
 *
 * Remote effects are synthetic fixture replies, never host shell/process execution. The production
 * runtime still performs real Android -> JSch -> Apache MINA transport, exact session publication,
 * durable Room journal transitions, one-shot action authority, read-only reconciliation and managed
 * reinstall same-row republish.
 */
@RunWith(AndroidJUnit4::class)
class Phase9_8ExistingInstallationFixtureAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun phase9ExistingInstallationFamilyIsExactNonReplayAndVerifiedBeforeTerminalPublication() = runBlocking {
        val fixturePort = requiredPort(ARG_FIXTURE_PORT)
        val fingerprint = requiredArgument(ARG_FIXTURE_FINGERPRINT)
        val runTag = requiredArgument(ARG_RUN_TAG).also {
            require(it.matches(Regex("[a-f0-9]{12}"))) { "Invalid Phase 9.8 run tag" }
        }
        require(fingerprint.startsWith("SHA256:") && fingerprint.length > 7) { "Invalid fixture fingerprint" }

        val dbName = "phase9_8_existing_${runTag}_${UUID.randomUUID().toString().take(8)}.db"
        var database: VelumDatabase? = null
        val secretId = SecretId("phase98-secret-$runTag")
        val secretStore = StaticSecretStore(secretId, FIXTURE_PASSWORD)
        try {
            context.deleteDatabase(dbName)
            val db = VelumDatabaseFactory.open(context, dbName)
            database = db
            val journal = RoomOperationJournal(db)
            val serverRepo = RoomServerRepository(db)
            val accessRepo = RoomServerAccessRepository(db)
            val accessWriter = RoomCredentialReferenceWriter(db)
            val installationRepo = RoomXuiInstallationRepository(db)
            val managementRepo = RoomManagementAccessRepository(db)
            val webRepo = RoomWebPanelAccessRepository(db)
            val publisher = RoomManagementEnrollmentPublisher(db)

            val serverId = ServerId("phase98-server-$runTag")
            val accessId = ServerAccessId("phase98-access-$runTag")
            val installationId = XuiInstallationId("phase98-installation-$runTag")
            val managedInstallId = ManagedInstallId(MANAGED_INSTALL_ID)
            val access = ServerAccess(
                id = accessId,
                serverId = serverId,
                endpoint = SshEndpoint(LOOPBACK_HOST, fixturePort),
                username = FIXTURE_USERNAME,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(fingerprint),
            )
            var installation = XuiInstallation(
                id = installationId,
                serverId = serverId,
                ownership = InstallationOwnership.MANAGED,
                identity = InstallationIdentity(
                    serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                    binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                    rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                    databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                    managedInstallId = managedInstallId,
                ),
                baseline = InstallationBaseline(
                    serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                    binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                    rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                    databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                    panelPort = INITIAL_PANEL_PORT,
                    webBasePath = INITIAL_WEB_BASE_PATH,
                    listenAddress = LOOPBACK_HOST,
                    capturedAt = Instant.now().minusSeconds(600),
                ),
            )

            serverRepo.create(Server(serverId, "Phase 9.8 existing-installation fixture", Instant.now().minusSeconds(120)))
                .requireRepositorySuccess("create Phase 9.8 Server")
            accessWriter.createServerAccess(access).requireRepositorySuccess("create Phase 9.8 ServerAccess")
            assertEquals(RecordRevision(0), installationRepo.create(installation).requireRepositorySuccess("create Phase 9.8 XuiInstallation"))
            managementRepo.create(ManagementAccess(installationId, accessId))
                .requireRepositorySuccess("create Phase 9.8 ManagementAccess")

            val sessionCounter = AtomicInteger(0)
            val connectionFactory = JschSshConnectionFactory(secretStore) {
                SessionId("phase98-session-${sessionCounter.incrementAndGet()}-$runTag")
            }
            val sessions = ExactSessionRegistry()
            val runtime = OperationRuntimeCoordinator(
                journal = journal,
                accessRepository = accessRepo,
                connectionFactory = connectionFactory,
                sessionRegistry = sessions,
                installationRepository = installationRepo,
                managementAccessRepository = managementRepo,
                managementEnrollmentPublisher = publisher,
            )

            // 1) RECOVERY: read-only diagnosis proves exact inactive service + absent listener, one
            // exact start command is checkpointed before dispatch, then a new admission reconnects
            // and commits only after fresh identity/service/listener/marker read-back.
            val recoveryCurrent = createOperation(journal, OperationType.RECOVERY, "recovery", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationRecoveryEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationRecoveryPreflight(verifiedPreflight(recoveryCurrent, installation, access)),
            )
            var recoveryAdmission = admit(runtime, recoveryCurrent.snapshot.operationId)
            assertEquals(ExistingInstallationRecoveryPreparationResult.TransportRequired, runtime.prepareExistingInstallationRecoveryTransport(recoveryAdmission))
            var recoveryConnected = connect(runtime, recoveryAdmission)
            val recoveryDispatch = runtime.executeExistingInstallationRecovery(recoveryAdmission, recoveryConnected.binding)
                as? ExistingInstallationRecoveryRuntimeResult.Repair
                ?: throw AssertionError("Phase 9.8 recovery did not reach exact repair")
            assertTrue(recoveryDispatch.result is ExistingInstallationRecoveryRepairResult.PostVerifyRequired)
            assertEquals(
                CheckpointSemantics.MUTATION_IN_FLIGHT,
                journal.get(recoveryCurrent.snapshot.operationId).requireOperationSuccess("read recovery mutation checkpoint").snapshot.checkpoint.semantics,
            )
            closeAndRelease(runtime, recoveryAdmission, recoveryConnected.binding)

            recoveryAdmission = admit(runtime, recoveryCurrent.snapshot.operationId)
            recoveryConnected = connect(runtime, recoveryAdmission)
            val recoveryCompleted = runtime.executeExistingInstallationRecovery(recoveryAdmission, recoveryConnected.binding)
                as? ExistingInstallationRecoveryRuntimeResult.Completed
                ?: throw AssertionError("Phase 9.8 recovery did not complete after read-only verify")
            assertTerminal((recoveryCompleted.result as ExistingInstallationRecoveryCompletionResult.Committed).durable, "recovery")
            closeAndRelease(runtime, recoveryAdmission, recoveryConnected.binding)

            // 2) RESTART success: command success itself is not success. A fresh exact reconnect and
            // read-only postverify must occur before terminal publication.
            val restartCurrent = createOperation(journal, OperationType.RESTART, "restart-success", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationRestartEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationRestartPreflight(verifiedPreflight(restartCurrent, installation, access)),
            )
            var restartAdmission = admit(runtime, restartCurrent.snapshot.operationId)
            assertEquals(ExistingInstallationRestartPreparationResult.TransportRequired, runtime.prepareExistingInstallationRestartTransport(restartAdmission))
            var restartConnected = connect(runtime, restartAdmission)
            val restartDispatch = runtime.executeExistingInstallationRestart(restartAdmission, restartConnected.binding)
                as? ExistingInstallationRestartRuntimeResult.Dispatch
                ?: throw AssertionError("Phase 9.8 restart did not dispatch")
            assertTrue(restartDispatch.result is ExistingInstallationRestartDispatchResult.ReconnectRequired)
            assertEquals(
                CheckpointSemantics.RESTART_IN_FLIGHT,
                journal.get(restartCurrent.snapshot.operationId).requireOperationSuccess("read restart checkpoint").snapshot.checkpoint.semantics,
            )
            closeAndRelease(runtime, restartAdmission, restartConnected.binding)

            restartAdmission = admit(runtime, restartCurrent.snapshot.operationId)
            restartConnected = connect(runtime, restartAdmission)
            val restartCompleted = runtime.executeExistingInstallationRestart(restartAdmission, restartConnected.binding)
                as? ExistingInstallationRestartRuntimeResult.Completed
                ?: throw AssertionError("Phase 9.8 restart did not complete after reconnect/readback")
            assertTerminal((restartCompleted.result as ExistingInstallationRestartCompletionResult.Committed).durable, "restart")
            closeAndRelease(runtime, restartAdmission, restartConnected.binding)

            // 3) Restart post-dispatch uncertainty: fixture accepts the exact exec request and sends
            // no exit-status. The old admission goes stale, a second execute cannot replay, and the
            // only continuation is a new exact read-only reconciliation admission.
            val uncertainCurrent = createOperation(journal, OperationType.RESTART, "restart-uncertain", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationRestartEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationRestartPreflight(verifiedPreflight(uncertainCurrent, installation, access)),
            )
            var uncertainAdmission = admit(runtime, uncertainCurrent.snapshot.operationId)
            var uncertainConnected = connect(runtime, uncertainAdmission)
            val uncertainDispatch = runtime.executeExistingInstallationRestart(uncertainAdmission, uncertainConnected.binding)
                as? ExistingInstallationRestartRuntimeResult.Dispatch
                ?: throw AssertionError("Phase 9.8 uncertain restart did not return dispatch result")
            val reconciliationRequired = uncertainDispatch.result as? ExistingInstallationRestartDispatchResult.ReconciliationRequired
                ?: throw AssertionError("Phase 9.8 uncertain restart did not stay reconciliation-required: ${uncertainDispatch.result}")
            assertEquals(ExistingInstallationRestartReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, reconciliationRequired.reason)
            assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliationRequired.durable.snapshot.status)
            assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, reconciliationRequired.durable.snapshot.checkpoint.semantics)
            assertTrue(
                "The old admission must be stale after the durable uncertainty checkpoint",
                runtime.executeExistingInstallationRestart(uncertainAdmission, uncertainConnected.binding) is ExistingInstallationRestartRuntimeResult.StalePlan,
            )
            closeAndRelease(runtime, uncertainAdmission, uncertainConnected.binding)

            uncertainAdmission = admit(runtime, uncertainCurrent.snapshot.operationId)
            uncertainConnected = connect(runtime, uncertainAdmission)
            val uncertainCompleted = runtime.executeExistingInstallationRestart(uncertainAdmission, uncertainConnected.binding)
                as? ExistingInstallationRestartRuntimeResult.Completed
                ?: throw AssertionError("Phase 9.8 uncertain restart did not reconcile read-only")
            assertTerminal((uncertainCompleted.result as ExistingInstallationRestartCompletionResult.Committed).durable, "uncertain restart")
            closeAndRelease(runtime, uncertainAdmission, uncertainConnected.binding)

            // 4) Exact operation ownership: an authenticated SSH session owned by another OperationId
            // is rejected locally before any remote command dispatch.
            val wrongOwnerCurrent = createOperation(journal, OperationType.RESTART, "wrong-owner", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationRestartEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationRestartPreflight(verifiedPreflight(wrongOwnerCurrent, installation, access)),
            )
            val wrongOwnerAdmission = admit(runtime, wrongOwnerCurrent.snapshot.operationId)
            val wrongOwnerHandle = connectDirect(
                connectionFactory,
                access,
                SessionOwner.Operation(OperationId("phase98-different-owner-$runTag")),
            )
            try {
                val rejected = runtime.executeExistingInstallationRestart(wrongOwnerAdmission, wrongOwnerHandle.binding)
                assertTrue(rejected is ExistingInstallationRestartRuntimeResult.ContractViolation)
                assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, current(journal, wrongOwnerCurrent.snapshot.operationId).snapshot.checkpoint.semantics)
            } finally {
                wrongOwnerHandle.close()
                assertEquals(OperationRuntimeReleaseResult.RELEASED, runtime.release(wrongOwnerAdmission))
                runtime.discardExistingInstallationRestartPreflight(wrongOwnerCurrent.snapshot.operationId)
                terminalize(journal, wrongOwnerCurrent.snapshot.operationId, "PHASE9_8_WRONG_OWNER_DONE")
            }

            // 5) Durable same-server uncertainty barrier: even with a correct authenticated session
            // and fresh process-local authority, another unsafe same-server operation blocks before
            // preflight consumption and before any remote command reaches the host witness.
            val barrierCurrent = createOperation(journal, OperationType.RESTART, "barrier", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationRestartEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationRestartPreflight(verifiedPreflight(barrierCurrent, installation, access)),
            )
            val barrierAdmission = admit(runtime, barrierCurrent.snapshot.operationId)
            val barrierConnected = connect(runtime, barrierAdmission)
            val blocker = createUnsafeBlocker(journal, runTag, serverId, accessId, installationId)
            val blocked = runtime.executeExistingInstallationRestart(barrierAdmission, barrierConnected.binding)
                as? ExistingInstallationRestartRuntimeResult.BlockedByDurableMutation
                ?: throw AssertionError("Phase 9.8 same-server uncertainty did not block")
            assertEquals(listOf(blocker.snapshot.operationId), blocked.blockers.map { it.operationId })
            assertEquals(ExistingInstallationRestartPreparationResult.TransportRequired, runtime.prepareExistingInstallationRestartTransport(barrierAdmission))
            closeAndRelease(runtime, barrierAdmission, barrierConnected.binding)
            terminalize(journal, blocker.snapshot.operationId, "PHASE9_8_BLOCKER_CLEARED")
            runtime.discardExistingInstallationRestartPreflight(barrierCurrent.snapshot.operationId)
            terminalize(journal, barrierCurrent.snapshot.operationId, "PHASE9_8_BARRIER_DONE")

            // 6) UNINSTALL: one exact destructive command. A new admission may only perform bounded
            // absence verification. Successful remote absence intentionally keeps local installation
            // and ManagementAccess rows intact.
            val uninstallCurrent = createOperation(journal, OperationType.UNINSTALL, "uninstall", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationUninstallEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationUninstallPreflight(verifiedPreflight(uninstallCurrent, installation, access)),
            )
            var uninstallAdmission = admit(runtime, uninstallCurrent.snapshot.operationId)
            var uninstallConnected = connect(runtime, uninstallAdmission)
            val uninstallDispatch = runtime.executeExistingInstallationUninstall(uninstallAdmission, uninstallConnected.binding)
                as? ExistingInstallationUninstallRuntimeResult.Dispatch
                ?: throw AssertionError("Phase 9.8 uninstall did not dispatch")
            assertTrue(uninstallDispatch.result is ExistingInstallationUninstallDispatchResult.PostVerifyRequired)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, current(journal, uninstallCurrent.snapshot.operationId).snapshot.checkpoint.semantics)
            closeAndRelease(runtime, uninstallAdmission, uninstallConnected.binding)

            uninstallAdmission = admit(runtime, uninstallCurrent.snapshot.operationId)
            uninstallConnected = connect(runtime, uninstallAdmission)
            val uninstallCompleted = runtime.executeExistingInstallationUninstall(uninstallAdmission, uninstallConnected.binding)
                as? ExistingInstallationUninstallRuntimeResult.Completed
                ?: throw AssertionError("Phase 9.8 uninstall did not complete after absence proof")
            val uninstallCommitted = uninstallCompleted.result as ExistingInstallationUninstallCompletionResult.Committed
            assertTerminal(uninstallCommitted.durable, "uninstall")
            assertEquals(ExistingInstallationUninstallLocalCleanupDisposition.DEFERRED_REFERENCES_RETAINED, uninstallCommitted.localCleanup)
            closeAndRelease(runtime, uninstallAdmission, uninstallConnected.binding)
            assertEquals(installationId, installationRepo.get(installationId).requireRepositorySuccess("installation retained after uninstall").value.id)
            assertEquals(accessId, managementRepo.get(installationId, accessId).requireRepositorySuccess("ManagementAccess retained after uninstall").serverAccessId)

            // 7) MANAGED REINSTALL: one compound five-step mutation. A fresh recovery admission only
            // reads worker/marker/facts and CAS-republishes the same logical installation row.
            installation = installationRepo.get(installationId).requireRepositorySuccess("read retained installation before reinstall").value
            val beforeReinstallRevision = installationRepo.get(installationId).requireRepositorySuccess("read pre-reinstall revision").revision
            val reinstallCurrent = createOperation(journal, OperationType.REINSTALL, "reinstall", runTag, serverId, accessId, installationId)
            assertEquals(
                ExistingInstallationReinstallEntryRegistrationResult.Registered,
                runtime.registerExistingInstallationReinstallPreflight(verifiedPreflight(reinstallCurrent, installation, access)),
            )
            var reinstallAdmission = admit(runtime, reinstallCurrent.snapshot.operationId)
            var reinstallConnected = connect(runtime, reinstallAdmission)
            val reinstallDispatch = runtime.executeExistingInstallationReinstall(reinstallAdmission, reinstallConnected.binding)
                as? ExistingInstallationReinstallRuntimeResult.Dispatch
                ?: throw AssertionError("Phase 9.8 reinstall did not dispatch")
            assertTrue(reinstallDispatch.result is ExistingInstallationReinstallDispatchResult.PostVerifyRequired)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, current(journal, reinstallCurrent.snapshot.operationId).snapshot.checkpoint.semantics)
            closeAndRelease(runtime, reinstallAdmission, reinstallConnected.binding)

            reinstallAdmission = admit(runtime, reinstallCurrent.snapshot.operationId)
            reinstallConnected = connect(runtime, reinstallAdmission)
            val reinstallCompleted = runtime.executeExistingInstallationReinstall(reinstallAdmission, reinstallConnected.binding)
                as? ExistingInstallationReinstallRuntimeResult.Completed
                ?: throw AssertionError("Phase 9.8 reinstall did not complete after verified republish")
            val reinstallCommitted = reinstallCompleted.result as ExistingInstallationReinstallCompletionResult.Committed
            assertTerminal(reinstallCommitted.durable, "reinstall")
            val published = requireNotNull(reinstallCommitted.publication)
            assertEquals(installationId, published.installation.value.id)
            assertEquals(managedInstallId, published.installation.value.identity.managedInstallId)
            assertEquals(accessId, published.managementAccess.serverAccessId)
            assertTrue(published.baselineUpdated)
            closeAndRelease(runtime, reinstallAdmission, reinstallConnected.binding)

            val afterReinstall = installationRepo.get(installationId).requireRepositorySuccess("read republished installation")
            assertEquals(installationId, afterReinstall.value.id)
            assertEquals(managedInstallId, afterReinstall.value.identity.managedInstallId)
            assertEquals(beforeReinstallRevision.value + 1, afterReinstall.revision.value)
            assertEquals(REINSTALLED_PANEL_PORT, afterReinstall.value.baseline.panelPort)
            assertEquals(REINSTALLED_WEB_BASE_PATH, afterReinstall.value.baseline.webBasePath)
            assertEquals(LOOPBACK_HOST, afterReinstall.value.baseline.listenAddress)
            assertEquals(1, installationRepo.listForServer(serverId).requireRepositorySuccess("list Phase 9.8 installations").size)
            assertEquals(1, managementRepo.listForServerAccess(accessId).requireRepositorySuccess("list Phase 9.8 ManagementAccess").size)
            assertTrue("Phase 9.8 must not create WebPanelAccess", webRepo.list().requireRepositorySuccess("list Phase 9.8 WebPanelAccess").isEmpty())

            assertEquals(EXPECTED_AUTH, sessionCounter.get())
            assertEquals("No exact session may leak after Phase 9.8", 0, sessions.size())
        } finally {
            secretStore.close()
            database?.close()
            context.deleteDatabase(dbName)
        }
    }

    private suspend fun createOperation(
        journal: RoomOperationJournal,
        type: OperationType,
        label: String,
        runTag: String,
        serverId: ServerId,
        accessId: ServerAccessId,
        installationId: XuiInstallationId,
    ): VersionedOperationSnapshot {
        val at = Instant.now().minusSeconds(2)
        return journal.create(
            OperationSnapshot(
                operationId = OperationId("phase98-$label-$runTag"),
                type = type,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("PHASE9_8_PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, at),
                startedAt = at.minusSeconds(30),
                updatedAt = at,
            ),
        ).requireOperationSuccess("create Phase 9.8 $label operation")
    }

    private suspend fun createUnsafeBlocker(
        journal: RoomOperationJournal,
        runTag: String,
        serverId: ServerId,
        accessId: ServerAccessId,
        installationId: XuiInstallationId,
    ): VersionedOperationSnapshot {
        val at = Instant.now().minusSeconds(1)
        return journal.create(
            OperationSnapshot(
                operationId = OperationId("phase98-durable-blocker-$runTag"),
                type = OperationType.UNINSTALL,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint("PHASE9_8_UNCERTAIN", CheckpointSemantics.MUTATION_IN_FLIGHT, at),
                startedAt = at.minusSeconds(30),
                updatedAt = at,
            ),
        ).requireOperationSuccess("create Phase 9.8 durable blocker")
    }

    private suspend fun terminalize(journal: RoomOperationJournal, operationId: OperationId, phase: String) {
        val current = current(journal, operationId)
        val now = Instant.now()
        val at = if (now.isBefore(current.snapshot.updatedAt)) current.snapshot.updatedAt else now
        journal.advance(
            operationId,
            current.revision,
            current.snapshot.copy(
                status = OperationStatus.CANCELLED,
                checkpoint = OperationCheckpoint(phase, CheckpointSemantics.TERMINAL, at),
                updatedAt = at,
            ),
        ).requireOperationSuccess("terminalize ${operationId.value}")
    }

    private suspend fun current(journal: RoomOperationJournal, operationId: OperationId): VersionedOperationSnapshot =
        journal.get(operationId).requireOperationSuccess("read ${operationId.value}")

    private suspend fun admit(runtime: OperationRuntimeCoordinator, operationId: OperationId): RecoveryRuntimeAdmission {
        val bootstrap = runtime.bootstrapRecovery(RecoveryExitProvenance.UNKNOWN)
        val success = bootstrap as? RecoveryBootstrapResult.Success
            ?: throw AssertionError("Phase 9.8 recovery bootstrap failed: $bootstrap")
        val plan = success.items.asSequence()
            .filterIsInstance<RecoveryBootstrapItem.Planned>()
            .map { it.plan }
            .singleOrNull { it.operationId == operationId }
            ?: throw AssertionError("Phase 9.8 bootstrap did not produce one exact plan for ${operationId.value}")
        return (runtime.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED) as? RecoveryAdmissionResult.Admitted)?.admission
            ?: throw AssertionError("Phase 9.8 exact runtime admission was not granted for ${operationId.value}")
    }

    private suspend fun connect(
        runtime: OperationRuntimeCoordinator,
        admission: RecoveryRuntimeAdmission,
    ): ExactReconnectResult.Connected {
        val observation = runtime.observeConnectivity(ConnectivityState.ONLINE)
        return runtime.beginReconnect(admission, observation, RetryBudget(maxAttempts = 1)) as? ExactReconnectResult.Connected
            ?: throw AssertionError("Phase 9.8 exact reconnect failed for ${admission.plan.operationId.value}")
    }

    private suspend fun connectDirect(
        factory: JschSshConnectionFactory,
        access: ServerAccess,
        owner: SessionOwner,
    ): SshSessionHandle = when (val result = factory.connect(access, owner)) {
        is SshConnectResult.Connected -> result.handle
        is SshConnectResult.Failed -> throw AssertionError("Phase 9.8 direct SSH connect failed: ${result.failure::class.java.simpleName}")
    }

    private fun closeAndRelease(
        runtime: OperationRuntimeCoordinator,
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ) {
        assertEquals(ExactRuntimeSessionCloseResult.Closed, runtime.closeExactSession(admission, binding))
        assertEquals(OperationRuntimeReleaseResult.RELEASED, runtime.release(admission))
    }

    private fun assertTerminal(current: VersionedOperationSnapshot, label: String) {
        assertEquals("$label status", OperationStatus.SUCCEEDED, current.snapshot.status)
        assertEquals("$label checkpoint", CheckpointSemantics.TERMINAL, current.snapshot.checkpoint.semantics)
    }

    private fun verifiedPreflight(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        access: ServerAccess,
    ): VerifiedExistingInstallationActionPreflight {
        val now = Instant.now()
        val proof = InstallationProof(
            id = TargetProofId("phase98-proof-${current.snapshot.operationId.value}"),
            installationId = installation.id,
            serverId = installation.serverId,
            serverAccessId = access.id,
            observedIdentity = installation.identity,
            observedAt = now.minusSeconds(3),
            validUntil = now.plusSeconds(600),
        )
        val verifiedTarget = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now)
            as TargetVerificationResult.Verified).target
        val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, verifiedTarget, now)
            as ExistingInstallationActionAuthorizationResult.Verified).authorization
        val evidence = ExistingInstallationPreflightEvidence(
            scope = ExistingInstallationActionScope(
                operationId = current.snapshot.operationId,
                operationRevision = current.revision.value,
                serverId = installation.serverId,
                serverAccessId = access.id,
                installationId = installation.id,
                action = current.snapshot.type,
                ownership = installation.ownership,
                managedInstallId = installation.identity.managedInstallId,
            ),
            installationProof = proof,
            accessPathState = ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
            layoutCapability = ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
            privilegeCapability = ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
            mutationBarrierState = ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
            observedAt = now.minusSeconds(2),
            validUntil = now.plusSeconds(300),
        )
        return (ExistingInstallationActionPreflightPolicy.verify(authorization, current, installation, evidence, now)
            as ExistingInstallationActionPreflightResult.Verified).preflight
    }

    private fun requiredArgument(name: String): String =
        InstrumentationRegistry.getArguments().getString(name)?.trim()?.takeIf { it.isNotEmpty() }
            ?: error("Missing required instrumentation argument: $name")

    private fun requiredPort(name: String): Int =
        requiredArgument(name).toIntOrNull()?.takeIf { it in 1..65535 }
            ?: error("Invalid required port argument: $name")

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(action: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(action: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private class StaticSecretStore(
        private val secretId: SecretId,
        password: String,
    ) : SecretStore, AutoCloseable {
        private val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.AlreadyExists

        override suspend fun read(secretId: SecretId): SecretReadResult =
            if (secretId == this.secretId) {
                SecretReadResult.Found(SecretMaterial.fromBytes(passwordBytes))
            } else {
                SecretReadResult.NotFound
            }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult = SecretDeleteResult.AlreadyAbsent
        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(secretId))

        override fun close() {
            java.util.Arrays.fill(passwordBytes, 0)
        }
    }

    private companion object {
        const val ARG_FIXTURE_PORT = "phase98.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase98.fixtureFingerprint"
        const val ARG_RUN_TAG = "phase98.runTag"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase98"
        const val FIXTURE_PASSWORD = "VELUM-phase98-test-only-password"
        const val MANAGED_INSTALL_ID = "v1-0123456789abcdef0123456789abcdef"
        const val INITIAL_PANEL_PORT = 2053
        const val INITIAL_WEB_BASE_PATH = "/panel/"
        const val REINSTALLED_PANEL_PORT = 24443
        const val REINSTALLED_WEB_BASE_PATH = "/phase98-reinstalled/"
        const val EXPECTED_AUTH = 12
    }
}
