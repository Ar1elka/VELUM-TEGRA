package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationRestartRuntimeCoordinatorTest {
    @Test
    fun `fresh restart consumes one preflight and dispatches once`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()

        assertEquals(
            ExistingInstallationRestartPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.Dispatch

        assertTrue(result.result is ExistingInstallationRestartDispatchResult.ReconnectRequired)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(false, fixture.coordinator.discardPreflight(fixture.operationId))
    }

    @Test
    fun `old admission becomes stale after restart checkpoint and cannot postverify`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)

        val second = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.StalePlan

        assertEquals(OperationRevision(0), second.expectedRevision)
        assertEquals(OperationRevision(1), second.actualRevision)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(0, fixture.verifyCalls)
    }

    @Test
    fun `new exact recovery admission never replays restart and commits only after read only verify`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)
        fixture.releaseAdmission(fixture.admission)

        val recovered = fixture.recoveryAdmission()
        val result = fixture.coordinator.execute(recovered, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.Completed

        val committed = result.result as ExistingInstallationRestartCompletionResult.Committed
        assertEquals(OperationStatus.SUCCEEDED, committed.durable.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, committed.durable.snapshot.checkpoint.semantics)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(1, fixture.verifyCalls)
        assertEquals(
            listOf(
                CheckpointSemantics.RESTART_IN_FLIGHT,
                CheckpointSemantics.POST_VERIFY_REQUIRED,
                CheckpointSemantics.COMMIT_VERIFIED,
                CheckpointSemantics.TERMINAL,
            ),
            fixture.journal.advancedSemantics,
        )
        fixture.releaseAdmission(recovered)
    }

    @Test
    fun `process recreation at mutation not started cannot reconstruct restart authority`() = runSuspend {
        val fixture = Fixture()
        fixture.registerConfirmation()
        val recreated = fixture.newCoordinatorWithEmptyEntryRegistry()

        assertEquals(
            ExistingInstallationRestartPreparationResult.FreshPreflightRequired,
            recreated.prepareTransport(fixture.admission),
        )
        assertEquals(
            ExistingInstallationRestartRuntimeResult.FreshPreflightRequired,
            recreated.execute(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.dispatchCalls)
    }

    @Test
    fun `visible confirmation runs exact preflight under shared server lease and dispatches once`() = runSuspend {
        val fixture = Fixture()
        fixture.registerConfirmation()
        assertEquals(ExistingInstallationRestartPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission))
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
        assertTrue(result is ExistingInstallationRestartRuntimeResult.Dispatch)
        assertEquals(1, fixture.preflightCalls)
        assertEquals(1, fixture.dispatchCalls)
        fixture.releaseAdmission(fixture.admission)
        val recovered = fixture.recoveryAdmission()
        assertTrue(fixture.coordinator.execute(recovered, fixture.binding) is ExistingInstallationRestartRuntimeResult.Completed)
        assertEquals(1, fixture.preflightCalls)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(1, fixture.verifyCalls)
        fixture.releaseAdmission(recovered)
    }

    @Test
    fun `metadata change before preflight terminates without ssh or dispatch`() = runSuspend {
        val fixture = Fixture(); fixture.registerConfirmation(); fixture.changeMetadata()
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.PreflightRejected
        assertEquals(ExistingInstallationRestartPreflightRejection.LOCAL_METADATA_CHANGED, result.reason)
        assertEquals(OperationStatus.FAILED, fixture.journal.current.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(0, fixture.preflightCalls)
        assertEquals(0, fixture.dispatchCalls)
    }

    @Test
    fun `metadata change during preflight invalidates observed authority before dispatch`() = runSuspend {
        val fixture = Fixture(); fixture.registerConfirmation(); fixture.preflightHook = { fixture.changeMetadata() }
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.PreflightRejected
        assertEquals(ExistingInstallationRestartPreflightRejection.LOCAL_METADATA_CHANGED, result.reason)
        assertEquals(1, fixture.preflightCalls)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(false, fixture.coordinator.discardPreflight(fixture.operationId))
    }

    @Test
    fun `rejected read only preflight records truthful failure and consumes confirmation`() = runSuspend {
        val fixture = Fixture(); fixture.registerConfirmation()
        fixture.preflightRejection = ExistingInstallationRestartPreflightRejection.DIRECT_ROOT_REQUIRED
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.PreflightRejected
        assertEquals(ExistingInstallationRestartPreflightRejection.DIRECT_ROOT_REQUIRED, result.reason)
        assertEquals("RESTART_PREFLIGHT_DIRECT_ROOT_REQUIRED", fixture.journal.current.snapshot.checkpoint.phaseName)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(false, fixture.coordinator.discardPreflight(fixture.operationId))
    }

    @Test
    fun `confirmation that expires during preflight cannot authorize restart`() = runSuspend {
        val fixture = Fixture(); fixture.registerConfirmation(); fixture.preflightHook = { fixture.clockOffsetSeconds = 91 }
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.PreflightRejected
        assertEquals(ExistingInstallationRestartPreflightRejection.CONFIRMATION_EXPIRED, result.reason)
        assertEquals(0, fixture.dispatchCalls)
    }

    @Test
    fun `durable blocker prevents confirmation consumption and preflight`() = runSuspend {
        val fixture = Fixture(); fixture.registerConfirmation()
        fixture.journal.nonTerminal = listOf(fixture.journal.current, fixture.otherUnsafeOperation())
        assertTrue(fixture.coordinator.execute(fixture.admission, fixture.binding) is ExistingInstallationRestartRuntimeResult.BlockedByDurableMutation)
        assertEquals(0, fixture.preflightCalls)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(ExistingInstallationRestartPreparationResult.TransportRequired, fixture.coordinator.prepareTransport(fixture.admission))
    }

    @Test
    fun `durable same server blocker stops before one shot preflight is consumed`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.journal.nonTerminal = listOf(fixture.journal.current, fixture.otherUnsafeOperation())

        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationRestartRuntimeResult.BlockedByDurableMutation

        assertEquals(1, result.blockers.size)
        assertEquals(fixture.otherOperationId, result.blockers.single().operationId)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(
            ExistingInstallationRestartPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
    }

    @Test
    fun `stale exact session id is rejected before dispatch and authority remains available`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        val stale = fixture.binding.copy(sessionId = SessionId("stale-phase94-session"))

        val result = fixture.coordinator.execute(fixture.admission, stale)
            as ExistingInstallationRestartRuntimeResult.StaleSession

        assertEquals(stale.sessionId, result.expectedSessionId)
        assertEquals(fixture.binding.sessionId, result.actualSessionId)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(
            ExistingInstallationRestartPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
    }

    private class Fixture {
        val now = Instant.parse("2026-09-13T11:15:00Z")
        val operationId = OperationId("phase94-runtime-restart")
        val otherOperationId = OperationId("phase94-runtime-other")
        val serverId = ServerId("phase94-runtime-server")
        val accessId = ServerAccessId("phase94-runtime-access")
        val installationId = XuiInstallationId("phase94-runtime-installation")
        private val managedInstallId = ManagedInstallId("v1-fedcba9876543210fedcba9876543210")
        val installation = XuiInstallation(
            id = installationId,
            serverId = serverId,
            ownership = InstallationOwnership.MANAGED,
            identity = InstallationIdentity(
                serviceUnit = "x-ui.service",
                binaryPath = "/usr/local/x-ui/x-ui",
                rootPath = "/usr/local/x-ui",
                databasePath = "/etc/x-ui/x-ui.db",
                managedInstallId = managedInstallId,
            ),
            baseline = InstallationBaseline(
                serviceUnit = "x-ui.service",
                binaryPath = "/usr/local/x-ui/x-ui",
                rootPath = "/usr/local/x-ui",
                databasePath = "/etc/x-ui/x-ui.db",
                panelPort = 2053,
                webBasePath = "/panel/",
                listenAddress = "127.0.0.1",
                capturedAt = now.minusSeconds(600),
            ),
        )
        private val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.95", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("phase94-runtime-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase94-runtime"),
        )
        val journal = FakeJournal(
            VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = operationId,
                    type = OperationType.RESTART,
                    target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(10)),
                    startedAt = now.minusSeconds(60),
                    updatedAt = now.minusSeconds(10),
                ),
                OperationRevision(0),
            ),
        )
        private val installationRepository = FakeInstallationRepository(installation)
        private val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val sessionRegistry = ExactSessionRegistry()
        private val serverMutationRegistry = ServerMutationLeaseRegistry()
        private val entryRegistry = ExistingInstallationRestartEntryRegistry()
        val binding = SessionBinding(SessionId("phase94-runtime-session"), accessId, SessionOwner.Operation(operationId))
        private val handle = FakeHandle(binding)
        var dispatchCalls = 0
        var verifyCalls = 0
        var preflightCalls = 0
        var clockOffsetSeconds = 0L
        var preflightHook: (() -> Unit)? = null
        var preflightRejection: ExistingInstallationRestartPreflightRejection? = null
        private val accessRepository = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
                if (serverAccessId == access.id) RepositoryResult.Success(access) else RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(access))
            override suspend fun delete(serverAccessId: ServerAccessId) = RepositoryResult.StorageFailure("not used")
        }
        private val preflightPort = ExistingInstallationRestartPreflightPort { current, exactInstallation, exactAccess, exactSession, barrier ->
            preflightCalls++
            assertEquals(installation, exactInstallation)
            assertEquals(access, exactAccess)
            assertEquals(binding, exactSession.binding)
            assertEquals(ExistingInstallationMutationBarrierState.PROVEN_CLEAR, barrier)
            // The common server lease is already held throughout preflight and dispatch.
            assertEquals(ServerMutationAcquireResult.AlreadyOwned, serverMutationRegistry.tryAcquire(serverId, otherOperationId))
            preflightHook?.invoke()
            val rejection = preflightRejection
            if (rejection != null) ExistingInstallationRestartPreflightResult.Rejected(rejection)
            else ExistingInstallationRestartPreflightResult.Verified(verifiedPreflight(current, installation, access, now))
        }

        private val dispatchPort = ExistingInstallationRestartDispatchPort { _, _, current, _ ->
            dispatchCalls += 1
            val advanced = journal.advance(
                operationId,
                current.revision,
                current.snapshot.copy(
                    checkpoint = OperationCheckpoint("RESTART_DISPATCHED", CheckpointSemantics.RESTART_IN_FLIGHT, now),
                    updatedAt = now,
                ),
            ) as OperationJournalResult.Success
            ExistingInstallationRestartDispatchResult.ReconnectRequired(advanced.value)
        }
        private val postVerifyPort = ExistingInstallationRestartPostVerifyPort { current, exactInstallation, exactSession ->
            verifyCalls += 1
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, current.snapshot.checkpoint.semantics)
            assertEquals(installation, exactInstallation)
            assertEquals(binding, exactSession.binding)
            ExistingInstallationRestartPostVerifyResult.Verified(now.plusSeconds(2))
        }

        val admission: RecoveryRuntimeAdmission
        val coordinator: ExistingInstallationRestartRuntimeCoordinator

        init {
            sessionRegistry.install(handle)
            admission = newAdmission(journal.current, RecoveryAction.RECONNECT_EXACT_OWNER)
            coordinator = createCoordinator(entryRegistry)
        }

        fun registerPreflight() {
            assertEquals(
                ExistingInstallationRestartEntryRegistrationResult.Registered,
                coordinator.registerPreflight(verifiedPreflight(journal.current, installation, access, now)),
            )
        }

        fun registerConfirmation() {
            val c = (ExistingInstallationRestartConfirmationPolicy.confirm(journal.current, installation, access, now)
                as ExistingInstallationRestartConfirmationResult.Confirmed).confirmation
            assertEquals(true, coordinator.registerConfirmation(c))
            assertEquals(false, coordinator.registerConfirmation(c))
        }

        fun changeMetadata() {
            installationRepository.record = VersionedRecord(installation.copy(baseline = installation.baseline.copy(panelPort = 2443)), RecordRevision(2))
        }

        fun recoveryAdmission(): RecoveryRuntimeAdmission =
            newAdmission(journal.current, RecoveryAction.RECONCILE_READ_ONLY)

        fun releaseAdmission(admission: RecoveryRuntimeAdmission) {
            assertEquals(OperationRuntimeReleaseResult.RELEASED, runtimeRegistry.release(admission.runtimeLease))
        }

        fun newCoordinatorWithEmptyEntryRegistry(): ExistingInstallationRestartRuntimeCoordinator =
            createCoordinator(ExistingInstallationRestartEntryRegistry())

        fun otherUnsafeOperation(): VersionedOperationSnapshot = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = otherOperationId,
                type = OperationType.UNINSTALL,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint("OTHER_UNCERTAIN", CheckpointSemantics.MUTATION_IN_FLIGHT, now.minusSeconds(2)),
                startedAt = now.minusSeconds(30),
                updatedAt = now.minusSeconds(2),
            ),
            OperationRevision(2),
        )

        private fun newAdmission(
            current: VersionedOperationSnapshot,
            action: RecoveryAction,
        ): RecoveryRuntimeAdmission {
            val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
            return RecoveryRuntimeAdmission(
                ColdStartRecoveryPlan(
                    operationId = operationId,
                    target = current.snapshot.target,
                    expectedRevision = current.revision,
                    action = action,
                    automaticAllowed = true,
                ),
                lease,
            )
        }

        private fun createCoordinator(
            restartEntries: ExistingInstallationRestartEntryRegistry,
        ) = ExistingInstallationRestartRuntimeCoordinator(
            journal = journal,
            installationRepository = installationRepository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = restartEntries,
            dispatchPort = dispatchPort,
            postVerifyPort = postVerifyPort,
            now = { now.plusSeconds(journal.current.revision.value + clockOffsetSeconds) },
            accessRepository = accessRepository,
            preflightPort = preflightPort,
        )
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current = initial
        var nonTerminal: List<VersionedOperationSnapshot> = listOf(initial)
        val advancedSemantics = mutableListOf<CheckpointSemantics>()

        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.StorageFailure("not used")
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(nonTerminal.map { if (it.snapshot.operationId == current.snapshot.operationId) current else it })
        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            advancedSemantics += next.checkpoint.semantics
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }

    private class FakeInstallationRepository(
        installation: XuiInstallation,
    ) : XuiInstallationRepository {
        var record = VersionedRecord(installation, RecordRevision(1))
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
            if (installationId == record.value.id) RepositoryResult.Success(record) else RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(record))
        override suspend fun create(installation: XuiInstallation) = RepositoryResult.StorageFailure("not used")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
    }

    private class FakeHandle(override val binding: SessionBinding) : SshSessionHandle {
        override val isOpen: Boolean = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult =
            error("runtime port test must not execute raw SSH")
        override fun close() = Unit
    }

    companion object {
        private fun verifiedPreflight(
            current: VersionedOperationSnapshot,
            installation: XuiInstallation,
            access: ServerAccess,
            now: Instant,
        ): VerifiedExistingInstallationActionPreflight {
            val proof = InstallationProof(
                TargetProofId("phase94-runtime-proof"),
                installation.id,
                installation.serverId,
                access.id,
                installation.identity,
                now.minusSeconds(3),
                now.plusSeconds(120),
            )
            val verifiedTarget = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now)
                as TargetVerificationResult.Verified).target
            val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, verifiedTarget, now)
                as ExistingInstallationActionAuthorizationResult.Verified).authorization
            val evidence = ExistingInstallationPreflightEvidence(
                scope = ExistingInstallationActionScope(
                    current.snapshot.operationId,
                    current.revision.value,
                    installation.serverId,
                    access.id,
                    installation.id,
                    OperationType.RESTART,
                    installation.ownership,
                    installation.identity.managedInstallId,
                ),
                installationProof = proof,
                accessPathState = ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
                layoutCapability = ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
                privilegeCapability = ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
                mutationBarrierState = ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
                observedAt = now.minusSeconds(2),
                validUntil = now.plusSeconds(60),
            )
            return (ExistingInstallationActionPreflightPolicy.verify(
                authorization, current, installation, evidence, now,
            ) as ExistingInstallationActionPreflightResult.Verified).preflight
        }
    }
}

private fun <T> runSuspend(block: suspend () -> T): T {
    var result: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(value: Result<T>) { result = value }
    })
    return result!!.getOrThrow()
}
