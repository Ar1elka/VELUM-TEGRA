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

class ExistingInstallationRecoveryRuntimeCoordinatorTest {
    @Test
    fun `fresh recovery consumes one preflight and dispatches one exact repair after read only diagnosis`() = runSuspendRecovery {
        val f = Fixture()
        f.registerPreflight()

        assertEquals(ExistingInstallationRecoveryPreparationResult.TransportRequired, f.coordinator.prepareTransport(f.admission))
        val result = f.coordinator.execute(f.admission, f.binding) as ExistingInstallationRecoveryRuntimeResult.Repair
        assertTrue(result.result is ExistingInstallationRecoveryRepairResult.PostVerifyRequired)
        assertEquals(1, f.diagnosisCalls)
        assertEquals(1, f.repairCalls)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, f.journal.current.snapshot.checkpoint.semantics)
        assertEquals(false, f.coordinator.discardPreflight(f.operationId))
    }

    @Test
    fun `healthy recovery commits without any remote mutation`() = runSuspendRecovery {
        val f = Fixture(healthy = true)
        f.registerPreflight()

        val result = f.coordinator.execute(f.admission, f.binding) as ExistingInstallationRecoveryRuntimeResult.Completed
        val committed = result.result as ExistingInstallationRecoveryCompletionResult.Committed
        assertEquals(OperationStatus.SUCCEEDED, committed.durable.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, committed.durable.snapshot.checkpoint.semantics)
        assertEquals(1, f.diagnosisCalls)
        assertEquals(0, f.repairCalls)
        assertEquals(listOf(CheckpointSemantics.COMMIT_VERIFIED, CheckpointSemantics.TERMINAL), f.journal.advancedSemantics)
    }

    @Test
    fun `old admission is stale after mutation checkpoint and cannot verify or replay repair`() = runSuspendRecovery {
        val f = Fixture()
        f.registerPreflight()
        f.coordinator.execute(f.admission, f.binding)

        val second = f.coordinator.execute(f.admission, f.binding) as ExistingInstallationRecoveryRuntimeResult.StalePlan
        assertEquals(OperationRevision(0), second.expectedRevision)
        assertEquals(OperationRevision(1), second.actualRevision)
        assertEquals(1, f.repairCalls)
        assertEquals(0, f.verifyCalls)
    }

    @Test
    fun `new exact recovery admission advances mutation in flight only to read only verify and terminal commit`() = runSuspendRecovery {
        val f = Fixture()
        f.registerPreflight()
        f.coordinator.execute(f.admission, f.binding)
        f.releaseAdmission(f.admission)

        val recovered = f.recoveryAdmission()
        val result = f.coordinator.execute(recovered, f.binding) as ExistingInstallationRecoveryRuntimeResult.Completed
        val committed = result.result as ExistingInstallationRecoveryCompletionResult.Committed
        assertEquals(OperationStatus.SUCCEEDED, committed.durable.snapshot.status)
        assertEquals(1, f.repairCalls)
        assertEquals(1, f.verifyCalls)
        assertEquals(
            listOf(
                CheckpointSemantics.MUTATION_IN_FLIGHT,
                CheckpointSemantics.POST_VERIFY_REQUIRED,
                CheckpointSemantics.COMMIT_VERIFIED,
                CheckpointSemantics.TERMINAL,
            ),
            f.journal.advancedSemantics,
        )
        f.releaseAdmission(recovered)
    }

    @Test
    fun `process recreation at mutation not started cannot reconstruct recovery authority`() = runSuspendRecovery {
        val f = Fixture()
        val recreated = f.newCoordinatorWithEmptyEntryRegistry()
        assertEquals(ExistingInstallationRecoveryPreparationResult.FreshPreflightRequired, recreated.prepareTransport(f.admission))
        assertEquals(ExistingInstallationRecoveryRuntimeResult.FreshPreflightRequired, recreated.execute(f.admission, f.binding))
        assertEquals(0, f.diagnosisCalls)
        assertEquals(0, f.repairCalls)
    }

    @Test
    fun `durable same server uncertain mutation blocks before repair dispatch`() = runSuspendRecovery {
        val f = Fixture()
        f.registerPreflight()
        f.journal.nonTerminal = listOf(f.journal.current, f.otherUnsafeOperation())

        val result = f.coordinator.execute(f.admission, f.binding) as ExistingInstallationRecoveryRuntimeResult.BlockedByDurableMutation
        assertEquals(1, result.blockers.size)
        assertEquals(f.otherOperationId, result.blockers.single().operationId)
        assertEquals(1, f.diagnosisCalls)
        assertEquals(0, f.repairCalls)
    }

    private class Fixture(
        private val healthy: Boolean = false,
    ) {
        val now = Instant.parse("2026-09-13T12:20:00Z")
        val operationId = OperationId("phase95-runtime-recovery")
        val otherOperationId = OperationId("phase95-runtime-other")
        val serverId = ServerId("phase95-runtime-server")
        val accessId = ServerAccessId("phase95-runtime-access")
        val installationId = XuiInstallationId("phase95-runtime-installation")
        val installation = XuiInstallation(
            installationId,
            serverId,
            InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", now.minusSeconds(600)),
        )
        private val access = ServerAccess(
            accessId,
            serverId,
            SshEndpoint("203.0.113.95", 22),
            "root",
            SshAuthRef.Password(SecretId("phase95-runtime-secret")),
            HostKeyFingerprint("SHA256:phase95-runtime"),
        )
        val journal = FakeJournal(
            VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId,
                    OperationType.RECOVERY,
                    OperationTarget.InstallationTarget(serverId, accessId, installationId),
                    OperationStatus.RUNNING,
                    OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(10)),
                    now.minusSeconds(60),
                    now.minusSeconds(10),
                ),
                OperationRevision(0),
            ),
        )
        private val installationRepository = FakeInstallationRepository(installation)
        private val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val sessionRegistry = ExactSessionRegistry()
        private val serverMutationRegistry = ServerMutationLeaseRegistry()
        val binding = SessionBinding(SessionId("phase95-runtime-session"), accessId, SessionOwner.Operation(operationId))
        private val handle = FakeHandle(binding)
        var diagnosisCalls = 0
        var repairCalls = 0
        var verifyCalls = 0

        private val diagnosisPort = ExistingInstallationRecoveryDiagnosisPort { preflight, _, _, _ ->
            diagnosisCalls++
            val evidence = ExistingInstallationRecoveryEvidence(
                preflight.evidence.scope,
                if (healthy) ExistingInstallationRecoveryDiagnosis.HEALTHY else ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT,
                if (healthy) ManagementServiceState.ACTIVE else ManagementServiceState.INACTIVE,
                now,
                now.plusSeconds(30),
            )
            ExistingInstallationRecoveryDiagnosisResult.Diagnosed(
                evidence,
                ExistingInstallationRecoveryRepairPolicy.authorize(preflight, evidence, now),
            )
        }
        private val repairPort = ExistingInstallationRecoveryRepairPort { _, current, _ ->
            repairCalls++
            val advanced = journal.advance(
                operationId,
                current.revision,
                current.snapshot.copy(
                    checkpoint = OperationCheckpoint("RECOVERY_REPAIR_DISPATCHED", CheckpointSemantics.MUTATION_IN_FLIGHT, now),
                    updatedAt = now,
                ),
            ) as OperationJournalResult.Success
            ExistingInstallationRecoveryRepairResult.PostVerifyRequired(advanced.value)
        }
        private val postVerifyPort = ExistingInstallationRecoveryPostVerifyPort { current, exactInstallation, exactSession ->
            verifyCalls++
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, current.snapshot.checkpoint.semantics)
            assertEquals(installation, exactInstallation)
            assertEquals(binding, exactSession.binding)
            ExistingInstallationRestartPostVerifyResult.Verified(now.plusSeconds(2))
        }

        val admission: RecoveryRuntimeAdmission
        val coordinator: ExistingInstallationRecoveryRuntimeCoordinator

        init {
            sessionRegistry.install(handle)
            admission = newAdmission(journal.current, RecoveryAction.RECONNECT_EXACT_OWNER)
            coordinator = createCoordinator(ExistingInstallationRecoveryEntryRegistry())
        }

        fun registerPreflight() {
            assertEquals(
                ExistingInstallationRecoveryEntryRegistrationResult.Registered,
                coordinator.registerPreflight(verifiedPreflight(journal.current, installation, access, now)),
            )
        }

        fun recoveryAdmission(): RecoveryRuntimeAdmission = newAdmission(journal.current, RecoveryAction.RECONCILE_READ_ONLY)

        fun releaseAdmission(admission: RecoveryRuntimeAdmission) {
            assertEquals(OperationRuntimeReleaseResult.RELEASED, runtimeRegistry.release(admission.runtimeLease))
        }

        fun newCoordinatorWithEmptyEntryRegistry() = createCoordinator(ExistingInstallationRecoveryEntryRegistry())

        fun otherUnsafeOperation() = VersionedOperationSnapshot(
            OperationSnapshot(
                otherOperationId,
                OperationType.UNINSTALL,
                OperationTarget.InstallationTarget(serverId, accessId, installationId),
                OperationStatus.RECONCILIATION_REQUIRED,
                OperationCheckpoint("OTHER_UNCERTAIN", CheckpointSemantics.MUTATION_IN_FLIGHT, now.minusSeconds(2)),
                now.minusSeconds(30),
                now.minusSeconds(2),
            ),
            OperationRevision(2),
        )

        private fun newAdmission(current: VersionedOperationSnapshot, action: RecoveryAction): RecoveryRuntimeAdmission {
            val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
            return RecoveryRuntimeAdmission(
                ColdStartRecoveryPlan(operationId, current.snapshot.target, current.revision, action, automaticAllowed = true),
                lease,
            )
        }

        private fun createCoordinator(entries: ExistingInstallationRecoveryEntryRegistry) = ExistingInstallationRecoveryRuntimeCoordinator(
            journal,
            installationRepository,
            runtimeRegistry,
            sessionRegistry,
            serverMutationRegistry,
            entries,
            diagnosisPort,
            repairPort,
            postVerifyPort,
            now = { now.plusSeconds(journal.current.revision.value) },
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
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            advancedSemantics += next.checkpoint.semantics
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
    }

    private class FakeInstallationRepository(installation: XuiInstallation) : XuiInstallationRepository {
        private val record = VersionedRecord(installation, RecordRevision(1))
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
            if (installationId == record.value.id) RepositoryResult.Success(record) else RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(record))
        override suspend fun create(installation: XuiInstallation) = RepositoryResult.StorageFailure("not used")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
    }

    private class FakeHandle(override val binding: SessionBinding) : SshSessionHandle {
        override val isOpen = true
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
            val proof = InstallationProof(TargetProofId("phase95-runtime-proof"), installation.id, installation.serverId, access.id, installation.identity, now.minusSeconds(3), now.plusSeconds(120))
            val target = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now) as TargetVerificationResult.Verified).target
            val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, target, now) as ExistingInstallationActionAuthorizationResult.Verified).authorization
            val evidence = ExistingInstallationPreflightEvidence(
                ExistingInstallationActionScope(current.snapshot.operationId, current.revision.value, installation.serverId, access.id, installation.id, OperationType.RECOVERY, installation.ownership, null),
                proof,
                ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
                ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
                ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
                ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
                now.minusSeconds(2),
                now.plusSeconds(60),
            )
            return (ExistingInstallationActionPreflightPolicy.verify(authorization, current, installation, evidence, now) as ExistingInstallationActionPreflightResult.Verified).preflight
        }
    }
}

private fun <T> runSuspendRecovery(block: suspend () -> T): T {
    var result: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(value: Result<T>) { result = value }
    })
    return result!!.getOrThrow()
}
