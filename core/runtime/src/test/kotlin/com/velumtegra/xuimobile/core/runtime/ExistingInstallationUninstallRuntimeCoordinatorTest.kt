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

class ExistingInstallationUninstallRuntimeCoordinatorTest {
    @Test
    fun `fresh uninstall consumes one preflight and dispatches once`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()

        assertEquals(
            ExistingInstallationUninstallPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationUninstallRuntimeResult.Dispatch

        assertTrue(result.result is ExistingInstallationUninstallDispatchResult.PostVerifyRequired)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(false, fixture.coordinator.discardPreflight(fixture.operationId))
    }

    @Test
    fun `old admission becomes stale after uninstall checkpoint and cannot postverify`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)

        val second = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationUninstallRuntimeResult.StalePlan

        assertEquals(OperationRevision(0), second.expectedRevision)
        assertEquals(OperationRevision(1), second.actualRevision)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(0, fixture.absenceVerifyCalls)
    }

    @Test
    fun `new exact recovery admission never replays uninstall and commits only after read only absence verify`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)
        fixture.releaseAdmission(fixture.admission)

        val recovered = fixture.recoveryAdmission()
        val result = fixture.coordinator.execute(recovered, fixture.binding)
            as ExistingInstallationUninstallRuntimeResult.Completed

        val committed = result.result as ExistingInstallationUninstallCompletionResult.Committed
        assertEquals(OperationStatus.SUCCEEDED, committed.durable.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, committed.durable.snapshot.checkpoint.semantics)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(1, fixture.absenceVerifyCalls)
        assertEquals(ExistingInstallationUninstallLocalCleanupDisposition.DEFERRED_REFERENCES_RETAINED, committed.localCleanup)
        assertEquals(0, fixture.installationRepository.deleteCalls)
        assertEquals(
            listOf(
                CheckpointSemantics.MUTATION_IN_FLIGHT,
                CheckpointSemantics.POST_VERIFY_REQUIRED,
                CheckpointSemantics.COMMIT_VERIFIED,
                CheckpointSemantics.TERMINAL,
            ),
            fixture.journal.advancedSemantics,
        )
        fixture.releaseAdmission(recovered)
    }

    @Test
    fun `process recreation at mutation not started cannot reconstruct uninstall authority`() = runSuspend {
        val fixture = Fixture()
        val recreated = fixture.newCoordinatorWithEmptyEntryRegistry()

        assertEquals(
            ExistingInstallationUninstallPreparationResult.FreshPreflightRequired,
            recreated.prepareTransport(fixture.admission),
        )
        assertEquals(
            ExistingInstallationUninstallRuntimeResult.FreshPreflightRequired,
            recreated.execute(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.dispatchCalls)
    }

    @Test
    fun `durable same server blocker stops before one shot preflight is consumed`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.journal.nonTerminal = listOf(fixture.journal.current, fixture.otherUnsafeOperation())

        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationUninstallRuntimeResult.BlockedByDurableMutation

        assertEquals(1, result.blockers.size)
        assertEquals(fixture.otherOperationId, result.blockers.single().operationId)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(
            ExistingInstallationUninstallPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
    }

    @Test
    fun `stale exact session id is rejected before dispatch and authority remains available`() = runSuspend {
        val fixture = Fixture()
        fixture.registerPreflight()
        val stale = fixture.binding.copy(sessionId = SessionId("stale-phase96-session"))

        val result = fixture.coordinator.execute(fixture.admission, stale)
            as ExistingInstallationUninstallRuntimeResult.StaleSession

        assertEquals(stale.sessionId, result.expectedSessionId)
        assertEquals(fixture.binding.sessionId, result.actualSessionId)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(
            ExistingInstallationUninstallPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
    }

    private class Fixture {
        val now = Instant.parse("2026-09-13T11:15:00Z")
        val operationId = OperationId("phase96-runtime-uninstall")
        val otherOperationId = OperationId("phase96-runtime-other")
        val serverId = ServerId("phase96-runtime-server")
        val accessId = ServerAccessId("phase96-runtime-access")
        val installationId = XuiInstallationId("phase96-runtime-installation")
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
            auth = SshAuthRef.Password(SecretId("phase96-runtime-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase96-runtime"),
        )
        val journal = FakeJournal(
            VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = operationId,
                    type = OperationType.UNINSTALL,
                    target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(10)),
                    startedAt = now.minusSeconds(60),
                    updatedAt = now.minusSeconds(10),
                ),
                OperationRevision(0),
            ),
        )
        val installationRepository = FakeInstallationRepository(installation)
        private val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val sessionRegistry = ExactSessionRegistry()
        private val serverMutationRegistry = ServerMutationLeaseRegistry()
        private val entryRegistry = ExistingInstallationUninstallEntryRegistry()
        val binding = SessionBinding(SessionId("phase96-runtime-session"), accessId, SessionOwner.Operation(operationId))
        private val handle = FakeHandle(binding)
        var dispatchCalls = 0
        var absenceVerifyCalls = 0

        private val dispatchPort = ExistingInstallationUninstallDispatchPort { _, _, current, _ ->
            dispatchCalls += 1
            val advanced = journal.advance(
                operationId,
                current.revision,
                current.snapshot.copy(
                    checkpoint = OperationCheckpoint("UNINSTALL_DISPATCHED", CheckpointSemantics.MUTATION_IN_FLIGHT, now),
                    updatedAt = now,
                ),
            ) as OperationJournalResult.Success
            ExistingInstallationUninstallDispatchResult.PostVerifyRequired(advanced.value)
        }
        private val absencePort = ExistingInstallationUninstallAbsencePort { current, exactInstallation, exactSession ->
            absenceVerifyCalls += 1
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, current.snapshot.checkpoint.semantics)
            assertEquals(installation, exactInstallation)
            assertEquals(binding, exactSession.binding)
            ExistingInstallationUninstallAbsenceResult.Verified(now.plusSeconds(2))
        }

        val admission: RecoveryRuntimeAdmission
        val coordinator: ExistingInstallationUninstallRuntimeCoordinator

        init {
            sessionRegistry.install(handle)
            admission = newAdmission(journal.current, RecoveryAction.RECONNECT_EXACT_OWNER)
            coordinator = createCoordinator(entryRegistry)
        }

        fun registerPreflight() {
            assertEquals(
                ExistingInstallationUninstallEntryRegistrationResult.Registered,
                coordinator.registerPreflight(verifiedPreflight(journal.current, installation, access, now)),
            )
        }

        fun recoveryAdmission(): RecoveryRuntimeAdmission =
            newAdmission(journal.current, RecoveryAction.RECONCILE_READ_ONLY)

        fun releaseAdmission(admission: RecoveryRuntimeAdmission) {
            assertEquals(OperationRuntimeReleaseResult.RELEASED, runtimeRegistry.release(admission.runtimeLease))
        }

        fun newCoordinatorWithEmptyEntryRegistry(): ExistingInstallationUninstallRuntimeCoordinator =
            createCoordinator(ExistingInstallationUninstallEntryRegistry())

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
            uninstallEntries: ExistingInstallationUninstallEntryRegistry,
        ) = ExistingInstallationUninstallRuntimeCoordinator(
            journal = journal,
            installationRepository = installationRepository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = uninstallEntries,
            dispatchPort = dispatchPort,
            absencePort = absencePort,
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
        private val record = VersionedRecord(installation, RecordRevision(1))
        var deleteCalls = 0
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
            if (installationId == record.value.id) RepositoryResult.Success(record) else RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(record))
        override suspend fun create(installation: XuiInstallation) = RepositoryResult.StorageFailure("not used")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> {
            deleteCalls += 1
            return RepositoryResult.StorageFailure("local cleanup must remain deferred")
        }
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
                TargetProofId("phase96-runtime-proof"),
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
                    OperationType.UNINSTALL,
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
