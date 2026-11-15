package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.FreshInstallAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.FreshInstallVerificationResult
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.FreshInstallConflictState
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPreflightProof
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.CapturedOutput
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionResult
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerRuntimeCoordinatorTest {
    @Test
    fun `fresh mutation requires live authority then uses one mutation lease and post verify path`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.MUTATION_NOT_STARTED)
        fixture.registerFreshAuthority()

        assertEquals(
            InstallerRuntimePreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)

        assertTrue(result is InstallerRuntimeExecutionResult.PostInstall)
        assertEquals(1, fixture.mutationCalls)
        assertEquals(1, fixture.postInstallCalls)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(OperationStatus.RUNNING, fixture.journal.current.snapshot.status)
        assertEquals(false, fixture.coordinator.discardFreshAuthorization(fixture.operationId))
    }

    @Test
    fun `process local same server lease blocks competing live mutation`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.MUTATION_NOT_STARTED)
        fixture.registerFreshAuthority()
        val competing = fixture.serverMutationRegistry.tryAcquire(fixture.serverId, fixture.otherOperationId)
            as ServerMutationAcquireResult.Acquired

        try {
            assertEquals(
                InstallerRuntimeExecutionResult.ServerMutationAlreadyOwned,
                fixture.coordinator.execute(fixture.admission, fixture.binding),
            )
            assertEquals(0, fixture.mutationCalls)
            assertEquals(0, fixture.postInstallCalls)
            assertEquals(
                InstallerRuntimePreparationResult.TransportRequired,
                fixture.coordinator.prepareTransport(fixture.admission),
            )
        } finally {
            fixture.serverMutationRegistry.release(competing.lease)
        }
    }

    @Test
    fun `stale exact session id is rejected before mutation`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.MUTATION_NOT_STARTED)
        fixture.registerFreshAuthority()
        val staleBinding = fixture.binding.copy(sessionId = SessionId("phase87-stale-session"))

        val result = fixture.coordinator.execute(fixture.admission, staleBinding)
            as InstallerRuntimeExecutionResult.StaleSession

        assertEquals(staleBinding.sessionId, result.expectedSessionId)
        assertEquals(fixture.binding.sessionId, result.actualSessionId)
        assertEquals(0, fixture.mutationCalls)
        assertEquals(0, fixture.postInstallCalls)
    }

    @Test
    fun `mutation in flight recovery promotes to post verify and never calls mutation executor`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.MUTATION_IN_FLIGHT)
        fixture.registerFreshAuthority() // Even forged leftover process authority must not enable replay.

        assertEquals(
            InstallerRuntimePreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
        assertEquals(
            false,
            fixture.coordinator.discardFreshAuthorization(fixture.operationId),
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)

        assertTrue(result is InstallerRuntimeExecutionResult.PostInstall)
        assertEquals(0, fixture.mutationCalls)
        assertEquals(1, fixture.postInstallCalls)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, fixture.journal.current.snapshot.status)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals("INSTALLER_RUNTIME_RECONCILIATION_REQUIRED", fixture.journal.current.snapshot.checkpoint.phaseName)
    }

    @Test
    fun `durable unsafe same server blocker prevents fresh mutation before authority consumption`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.MUTATION_NOT_STARTED)
        fixture.registerFreshAuthority()
        fixture.journal.nonTerminal = listOf(
            fixture.journal.current,
            fixture.otherUnsafeOperation(),
        )

        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as InstallerRuntimeExecutionResult.BlockedByDurableMutation

        assertEquals(1, result.blockers.size)
        assertEquals(fixture.otherOperationId, result.blockers.single().operationId)
        assertEquals(0, fixture.mutationCalls)
        assertEquals(0, fixture.postInstallCalls)
        // Authority is still available because the durable barrier failed before the mutation boundary.
        assertEquals(
            InstallerRuntimePreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
    }

    @Test
    fun `missing fresh authority stops before ssh mutation`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.MUTATION_NOT_STARTED)

        assertEquals(
            InstallerRuntimePreparationResult.FreshAuthorizationRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
        assertEquals(
            InstallerRuntimeExecutionResult.FreshAuthorizationRequired,
            fixture.coordinator.execute(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.mutationCalls)
        assertEquals(0, fixture.postInstallCalls)
    }

    @Test
    fun `fresh authority cannot mutate a non running predispatch operation`() = runSuspend {
        val fixture = Fixture(
            semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
            status = OperationStatus.RECONCILIATION_REQUIRED,
        )
        fixture.registerFreshAuthority()

        val prepared = fixture.coordinator.prepareTransport(fixture.admission)
            as InstallerRuntimePreparationResult.ContractViolation

        assertTrue(prepared.reason.contains("RUNNING"))
        assertEquals(0, fixture.mutationCalls)
        assertEquals(0, fixture.postInstallCalls)
    }

    @Test
    fun `commit verified finishes locally before transport`() = runSuspend {
        val fixture = Fixture(CheckpointSemantics.COMMIT_VERIFIED)

        val prepared = fixture.coordinator.prepareTransport(fixture.admission)
            as InstallerRuntimePreparationResult.Completed

        assertTrue(prepared.result is InstallerPostInstallCoordinatorResult.Succeeded)
        assertEquals(1, fixture.finishCommittedCalls)
        assertEquals(0, fixture.mutationCalls)
        assertEquals(0, fixture.postInstallCalls)
    }

    private class Fixture(
        semantics: CheckpointSemantics,
        status: OperationStatus = OperationStatus.RUNNING,
    ) {
        val now = Instant.parse("2026-09-12T12:00:00Z")
        val operationId = OperationId("phase87-install")
        val otherOperationId = OperationId("phase87-other")
        val serverId = ServerId("phase87-server")
        val accessId = ServerAccessId("phase87-access")
        private val startedAt = now.minusSeconds(120)
        val journal = FakeJournal(
            versioned(
                snapshot = OperationSnapshot(
                    operationId = operationId,
                    type = OperationType.INSTALL,
                    target = OperationTarget.ServerTarget(serverId, accessId),
                    status = status,
                    checkpoint = OperationCheckpoint(
                        phaseName = when (semantics) {
                            CheckpointSemantics.MUTATION_NOT_STARTED -> "PREPARING"
                            CheckpointSemantics.MUTATION_IN_FLIGHT -> "INSTALLING"
                            CheckpointSemantics.POST_VERIFY_REQUIRED -> "VERIFYING"
                            CheckpointSemantics.COMMIT_VERIFIED -> "INSTALLER_COMMIT_VERIFIED"
                            else -> semantics.name
                        },
                        semantics = semantics,
                        recordedAt = startedAt,
                    ),
                    startedAt = startedAt,
                    updatedAt = startedAt,
                ),
                0,
            ),
        )
        private val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val runtimeLease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
        val admission = RecoveryRuntimeAdmission(
            plan = ColdStartRecoveryPlan(
                operationId = operationId,
                target = journal.current.snapshot.target,
                expectedRevision = journal.current.revision,
                action = if (semantics == CheckpointSemantics.MUTATION_NOT_STARTED) {
                    RecoveryAction.RECONNECT_EXACT_OWNER
                } else {
                    RecoveryAction.RECONCILE_READ_ONLY
                },
                automaticAllowed = true,
            ),
            runtimeLease = runtimeLease,
        )
        private val sessionRegistry = ExactSessionRegistry()
        val binding = SessionBinding(
            sessionId = SessionId("phase87-session"),
            serverAccessId = accessId,
            owner = SessionOwner.Operation(operationId),
        )
        private val handle = FakeHandle(binding)
        private val entryRegistry = InstallerRuntimeEntryRegistry()
        val serverMutationRegistry = ServerMutationLeaseRegistry()
        var mutationCalls = 0
        var postInstallCalls = 0
        var finishCommittedCalls = 0
        val coordinator: InstallerRuntimeCoordinator

        init {
            sessionRegistry.install(handle)
            val mutationPort = InstallerMutationExecutionPort { _, current, _ ->
                mutationCalls += 1
                val nextAt = now.plusSeconds(1)
                val next = current.snapshot.copy(
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint(
                        "VERIFYING",
                        CheckpointSemantics.POST_VERIFY_REQUIRED,
                        nextAt,
                    ),
                    updatedAt = nextAt,
                )
                val advanced = journal.advance(current.snapshot.operationId, current.revision, next)
                    as OperationJournalResult.Success
                InstallerSshExecutionResult.AwaitingVerification(
                    durable = advanced.value,
                    markerReadback = ManagedInstallMarkerReadbackState.MATCH,
                )
            }
            val postPort = object : InstallerPostInstallRuntimePort {
                override suspend fun reconcileAndPublish(
                    current: VersionedOperationSnapshot,
                    session: SshSessionHandle,
                ): InstallerPostInstallCoordinatorResult {
                    postInstallCalls += 1
                    return InstallerPostInstallCoordinatorResult.AwaitingWorker(current)
                }

                override suspend fun finishCommitted(
                    current: VersionedOperationSnapshot,
                ): InstallerPostInstallCoordinatorResult {
                    finishCommittedCalls += 1
                    return InstallerPostInstallCoordinatorResult.Succeeded(
                        current,
                        XuiInstallationId("xui-phase87"),
                    )
                }
            }
            coordinator = InstallerRuntimeCoordinator(
                journal = journal,
                runtimeRegistry = runtimeRegistry,
                sessionRegistry = sessionRegistry,
                serverMutationRegistry = serverMutationRegistry,
                entryRegistry = entryRegistry,
                mutationExecutor = mutationPort,
                postInstall = postPort,
                now = { now },
            )
        }

        fun registerFreshAuthority() {
            val verified = FreshInstallAuthorizationPolicy.verify(
                operation = journal.current.snapshot.copy(
                    checkpoint = OperationCheckpoint(
                        "PREPARING",
                        CheckpointSemantics.MUTATION_NOT_STARTED,
                        startedAt,
                    ),
                    updatedAt = startedAt,
                ),
                proof = FreshInstallPreflightProof(
                    id = TargetProofId("phase87-proof"),
                    scope = FreshInstallScope(operationId, serverId, accessId),
                    platform = DiscoveryPlatform("ubuntu", "24.04"),
                    installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                    privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
                    conflictState = FreshInstallConflictState.PROVEN_CLEAR,
                    observedAt = now.minusSeconds(30),
                    validUntil = now.plusSeconds(300),
                ),
                now = now,
            ) as FreshInstallVerificationResult.Verified
            assertEquals(
                InstallerRuntimeEntryRegistrationResult.Registered,
                coordinator.registerFreshAuthorization(verified.target),
            )
        }

        fun otherUnsafeOperation(): VersionedOperationSnapshot = versioned(
            OperationSnapshot(
                operationId = otherOperationId,
                type = OperationType.RESTART,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(
                    "OTHER_UNCERTAIN",
                    CheckpointSemantics.POST_VERIFY_REQUIRED,
                    startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            ),
            0,
        )
    }

    private class FakeJournal(
        initial: VersionedOperationSnapshot,
    ) : OperationJournal {
        var current = initial
        var nonTerminal: List<VersionedOperationSnapshot> = listOf(initial)

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.StorageFailure("not used")

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) {
                OperationJournalResult.Success(current)
            } else {
                OperationJournalResult.NotFound
            }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(
                nonTerminal.map { if (it.snapshot.operationId == current.snapshot.operationId) current else it },
            )

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) {
                return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            }
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }

    private class FakeHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        override val isOpen: Boolean = true

        override suspend fun execute(
            command: RemoteCommand,
            config: SshTransportConfig,
        ): SshCommandResult = SshCommandResult(
            dispatchState = CommandDispatchState.DISPATCHED,
            completion = CommandCompletion.ConfirmedSuccess,
            stdout = CapturedOutput.EMPTY,
            stderr = CapturedOutput.EMPTY,
        )

        override fun close() = Unit
    }

    companion object {
        private fun versioned(snapshot: OperationSnapshot, revision: Long) =
            VersionedOperationSnapshot(snapshot, OperationRevision(revision))
    }
}

private fun <T> runSuspend(block: suspend () -> T): T {
    var result: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(value: Result<T>) {
            result = value
        }
    })
    return result!!.getOrThrow()
}
