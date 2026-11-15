package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.ssh.CapturedOutput
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Test

class OperationRuntimeCoordinatorTest {
    @Test
    fun `maintenance lease shares the existing same server gate without connecting`() = runSuspend {
        val fixture = Fixture()
        val result = fixture.coordinator.withExclusiveServerMaintenanceLease(fixture.serverId, fixture.operationId) {
            assertEquals(null, fixture.coordinator.withRecoveryPanelReadLease(fixture.serverId, OperationId("other")) { true })
            assertEquals(true, fixture.coordinator.withRecoveryPanelReadLease(ServerId("other-server"), OperationId("other")) { true })
            true
        }
        assertEquals(true, result)
        assertEquals(true, fixture.coordinator.withRecoveryPanelReadLease(fixture.serverId, fixture.operationId) { true })
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `maintenance failure releases only its own process lease and cannot authorize network`() = runSuspend {
        val fixture = Fixture()
        try {
            fixture.coordinator.withExclusiveServerMaintenanceLease<Boolean>(fixture.serverId, fixture.operationId) { throw IllegalStateException("fixture") }
            error("expected failure")
        } catch (_: IllegalStateException) { }
        assertEquals(true, fixture.coordinator.withRecoveryPanelReadLease(fixture.serverId, fixture.operationId) { true })
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `one coordinator serializes duplicate admission through one exact runtime registry`() = runSuspend {
        val fixture = Fixture()
        val plan = fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER)

        val first = fixture.coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted
        assertEquals(
            RecoveryAdmissionResult.AlreadyOwned,
            fixture.coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC),
        )

        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(first.admission))
        val replacement = fixture.coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(replacement.admission))
    }

    @Test
    fun `stale cleanup through coordinator cannot release replacement admission`() = runSuspend {
        val fixture = Fixture()
        val plan = fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER)

        val first = (fixture.coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted).admission
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(first))

        val replacement = (fixture.coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted).admission
        assertEquals(
            OperationRuntimeReleaseResult.STALE_OR_ALREADY_RELEASED,
            fixture.coordinator.release(first),
        )
        assertEquals(
            RecoveryAdmissionResult.AlreadyOwned,
            fixture.coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC),
        )
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(replacement))
    }

    @Test
    fun `shared connectivity generation invalidates stale observation before reconnect`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission

        val stale = fixture.coordinator.observeConnectivity(ConnectivityState.UNKNOWN)
        fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE)

        assertEquals(
            ExactReconnectResult.StaleConnectivityGeneration,
            fixture.coordinator.beginReconnect(admission, stale, RetryBudget(maxAttempts = 1)),
        )
        assertEquals(0, fixture.factory.connectCalls)
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    @Test
    fun `reconnect publication and reconciliation share the same exact session registry`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONCILE_READ_ONLY),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission
        val observation = fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE)

        val connected = fixture.coordinator.beginReconnect(
            admission = admission,
            observation = observation,
            budget = RetryBudget(maxAttempts = 1),
        ) as ExactReconnectResult.Connected

        val reconciliation = fixture.coordinator.reconcile(admission, connected.binding)
            as FeatureReconciliationResult.EvidenceAccepted

        assertEquals(connected.binding, reconciliation.evidence.sessionBinding)
        assertEquals(FeatureReconciliationVerdict.UNVERIFIED, reconciliation.evidence.verdict)
        assertEquals(1, fixture.port.requests)
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    @Test
    fun `exact session cleanup closes only admitted operation session`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission
        val observation = fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE)
        val connected = fixture.coordinator.beginReconnect(
            admission,
            observation,
            RetryBudget(maxAttempts = 1),
        ) as ExactReconnectResult.Connected

        assertEquals(
            ExactRuntimeSessionCloseResult.Closed,
            fixture.coordinator.closeExactSession(admission, connected.binding),
        )
        assertEquals(0, fixture.sessions.size())
        assertEquals(
            ExactRuntimeSessionCloseResult.StaleOrAlreadyClosed,
            fixture.coordinator.closeExactSession(admission, connected.binding),
        )
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    @Test
    fun `exact session cleanup remains safe after runtime admission release`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission
        val connected = fixture.coordinator.beginReconnect(
            admission,
            fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE),
            RetryBudget(maxAttempts = 1),
        ) as ExactReconnectResult.Connected

        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
        assertEquals(
            ExactRuntimeSessionCloseResult.Closed,
            fixture.coordinator.closeExactSession(admission, connected.binding),
        )
        assertEquals(0, fixture.sessions.size())
    }

    @Test
    fun `stale exact session cleanup cannot remove replacement session`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission

        val first = fixture.coordinator.beginReconnect(
            admission,
            fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE),
            RetryBudget(maxAttempts = 1),
        ) as ExactReconnectResult.Connected
        val replacement = fixture.coordinator.beginReconnect(
            admission,
            fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE),
            RetryBudget(maxAttempts = 1),
        ) as ExactReconnectResult.Connected

        assertEquals(1, fixture.sessions.size())
        assertEquals(
            ExactRuntimeSessionCloseResult.StaleOrAlreadyClosed,
            fixture.coordinator.closeExactSession(admission, first.binding),
        )
        assertEquals(1, fixture.sessions.size())
        assertEquals(
            ExactRuntimeSessionCloseResult.Closed,
            fixture.coordinator.closeExactSession(admission, replacement.binding),
        )
        assertEquals(0, fixture.sessions.size())
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    @Test
    fun `session cleanup rejects different operation owner without touching registry`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission

        val result = fixture.coordinator.closeExactSession(
            admission,
            SessionBinding(
                sessionId = SessionId("foreign-session"),
                serverAccessId = fixture.accessId,
                owner = SessionOwner.Operation(OperationId("other-operation")),
            ),
        )

        assertEquals(
            ExactRuntimeSessionCloseResult.ContractViolation(
                "Session cleanup binding belongs to a different operation owner",
            ),
            result,
        )
        assertEquals(0, fixture.sessions.size())
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    @Test
    fun `session cleanup rejects different access without touching registry`() = runSuspend {
        val fixture = Fixture()
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONNECT_EXACT_OWNER),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission

        val result = fixture.coordinator.closeExactSession(
            admission,
            SessionBinding(
                sessionId = SessionId("foreign-access-session"),
                serverAccessId = ServerAccessId("other-access"),
                owner = SessionOwner.Operation(fixture.operationId),
            ),
        )

        assertEquals(
            ExactRuntimeSessionCloseResult.ContractViolation(
                "Session cleanup binding uses a different ServerAccessId than the admitted target",
            ),
            result,
        )
        assertEquals(0, fixture.sessions.size())
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    @Test
    fun `bootstrap planning through coordinator remains journal first and lease free`() = runSuspend {
        val fixture = Fixture()
        fixture.journal.nonTerminal = listOf(fixture.current)
        fixture.journal.history = listOf(fixture.entryForCurrent())

        val bootstrap = fixture.coordinator.bootstrapRecovery(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Success
        val planned = (bootstrap.items.single() as RecoveryBootstrapItem.Planned).plan

        assertEquals(fixture.current.snapshot.operationId, planned.operationId)
        assertEquals(fixture.current.revision, planned.expectedRevision)

        // Planning alone must not occupy the process-local runtime lease.
        val admitted = fixture.coordinator.admitRecovery(planned, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admitted.admission))
    }

    @Test
    fun `default unsupported reconciliation port is fail closed`() = runSuspend {
        val fixture = Fixture(useDefaultPort = true)
        val admission = (fixture.coordinator.admitRecovery(
            fixture.plan(RecoveryAction.RECONCILE_READ_ONLY),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted).admission
        val observation = fixture.coordinator.observeConnectivity(ConnectivityState.ONLINE)
        val connected = fixture.coordinator.beginReconnect(
            admission,
            observation,
            RetryBudget(maxAttempts = 1),
        ) as ExactReconnectResult.Connected

        assertEquals(
            FeatureReconciliationResult.Unsupported(OperationType.RECOVERY),
            fixture.coordinator.reconcile(admission, connected.binding),
        )
        assertEquals(OperationRuntimeReleaseResult.RELEASED, fixture.coordinator.release(admission))
    }

    private class Fixture(
        useDefaultPort: Boolean = false,
    ) {
        val operationId = OperationId("op-coordinator")
        val serverId = ServerId("server-coordinator")
        val accessId = ServerAccessId("access-coordinator")
        val now = Instant.parse("2026-09-02T00:00:00Z")
        val current = VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = operationId,
                type = OperationType.RECOVERY,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(
                    phaseName = "post-verify",
                    semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                    recordedAt = now,
                ),
                startedAt = now,
                updatedAt = now,
            ),
            revision = OperationRevision(0),
        )
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("127.0.0.1", 22),
            username = "velum",
            auth = SshAuthRef.Password(SecretId("secret-coordinator")),
            pinnedHostKey = HostKeyFingerprint("SHA256:coordinator"),
        )
        val journal = FakeJournal(current)
        val accessRepository = FakeAccessRepository(access)
        val factory = FakeConnectionFactory(accessId)
        val sessions = ExactSessionRegistry()
        val port = FakeReconciliationPort()
        val coordinator = if (useDefaultPort) {
            OperationRuntimeCoordinator(
                journal = journal,
                accessRepository = accessRepository,
                connectionFactory = factory,
                sessionRegistry = sessions,
            )
        } else {
            OperationRuntimeCoordinator(
                journal = journal,
                accessRepository = accessRepository,
                connectionFactory = factory,
                sessionRegistry = sessions,
                featureReconciliationPort = port,
            )
        }

        fun plan(action: RecoveryAction): ColdStartRecoveryPlan = ColdStartRecoveryPlan(
            operationId = operationId,
            target = current.snapshot.target,
            expectedRevision = current.revision,
            action = action,
            automaticAllowed = true,
        )

        fun entryForCurrent(): OperationJournalEntry = OperationJournalEntry(
            operationId = operationId,
            revision = current.revision,
            status = current.snapshot.status,
            checkpoint = current.snapshot.checkpoint,
            recordedAt = current.snapshot.updatedAt,
        )
    }

    private class FakeJournal(
        var current: VersionedOperationSnapshot,
    ) : OperationJournal {
        var nonTerminal: List<VersionedOperationSnapshot> = emptyList()
        var history: List<OperationJournalEntry> = emptyList()

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.StorageFailure("not used")

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.Success(current)

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(nonTerminal)

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.StorageFailure("must not be called by coordinator boundary")

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(history)
    }

    private class FakeAccessRepository(
        private val access: ServerAccess,
    ) : ServerAccessRepository {
        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
            if (serverAccessId == access.id) RepositoryResult.Success(access) else RepositoryResult.NotFound

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> =
            RepositoryResult.StorageFailure("not used")

        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> =
            RepositoryResult.StorageFailure("not used")
    }

    private class FakeConnectionFactory(
        private val accessId: ServerAccessId,
    ) : SshConnectionFactory {
        var connectCalls = 0

        override suspend fun connect(
            access: ServerAccess,
            owner: SessionOwner,
            config: SshTransportConfig,
        ): SshConnectResult {
            connectCalls += 1
            assertEquals(accessId, access.id)
            return SshConnectResult.Connected(
                FakeHandle(
                    SessionBinding(
                        sessionId = SessionId("session-$connectCalls"),
                        serverAccessId = access.id,
                        owner = owner,
                    ),
                ),
            )
        }
    }

    private class FakeReconciliationPort : FeatureReconciliationPort {
        var requests = 0

        override suspend fun reconcile(request: FeatureReconciliationRequest): FeatureReconciliationPortResult {
            requests += 1
            return FeatureReconciliationPortResult.Evidence(
                FeatureReconciliationEvidence(
                    operationId = request.current.snapshot.operationId,
                    target = request.current.snapshot.target,
                    observedRevision = request.current.revision,
                    sessionBinding = request.sessionBinding,
                    verdict = FeatureReconciliationVerdict.UNVERIFIED,
                    completeness = FeatureReconciliationCompleteness.COMPLETE,
                ),
            )
        }
    }

    private class FakeHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        private var closed = false

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult =
            SshCommandResult(
                dispatchState = CommandDispatchState.NOT_DISPATCHED,
                completion = CommandCompletion.ConfirmedSuccess,
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )

        override fun close() {
            closed = true
        }
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(
            object : Continuation<T> {
                override val context = EmptyCoroutineContext
                override fun resumeWith(result: Result<T>) {
                    outcome = result
                }
            },
        )
        return requireNotNull(outcome) { "Test coroutine did not complete synchronously" }.getOrThrow()
    }
}
