package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
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
import com.velumtegra.xuimobile.core.ssh.CapturedOutput
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class FeatureReconciliationCoordinatorTest {
    @Test
    fun `exact complete verified evidence is accepted and journal is never advanced`() = runSuspend {
        val fixture = Fixture()
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(request.evidence(FeatureReconciliationVerdict.VERIFIED))
        }

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.EvidenceAccepted

        assertEquals(FeatureReconciliationVerdict.VERIFIED, result.evidence.verdict)
        assertEquals(fixture.current, fixture.port.requests.single().current)
        assertEquals(fixture.binding, fixture.port.requests.single().sessionBinding)
        assertEquals(2, fixture.journal.getCalls)
        assertEquals(0, fixture.journal.advanceCalls)
        assertEquals(0, fixture.handle.executeCalls)
    }

    @Test
    fun `non reconciliation plan never calls feature port`() = runSuspend {
        val fixture = Fixture(action = RecoveryAction.RECONNECT_EXACT_OWNER)

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)

        assertEquals(
            FeatureReconciliationResult.NotReconciliationPlan(RecoveryAction.RECONNECT_EXACT_OWNER),
            result,
        )
        assertEquals(0, fixture.port.requests.size)
        assertEquals(0, fixture.journal.getCalls)
    }

    @Test
    fun `released admission cannot enter feature reconciliation`() = runSuspend {
        val fixture = Fixture()
        fixture.runtimeRegistry.release(fixture.admission.runtimeLease)

        assertEquals(
            FeatureReconciliationResult.AdmissionLost,
            fixture.coordinator.reconcile(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.port.requests.size)
    }

    @Test
    fun `caller binding for another owner is rejected before port`() = runSuspend {
        val fixture = Fixture()
        val wrong = fixture.binding.copy(owner = SessionOwner.Operation(OperationId("other-op")))

        val result = fixture.coordinator.reconcile(fixture.admission, wrong)

        assertTrue(result is FeatureReconciliationResult.ContractViolation)
        assertEquals(0, fixture.port.requests.size)
    }

    @Test
    fun `missing exact live session prevents feature reconciliation`() = runSuspend {
        val fixture = Fixture(installSession = false)

        assertEquals(
            FeatureReconciliationResult.SessionUnavailable,
            fixture.coordinator.reconcile(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.port.requests.size)
    }

    @Test
    fun `replacement exact session makes old binding stale`() = runSuspend {
        val fixture = Fixture()
        val replacement = fixture.handle("replacement")
        fixture.sessions.install(replacement)

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.StaleSession

        assertEquals(fixture.binding.sessionId, result.expectedSessionId)
        assertEquals(replacement.binding.sessionId, result.actualSessionId)
        assertEquals(0, fixture.port.requests.size)
    }

    @Test
    fun `durable revision changed before probe requires fresh replan and skips port`() = runSuspend {
        val fixture = Fixture()
        fixture.journal.current = fixture.versioned(revision = 4L)

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.StalePlan

        assertEquals(OperationRevision(3), result.expectedRevision)
        assertEquals(OperationRevision(4), result.actualRevision)
        assertEquals(0, fixture.port.requests.size)
    }

    @Test
    fun `changed durable target fails corruption closed`() = runSuspend {
        val fixture = Fixture()
        fixture.journal.current = fixture.current.copy(
            snapshot = fixture.current.snapshot.copy(
                target = OperationTarget.ServerTarget(
                    serverId = fixture.current.snapshot.target.serverId,
                    serverAccessId = ServerAccessId("different-access"),
                ),
            ),
        )

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, result.failure.kind)
        assertEquals(0, fixture.port.requests.size)
    }

    @Test
    fun `admission lost while feature probes discards returned evidence`() = runSuspend {
        val fixture = Fixture()
        fixture.port.onReconcile = { fixture.runtimeRegistry.release(fixture.admission.runtimeLease) }
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(request.evidence(FeatureReconciliationVerdict.VERIFIED))
        }

        assertEquals(
            FeatureReconciliationResult.AdmissionLost,
            fixture.coordinator.reconcile(fixture.admission, fixture.binding),
        )
    }

    @Test
    fun `session replaced while feature probes discards returned evidence`() = runSuspend {
        val fixture = Fixture()
        val replacement = fixture.handle("replacement-during-probe")
        fixture.port.onReconcile = { fixture.sessions.install(replacement) }
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(request.evidence(FeatureReconciliationVerdict.VERIFIED))
        }

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.StaleSession

        assertEquals(replacement.binding.sessionId, result.actualSessionId)
    }

    @Test
    fun `durable revision advancing while feature probes discards evidence and requires replan`() = runSuspend {
        val fixture = Fixture()
        fixture.port.onReconcile = { fixture.journal.current = fixture.versioned(revision = 5L) }
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(request.evidence(FeatureReconciliationVerdict.VERIFIED))
        }

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.StalePlan

        assertEquals(OperationRevision(3), result.expectedRevision)
        assertEquals(OperationRevision(5), result.actualRevision)
    }

    @Test
    fun `feature evidence for another revision is rejected as contract violation`() = runSuspend {
        val fixture = Fixture()
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(
                request.evidence(FeatureReconciliationVerdict.UNVERIFIED).copy(
                    observedRevision = OperationRevision(request.current.revision.value + 1),
                ),
            )
        }

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)

        assertTrue(result is FeatureReconciliationResult.ContractViolation)
    }

    @Test
    fun `feature evidence through another exact session is rejected`() = runSuspend {
        val fixture = Fixture()
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(
                request.evidence(FeatureReconciliationVerdict.UNVERIFIED).copy(
                    sessionBinding = request.sessionBinding.copy(sessionId = SessionId("wrong-session")),
                ),
            )
        }

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)

        assertTrue(result is FeatureReconciliationResult.ContractViolation)
    }

    @Test
    fun `truncated or ambiguous evidence cannot claim verified or contradicted`() {
        for (verdict in listOf(FeatureReconciliationVerdict.VERIFIED, FeatureReconciliationVerdict.CONTRADICTED)) {
            for (completeness in listOf(
                FeatureReconciliationCompleteness.TRUNCATED,
                FeatureReconciliationCompleteness.AMBIGUOUS,
            )) {
                try {
                    Fixture().evidence(verdict, completeness)
                    fail("$verdict with $completeness must be rejected")
                } catch (_: IllegalArgumentException) {
                    // expected
                }
            }
        }
    }

    @Test
    fun `incomplete observations remain representable only as unverified evidence`() = runSuspend {
        val fixture = Fixture()
        fixture.port.resultFactory = { request ->
            FeatureReconciliationPortResult.Evidence(
                request.evidence(
                    FeatureReconciliationVerdict.UNVERIFIED,
                    FeatureReconciliationCompleteness.TRUNCATED,
                ),
            )
        }

        val accepted = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.EvidenceAccepted

        assertEquals(FeatureReconciliationVerdict.UNVERIFIED, accepted.evidence.verdict)
        assertEquals(FeatureReconciliationCompleteness.TRUNCATED, accepted.evidence.completeness)
    }

    @Test
    fun `unsupported feature is surfaced without changing durable state`() = runSuspend {
        val fixture = Fixture()
        fixture.port.resultFactory = { FeatureReconciliationPortResult.Unsupported }

        assertEquals(
            FeatureReconciliationResult.Unsupported(OperationType.RECOVERY),
            fixture.coordinator.reconcile(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.journal.advanceCalls)
    }

    @Test
    fun `feature failure is typed and does not mutate durable state`() = runSuspend {
        val fixture = Fixture()
        fixture.port.resultFactory = { FeatureReconciliationPortResult.Failed("probe unavailable") }

        assertEquals(
            FeatureReconciliationResult.PortFailed("probe unavailable"),
            fixture.coordinator.reconcile(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.journal.advanceCalls)
    }

    @Test
    fun `terminal durable state at planned revision is rejected before feature port`() = runSuspend {
        val fixture = Fixture()
        fixture.journal.current = fixture.versioned(
            revision = 3L,
            status = OperationStatus.SUCCEEDED,
            semantics = CheckpointSemantics.TERMINAL,
        )

        val result = fixture.coordinator.reconcile(fixture.admission, fixture.binding)
            as FeatureReconciliationResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, result.failure.kind)
        assertEquals(0, fixture.port.requests.size)
    }

    private class Fixture(
        action: RecoveryAction = RecoveryAction.RECONCILE_READ_ONLY,
        installSession: Boolean = true,
    ) {
        val operationId = OperationId("op-reconcile")
        val accessId = ServerAccessId("access-reconcile")
        val current = versioned(revision = 3L)
        val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
        val admission = RecoveryRuntimeAdmission(
            plan = ColdStartRecoveryPlan(
                operationId = operationId,
                target = current.snapshot.target,
                expectedRevision = current.revision,
                action = action,
                automaticAllowed = true,
            ),
            runtimeLease = lease,
        )
        val sessions = ExactSessionRegistry()
        val handle = handle("session-current")
        val binding: SessionBinding = handle.binding
        val journal = FakeJournal(current)
        val port = FakePort()
        val coordinator = FeatureReconciliationCoordinator(journal, runtimeRegistry, sessions, port)

        init {
            if (installSession) sessions.install(handle)
        }

        fun handle(session: String): FakeHandle = FakeHandle(
            SessionBinding(
                sessionId = SessionId(session),
                serverAccessId = accessId,
                owner = SessionOwner.Operation(operationId),
            ),
        )

        fun versioned(
            revision: Long,
            status: OperationStatus = OperationStatus.RECONCILIATION_REQUIRED,
            semantics: CheckpointSemantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
        ): VersionedOperationSnapshot {
            val updated = now.plusSeconds(revision)
            return VersionedOperationSnapshot(
                snapshot = OperationSnapshot(
                    operationId = operationId,
                    type = OperationType.RECOVERY,
                    target = OperationTarget.ServerTarget(
                        serverId = ServerId("server-reconcile"),
                        serverAccessId = accessId,
                    ),
                    status = status,
                    checkpoint = OperationCheckpoint(
                        phaseName = "reconcile-$revision",
                        semantics = semantics,
                        recordedAt = updated,
                    ),
                    startedAt = now,
                    updatedAt = updated,
                ),
                revision = OperationRevision(revision),
            )
        }

        fun evidence(
            verdict: FeatureReconciliationVerdict,
            completeness: FeatureReconciliationCompleteness = FeatureReconciliationCompleteness.COMPLETE,
        ): FeatureReconciliationEvidence = FeatureReconciliationEvidence(
            operationId = operationId,
            target = current.snapshot.target,
            observedRevision = current.revision,
            sessionBinding = binding,
            verdict = verdict,
            completeness = completeness,
        )
    }

    private class FakePort : FeatureReconciliationPort {
        val requests = mutableListOf<FeatureReconciliationRequest>()
        var onReconcile: (FeatureReconciliationRequest) -> Unit = {}
        var resultFactory: (FeatureReconciliationRequest) -> FeatureReconciliationPortResult = { request ->
            FeatureReconciliationPortResult.Evidence(request.evidence(FeatureReconciliationVerdict.UNVERIFIED))
        }

        override suspend fun reconcile(request: FeatureReconciliationRequest): FeatureReconciliationPortResult {
            requests += request
            onReconcile(request)
            return resultFactory(request)
        }

        private fun FeatureReconciliationRequest.evidence(
            verdict: FeatureReconciliationVerdict,
        ): FeatureReconciliationEvidence = FeatureReconciliationEvidence(
            operationId = current.snapshot.operationId,
            target = current.snapshot.target,
            observedRevision = current.revision,
            sessionBinding = sessionBinding,
            verdict = verdict,
            completeness = FeatureReconciliationCompleteness.COMPLETE,
        )
    }

    private class FakeJournal(
        var current: VersionedOperationSnapshot,
    ) : OperationJournal {
        var getCalls: Int = 0
        var advanceCalls: Int = 0

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.StorageFailure("not used")

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> {
            getCalls += 1
            return OperationJournalResult.Success(current)
        }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.StorageFailure("not used")

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCalls += 1
            return OperationJournalResult.StorageFailure("must not be called by reconciliation boundary")
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.StorageFailure("not used")
    }

    private class FakeHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        var closed = false
        var executeCalls = 0

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executeCalls += 1
            return SshCommandResult(
                dispatchState = CommandDispatchState.NOT_DISPATCHED,
                completion = CommandCompletion.ConfirmedSuccess,
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )
        }

        override fun close() {
            closed = true
        }
    }

    private fun FeatureReconciliationRequest.evidence(
        verdict: FeatureReconciliationVerdict,
        completeness: FeatureReconciliationCompleteness = FeatureReconciliationCompleteness.COMPLETE,
    ): FeatureReconciliationEvidence = FeatureReconciliationEvidence(
        operationId = current.snapshot.operationId,
        target = current.snapshot.target,
        observedRevision = current.revision,
        sessionBinding = sessionBinding,
        verdict = verdict,
        completeness = completeness,
    )

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

    private companion object {
        val now: Instant = Instant.parse("2026-01-01T00:00:00Z")
    }
}
