package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeSpec
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryResult
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
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeExecutor
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
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoveryRuntimeCoordinatorTest {
    @Test
    fun `canonical supported evidence commits one terminal Discovery result`() = runSuspend {
        val fixture = Fixture(OperationType.DISCOVERY)
        val result = fixture.coordinator.execute(fixture.admission, fixture.session.binding)

        assertTrue(result is DiscoveryRuntimeExecutionResult.Completed)
        val completed = result as DiscoveryRuntimeExecutionResult.Completed
        assertTrue(completed.result is DiscoveryResult.ProvenSupportedInstallation)
        assertEquals(OperationStatus.SUCCEEDED, fixture.journal.current.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals("DISCOVERY_RESULT_PROVEN_SUPPORTED", fixture.journal.current.snapshot.checkpoint.phaseName)
        assertEquals(OperationRevision(1), completed.committedRevision)
        assertEquals(DiscoveryProbePlan.initialProbes.size, fixture.session.executeCalls)
    }

    @Test
    fun `non Discovery operation consumes no probe and advances no journal`() = runSuspend {
        val fixture = Fixture(OperationType.QUICK_INSPECT)
        val result = fixture.coordinator.execute(fixture.admission, fixture.session.binding)

        assertEquals(
            DiscoveryRuntimeExecutionResult.NotDiscoveryOperation(OperationType.QUICK_INSPECT),
            result,
        )
        assertEquals(0, fixture.session.executeCalls)
        assertEquals(OperationRevision(0), fixture.journal.current.revision)
    }


    @Test
    fun `non Discovery installer post verify checkpoint is typed not applicable before Discovery checkpoint validation`() = runSuspend {
        val fixture = Fixture(
            type = OperationType.INSTALL,
            checkpointSemantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.session.binding)

        assertEquals(
            DiscoveryRuntimeExecutionResult.NotDiscoveryOperation(OperationType.INSTALL),
            result,
        )
        assertEquals(0, fixture.session.executeCalls)
        assertEquals(OperationRevision(0), fixture.journal.current.revision)
    }

    @Test
    fun `replacement exact session after probe discards result and never advances`() = runSuspend {
        val fixture = Fixture(OperationType.DISCOVERY)
        fixture.session.afterLastExecute = {
            fixture.sessions.install(
                ScriptedDiscoverySession(
                    binding = fixture.session.binding.copy(sessionId = SessionId("session-replacement")),
                ),
            )
        }

        val result = fixture.coordinator.execute(fixture.admission, fixture.session.binding)

        assertTrue(result is DiscoveryRuntimeExecutionResult.StaleSession)
        assertEquals(OperationRevision(0), fixture.journal.current.revision)
    }

    @Test
    fun `malformed platform evidence commits typed failed result without raw output`() = runSuspend {
        val fixture = Fixture(OperationType.DISCOVERY)
        fixture.session.platformStdout = byteArrayOf(0xC3.toByte(), 0x28)

        val result = fixture.coordinator.execute(fixture.admission, fixture.session.binding)

        assertTrue(result is DiscoveryRuntimeExecutionResult.Completed)
        val completed = result as DiscoveryRuntimeExecutionResult.Completed
        assertEquals(
            com.velumtegra.xuimobile.core.model.DiscoveryFailureKind.MALFORMED_PROBE_EVIDENCE,
            (completed.result as DiscoveryResult.Failed).failure,
        )
        assertEquals(OperationStatus.FAILED, fixture.journal.current.snapshot.status)
        assertEquals("DISCOVERY_RESULT_FAILED", fixture.journal.current.snapshot.checkpoint.phaseName)
    }

    private class Fixture(
        type: OperationType,
        checkpointSemantics: CheckpointSemantics = CheckpointSemantics.READ_ONLY,
    ) {
        val operationId = OperationId("op-discovery-runtime")
        val serverId = ServerId("server-discovery-runtime")
        val accessId = ServerAccessId("access-discovery-runtime")
        val startedAt: Instant = Instant.parse("2026-09-06T07:00:00Z")
        val journal = FakeJournal(
            VersionedOperationSnapshot(
                snapshot = OperationSnapshot(
                    operationId = operationId,
                    type = type,
                    target = OperationTarget.ServerTarget(serverId, accessId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("DISCOVER", checkpointSemantics, startedAt),
                    startedAt = startedAt,
                    updatedAt = startedAt,
                ),
                revision = OperationRevision(0),
            ),
        )
        val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
        val admission = RecoveryRuntimeAdmission(
            plan = ColdStartRecoveryPlan(
                operationId = operationId,
                target = OperationTarget.ServerTarget(serverId, accessId),
                expectedRevision = OperationRevision(0),
                action = RecoveryAction.RECONNECT_EXACT_OWNER,
                automaticAllowed = true,
            ),
            runtimeLease = lease,
        )
        val sessions = ExactSessionRegistry()
        val session = ScriptedDiscoverySession(
            SessionBinding(
                sessionId = SessionId("session-discovery-runtime"),
                owner = SessionOwner.Operation(operationId),
                serverAccessId = accessId,
            ),
        )
        val coordinator = DiscoveryRuntimeCoordinator(
            journal = journal,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessions,
            executor = DiscoverySshProbeExecutor(now = { Instant.parse("2026-09-06T07:00:01Z") }),
            now = { Instant.parse("2026-09-06T07:00:02Z") },
            proofIdFactory = { DiscoveryProofId("proof-discovery-runtime") },
        )

        init {
            sessions.install(session)
        }
    }

    private class ScriptedDiscoverySession(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        override var isOpen: Boolean = true
        var executeCalls: Int = 0
        var platformStdout: ByteArray = "ID=ubuntu\nVERSION_ID=24.04\n".toByteArray()
        var afterLastExecute: (() -> Unit)? = null

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            val probe = DiscoveryProbePlan.initialProbes[executeCalls++]
            val result = when (probe) {
                is DiscoveryProbeSpec.PlatformRelease -> success(platformStdout)
                is DiscoveryProbeSpec.ServiceUnitPresence -> presence(probe.serviceUnit == "x-ui.service")
                is DiscoveryProbeSpec.InstallationPathPresence -> presence(
                    when (probe.pathKind) {
                        DiscoveryPathKind.BINARY -> probe.path == "/usr/local/x-ui/x-ui"
                        DiscoveryPathKind.ROOT -> probe.path == "/usr/local/x-ui"
                        DiscoveryPathKind.DATABASE -> probe.path == "/etc/x-ui/x-ui.db"
                    },
                )
                is DiscoveryProbeSpec.ForeignPanelPathMarker -> presence(false)
            }
            if (executeCalls == DiscoveryProbePlan.initialProbes.size) afterLastExecute?.invoke()
            return result
        }

        override fun close() {
            isOpen = false
        }

        private fun success(stdout: ByteArray = ByteArray(0)) = SshCommandResult(
            dispatchState = CommandDispatchState.DISPATCHED,
            completion = CommandCompletion.ConfirmedSuccess,
            stdout = CapturedOutput.of(stdout, truncated = false),
            stderr = CapturedOutput.EMPTY,
        )

        private fun presence(present: Boolean): SshCommandResult = if (present) {
            success()
        } else {
            SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = CommandCompletion.ConfirmedFailure("absent", exitCode = 1),
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )
        }
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current: VersionedOperationSnapshot = initial

        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.AlreadyExists
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current)
            else OperationJournalResult.NotFound

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(listOf(current))

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            if (expectedRevision != current.revision) {
                return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            }
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext
            override fun resumeWith(result: Result<T>) {
                outcome = result
            }
        })
        return checkNotNull(outcome).getOrThrow()
    }
}
