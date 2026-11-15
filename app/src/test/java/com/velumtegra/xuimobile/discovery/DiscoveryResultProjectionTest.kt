package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DiscoveryFailureKind
import com.velumtegra.xuimobile.core.model.DiscoveryResult
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.DiscoveryTerminalKind
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequenceResult
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoveryResultProjectionTest {
    private val operationId = OperationId("projection-op")
    private val serverId = ServerId("projection-server")
    private val accessId = ServerAccessId("projection-access")
    private val startedAt = Instant.parse("2026-09-06T08:30:00Z")
    private val completedAt = startedAt.plusSeconds(5)

    @Test
    fun `matching process local result is projected only after durable terminal agreement`() = runSuspend {
        val journal = FakeJournal(terminal(DiscoveryTerminalKind.NO_SUPPORTED_INSTALLATION))
        val registry = DiscoveryResultRegistry()
        registry.beginAttempt(operationId)
        val result = DiscoveryResult.NoSupportedInstallation(scope(), completedAt)
        registry.publishResult(result)

        assertEquals(
            DiscoveryReadResult.Detailed(result),
            DiscoveryResultProjector(journal, registry).read(operationId),
        )
    }

    @Test
    fun `process death fallback reconstructs only durable terminal category and never proof detail`() = runSuspend {
        val journal = FakeJournal(terminal(DiscoveryTerminalKind.PROVEN_SUPPORTED))
        val registry = DiscoveryResultRegistry()

        assertEquals(
            DiscoveryReadResult.DurableTerminal(
                DiscoveryTerminalSummary(
                    scope = scope(),
                    kind = DiscoveryTerminalKind.PROVEN_SUPPORTED,
                    completedAt = completedAt,
                ),
            ),
            DiscoveryResultProjector(journal, registry).read(operationId),
        )
    }

    @Test
    fun `detailed result with mismatched completion time fails closed`() = runSuspend {
        val journal = FakeJournal(terminal(DiscoveryTerminalKind.NO_SUPPORTED_INSTALLATION))
        val registry = DiscoveryResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishResult(
            DiscoveryResult.NoSupportedInstallation(scope(), completedAt.plusSeconds(1)),
        )

        assertTrue(
            DiscoveryResultProjector(journal, registry).read(operationId) is
                DiscoveryReadResult.ContractViolation,
        )
    }

    @Test
    fun `nonterminal durable state may expose only safe process notice`() = runSuspend {
        val journal = FakeJournal(nonTerminal())
        val registry = DiscoveryResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishNotice(
            operationId,
            DiscoveryProcessNotice.Failure(DiscoveryFailureKind.AUTHENTICATION_REJECTED),
        )

        assertEquals(
            DiscoveryReadResult.InProgress(
                scope = scope(),
                status = OperationStatus.RUNNING,
                phaseName = "DISCOVER",
                processNotice = DiscoveryProcessNotice.Failure(
                    DiscoveryFailureKind.AUTHENTICATION_REJECTED,
                ),
            ),
            DiscoveryResultProjector(journal, registry).read(operationId),
        )
    }

    @Test
    fun `untracked host notice or detail cannot enter process projection registry`() {
        val registry = DiscoveryResultRegistry()
        registry.publishNotice(operationId, DiscoveryProcessNotice.WaitingForNetwork)
        registry.publishResult(DiscoveryResult.NoSupportedInstallation(scope(), completedAt))

        assertNull(registry.latestNotice(operationId))
        assertNull(registry.latestResult(operationId))
    }

    @Test
    fun `unknown terminal phase is never guessed`() = runSuspend {
        val bad = terminal(DiscoveryTerminalKind.NO_SUPPORTED_INSTALLATION).copy(
            snapshot = terminal(DiscoveryTerminalKind.NO_SUPPORTED_INSTALLATION).snapshot.copy(
                checkpoint = OperationCheckpoint(
                    phaseName = "DISCOVERY_RESULT_FUTURE_UNKNOWN",
                    semantics = CheckpointSemantics.TERMINAL,
                    recordedAt = completedAt,
                ),
            ),
        )

        assertTrue(
            DiscoveryResultProjector(FakeJournal(bad), DiscoveryResultRegistry()).read(operationId) is
                DiscoveryReadResult.ContractViolation,
        )
    }

    @Test
    fun `host outcome mapping exposes only safe enum categories`() {
        assertEquals(
            DiscoveryProcessNotice.WaitingForNetwork,
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.WaitForNetwork,
            ).toDiscoveryProcessNotice(),
        )
        assertEquals(
            DiscoveryProcessNotice.Failure(DiscoveryFailureKind.EXACT_ACCESS_UNAVAILABLE),
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.RecoveryBlocked(
                    reason = RecoveryBlockReason.EXACT_ACCESS_MISSING,
                ),
            ).toDiscoveryProcessNotice(),
        )
        assertEquals(
            DiscoveryProcessNotice.Failure(DiscoveryFailureKind.INTERNAL_INVARIANT_FAILURE),
            ExactOperationHostRuntimeBindResult.ContractViolation(
                "RAW_REASON_THAT_MUST_NOT_CROSS_PROJECTION",
            ).toDiscoveryProcessNotice(),
        )
    }

    private fun scope() = DiscoveryScope(operationId, serverId, accessId)

    private fun nonTerminal() = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.DISCOVERY,
            target = OperationTarget.ServerTarget(serverId, accessId),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint("DISCOVER", CheckpointSemantics.READ_ONLY, startedAt),
            startedAt = startedAt,
            updatedAt = startedAt,
        ),
        revision = OperationRevision(0),
    )

    private fun terminal(kind: DiscoveryTerminalKind) = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.DISCOVERY,
            target = OperationTarget.ServerTarget(serverId, accessId),
            status = kind.operationStatus,
            checkpoint = OperationCheckpoint(
                phaseName = kind.phaseName,
                semantics = CheckpointSemantics.TERMINAL,
                recordedAt = completedAt,
            ),
            startedAt = startedAt,
            updatedAt = completedAt,
        ),
        revision = OperationRevision(1),
    )

    private class FakeJournal(
        private val current: VersionedOperationSnapshot,
    ) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.AlreadyExists

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (current.snapshot.operationId == operationId) {
                OperationJournalResult.Success(current)
            } else {
                OperationJournalResult.NotFound
            }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(emptyList())

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> = OperationJournalResult.NotFound

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
