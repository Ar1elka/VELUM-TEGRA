package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationStaleCasReloadGateTest {
    private val now = Instant.parse("2026-09-02T00:00:00Z")

    @Test
    fun `stale conflict reloads exact latest durable revision for replan`() = runSuspend {
        val current = versioned("op-reload", revision = 4L)
        val journal = FakeJournal(current = current, history = historyFor(current))
        val gate = OperationStaleCasReloadGate(journal)

        val result = gate.reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.ReplanRequired

        assertEquals(OperationRevision(4), result.context.current.revision)
        assertEquals(current.snapshot.target, result.context.current.snapshot.target)
        assertEquals(1, journal.getCalls)
        assertEquals(1, journal.historyCalls)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `reload accepts a newer revision than the one first reported by stale CAS`() = runSuspend {
        val current = versioned("op-moved-again", revision = 6L)
        val journal = FakeJournal(current = current, history = historyFor(current))

        val result = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.ReplanRequired

        assertEquals(OperationRevision(6), result.context.current.revision)
        assertEquals(OperationRevision(4), result.context.staleConflict.observedActualRevision)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `stale result with a different attempted expected revision is rejected before reload`() {
        val current = versioned("op-bad-stale", revision = 4L)
        val conflict = StaleCasConflict.from(
            operationId = current.snapshot.operationId,
            target = current.snapshot.target,
            attemptedExpectedRevision = OperationRevision(3),
            stale = OperationJournalResult.StaleRevision(
                expected = OperationRevision(2),
                actual = OperationRevision(4),
            ),
        )

        assertNull(conflict)
    }

    @Test
    fun `non advancing stale result is rejected before reload`() {
        val current = versioned("op-invalid-stale", revision = 4L)
        val conflict = StaleCasConflict.from(
            operationId = current.snapshot.operationId,
            target = current.snapshot.target,
            attemptedExpectedRevision = OperationRevision(4),
            stale = OperationJournalResult.StaleRevision(
                expected = OperationRevision(4),
                actual = OperationRevision(4),
            ),
        )

        assertNull(conflict)
    }

    @Test
    fun `journal moving backward below already observed actual revision fails contract closed`() = runSuspend {
        val current = versioned("op-backward", revision = 4L)
        val journal = FakeJournal(current = current, history = historyFor(current))
        val conflict = StaleCasConflict(
            operationId = current.snapshot.operationId,
            target = current.snapshot.target,
            attemptedExpectedRevision = OperationRevision(3),
            observedActualRevision = OperationRevision(5),
        )

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(conflict)
            as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, failed.failure.kind)
        assertEquals(0, journal.historyCalls)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `different exact target fails as corruption and cannot replan`() = runSuspend {
        val planned = versioned("op-target", revision = 4L)
        val changed = planned.copy(
            snapshot = planned.snapshot.copy(
                target = OperationTarget.ServerTarget(
                    serverId = planned.snapshot.target.serverId,
                    serverAccessId = ServerAccessId("access-replaced"),
                ),
            ),
        )
        val journal = FakeJournal(current = changed, history = historyFor(changed))

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(planned, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, failed.failure.kind)
        assertEquals(0, journal.historyCalls)
    }

    @Test
    fun `different operation id from exact lookup fails as corruption`() = runSuspend {
        val planned = versioned("op-exact", revision = 4L)
        val wrong = versioned("op-wrong", revision = 4L)
        val journal = FakeJournal(current = wrong, history = historyFor(wrong))

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(planned, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, failed.failure.kind)
        assertEquals(0, journal.historyCalls)
    }

    @Test
    fun `missing exact operation fails contract closed without replay`() = runSuspend {
        val current = versioned("op-missing", revision = 4L)
        val journal = FakeJournal(
            current = current,
            history = historyFor(current),
            getResult = OperationJournalResult.NotFound,
        )

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, failed.failure.kind)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `journal storage failure remains typed and never retries advance`() = runSuspend {
        val current = versioned("op-storage", revision = 4L)
        val journal = FakeJournal(
            current = current,
            history = historyFor(current),
            getResult = OperationJournalResult.StorageFailure("disk unavailable"),
        )

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, failed.failure.kind)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `history storage failure blocks replan without retrying original write`() = runSuspend {
        val current = versioned("op-history-storage", revision = 4L)
        val journal = FakeJournal(
            current = current,
            history = historyFor(current),
            historyResult = OperationJournalResult.StorageFailure("history unavailable"),
        )

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, failed.failure.kind)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `missing history is durability corruption and cannot produce replan context`() = runSuspend {
        val current = versioned("op-no-history", revision = 4L)
        val journal = FakeJournal(
            current = current,
            history = historyFor(current),
            historyResult = OperationJournalResult.NotFound,
        )

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, failed.failure.kind)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `corrupt history is rejected instead of trusting current snapshot alone`() = runSuspend {
        val current = versioned("op-corrupt-history", revision = 4L)
        val corruptHistory = historyFor(current).dropLast(1)
        val journal = FakeJournal(current = current, history = corruptHistory)

        val failed = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, failed.failure.kind)
        assertEquals(0, journal.advanceCalls)
    }

    @Test
    fun `terminal winner is valid durable truth and is returned for fresh no action replan`() = runSuspend {
        val current = versioned(
            id = "op-terminal-winner",
            revision = 4L,
            status = OperationStatus.SUCCEEDED,
            semantics = CheckpointSemantics.TERMINAL,
        )
        val journal = FakeJournal(current = current, history = historyFor(current))

        val result = OperationStaleCasReloadGate(journal).reloadForReplan(
            conflictFor(current, attempted = 3L, observedActual = 4L),
        ) as StaleCasReloadResult.ReplanRequired

        assertEquals(OperationStatus.SUCCEEDED, result.context.current.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, result.context.current.snapshot.checkpoint.semantics)
        assertEquals(0, journal.advanceCalls)
    }

    private fun conflictFor(
        current: VersionedOperationSnapshot,
        attempted: Long,
        observedActual: Long,
    ): StaleCasConflict = StaleCasConflict(
        operationId = current.snapshot.operationId,
        target = current.snapshot.target,
        attemptedExpectedRevision = OperationRevision(attempted),
        observedActualRevision = OperationRevision(observedActual),
    )

    private fun versioned(
        id: String,
        revision: Long,
        status: OperationStatus = OperationStatus.WAITING,
        semantics: CheckpointSemantics = CheckpointSemantics.READ_ONLY,
    ): VersionedOperationSnapshot {
        val operationId = OperationId(id)
        val checkpoint = OperationCheckpoint(
            phaseName = if (semantics == CheckpointSemantics.TERMINAL) "DONE" else "WAITING_FOR_REPLAN",
            semantics = semantics,
            recordedAt = now.plusSeconds(revision),
        )
        return VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = operationId,
                type = OperationType.DISCOVERY,
                target = OperationTarget.ServerTarget(
                    serverId = ServerId("server-$id"),
                    serverAccessId = ServerAccessId("access-$id"),
                ),
                status = status,
                checkpoint = checkpoint,
                startedAt = now,
                updatedAt = checkpoint.recordedAt,
            ),
            revision = OperationRevision(revision),
        )
    }

    private fun historyFor(current: VersionedOperationSnapshot): List<OperationJournalEntry> {
        val snapshot = current.snapshot
        return (0L..current.revision.value).map { revision ->
            val isLatest = revision == current.revision.value
            val checkpoint = if (isLatest) {
                snapshot.checkpoint
            } else {
                OperationCheckpoint(
                    phaseName = "REV_$revision",
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = now.plusSeconds(revision),
                )
            }
            OperationJournalEntry(
                operationId = snapshot.operationId,
                revision = OperationRevision(revision),
                status = if (isLatest) snapshot.status else OperationStatus.RUNNING,
                checkpoint = checkpoint,
                recordedAt = if (isLatest) snapshot.updatedAt else now.plusSeconds(revision),
            )
        }
    }

    private class FakeJournal(
        private val current: VersionedOperationSnapshot,
        private val history: List<OperationJournalEntry>,
        private var getResult: OperationJournalResult<VersionedOperationSnapshot> = OperationJournalResult.Success(current),
        private var historyResult: OperationJournalResult<List<OperationJournalEntry>> = OperationJournalResult.Success(history),
    ) : OperationJournal {
        var getCalls: Int = 0
        var historyCalls: Int = 0
        var advanceCalls: Int = 0

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            error("create must not be called by stale-CAS reload")

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> {
            getCalls += 1
            return getResult
        }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            error("listNonTerminal must not be called by stale-CAS reload")

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCalls += 1
            return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> {
            historyCalls += 1
            return historyResult
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
        return outcome!!.getOrThrow()
    }
}
