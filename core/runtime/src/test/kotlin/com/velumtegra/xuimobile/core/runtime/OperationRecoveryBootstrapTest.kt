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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationRecoveryBootstrapTest {
    private val now = Instant.parse("2026-09-01T20:00:00Z")

    @Test
    fun `valid nonterminal histories produce exact recovery plans in journal order`() = runSuspend {
        val first = versioned("op-a", CheckpointSemantics.READ_ONLY, revision = 1L)
        val second = versioned("op-b", CheckpointSemantics.MUTATION_IN_FLIGHT, revision = 1L)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(first, second)),
            histories = mutableMapOf(
                first.snapshot.operationId to OperationJournalResult.Success(historyFor(first)),
                second.snapshot.operationId to OperationJournalResult.Success(historyFor(second)),
            ),
        )

        val result = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
        val success = result as RecoveryBootstrapResult.Success

        assertEquals(listOf(first.snapshot.operationId, second.snapshot.operationId), success.items.map { it.operationId })
        assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, (success.items[0] as RecoveryBootstrapItem.Planned).plan.action)
        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, (success.items[1] as RecoveryBootstrapItem.Planned).plan.action)
    }

    @Test
    fun `bootstrap preserves exact target and expected revision`() = runSuspend {
        val current = versioned("op-exact", CheckpointSemantics.READ_ONLY, revision = 3L)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current)),
            histories = mutableMapOf(
                current.snapshot.operationId to OperationJournalResult.Success(historyFor(current)),
            ),
        )

        val item = ((OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Success).items.single() as RecoveryBootstrapItem.Planned)

        assertEquals(current.snapshot.operationId, item.operationId)
        assertEquals(current.snapshot.target, item.target)
        assertEquals(current.revision, item.expectedRevision)
    }

    @Test
    fun `corrupt history becomes recovery blocked and is never silently omitted`() = runSuspend {
        val current = versioned("op-corrupt", CheckpointSemantics.READ_ONLY, revision = 1L)
        val corruptHistory = historyFor(current).dropLast(1)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current)),
            histories = mutableMapOf(
                current.snapshot.operationId to OperationJournalResult.Success(corruptHistory),
            ),
        )

        val success = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Success
        val plan = (success.items.single() as RecoveryBootstrapItem.Planned).plan

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT, plan.blockReason)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `missing history becomes durability blocked rather than guessed from snapshot`() = runSuspend {
        val current = versioned("op-missing-history", CheckpointSemantics.READ_ONLY, revision = 0L)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current)),
            histories = mutableMapOf(current.snapshot.operationId to OperationJournalResult.NotFound),
        )

        val success = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Success
        val plan = (success.items.single() as RecoveryBootstrapItem.Planned).plan

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT, plan.blockReason)
    }

    @Test
    fun `per operation history storage failure is explicit unavailable and preserves identity`() = runSuspend {
        val current = versioned("op-storage", CheckpointSemantics.READ_ONLY, revision = 4L)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current)),
            histories = mutableMapOf(
                current.snapshot.operationId to OperationJournalResult.StorageFailure("disk unavailable"),
            ),
        )

        val success = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Success
        val unavailable = success.items.single() as RecoveryBootstrapItem.Unavailable

        assertEquals(current.snapshot.operationId, unavailable.operationId)
        assertEquals(current.snapshot.target, unavailable.target)
        assertEquals(current.revision, unavailable.expectedRevision)
        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, unavailable.failure.kind)
    }

    @Test
    fun `list storage failure blocks entire bootstrap before history reads`() = runSuspend {
        val journal = FakeJournal(
            listResult = OperationJournalResult.StorageFailure("database unavailable"),
        )

        val failed = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.UNKNOWN)
            as RecoveryBootstrapResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, failed.failure.kind)
        assertEquals(0, journal.historyCalls)
    }

    @Test
    fun `duplicate operation id in nonterminal index fails closed before history reads`() = runSuspend {
        val current = versioned("op-duplicate", CheckpointSemantics.READ_ONLY, revision = 1L)
        val duplicate = current.copy()
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current, duplicate)),
        )

        val failed = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, failed.failure.kind)
        assertEquals(0, journal.historyCalls)
    }

    @Test
    fun `terminal operation returned by nonterminal query is contract violation`() = runSuspend {
        val terminal = versioned(
            id = "op-terminal",
            semantics = CheckpointSemantics.TERMINAL,
            revision = 1L,
            status = OperationStatus.SUCCEEDED,
        )
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(terminal)),
        )

        val failed = OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)
            as RecoveryBootstrapResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, failed.failure.kind)
        assertEquals(0, journal.historyCalls)
    }

    @Test
    fun `unknown exit provenance remains non automatic for safe operation`() = runSuspend {
        val current = versioned("op-unknown", CheckpointSemantics.MUTATION_NOT_STARTED, revision = 1L)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current)),
            histories = mutableMapOf(
                current.snapshot.operationId to OperationJournalResult.Success(historyFor(current)),
            ),
        )

        val plan = (((OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.UNKNOWN)
            as RecoveryBootstrapResult.Success).items.single() as RecoveryBootstrapItem.Planned).plan)

        assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plan.action)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `bootstrap performs no journal writes`() = runSuspend {
        val current = versioned("op-read-only-bootstrap", CheckpointSemantics.READ_ONLY, revision = 1L)
        val journal = FakeJournal(
            listResult = OperationJournalResult.Success(listOf(current)),
            histories = mutableMapOf(
                current.snapshot.operationId to OperationJournalResult.Success(historyFor(current)),
            ),
        )

        OperationRecoveryBootstrap(journal).plan(RecoveryExitProvenance.PROCESS_DEATH)

        assertEquals(0, journal.createCalls)
        assertEquals(0, journal.advanceCalls)
        assertEquals(0, journal.getCalls)
        assertTrue(journal.historyCalls > 0)
    }

    private fun versioned(
        id: String,
        semantics: CheckpointSemantics,
        revision: Long,
        status: OperationStatus = OperationStatus.RUNNING,
    ): VersionedOperationSnapshot {
        val checkpointTime = now.plusSeconds(revision)
        return VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = OperationId(id),
                type = OperationType.RECOVERY,
                target = OperationTarget.ServerTarget(
                    serverId = ServerId("server-$id"),
                    serverAccessId = ServerAccessId("access-$id"),
                ),
                status = status,
                checkpoint = OperationCheckpoint(
                    phaseName = "phase-$revision",
                    semantics = semantics,
                    recordedAt = checkpointTime,
                ),
                startedAt = now,
                updatedAt = checkpointTime,
            ),
            revision = OperationRevision(revision),
        )
    }

    private fun historyFor(current: VersionedOperationSnapshot): List<OperationJournalEntry> {
        val snapshot = current.snapshot
        return (0L..current.revision.value).map { revision ->
            val isLatest = revision == current.revision.value
            val recordedAt = now.plusSeconds(revision)
            OperationJournalEntry(
                operationId = snapshot.operationId,
                revision = OperationRevision(revision),
                status = if (isLatest) snapshot.status else OperationStatus.RUNNING,
                checkpoint = if (isLatest) {
                    snapshot.checkpoint
                } else {
                    OperationCheckpoint(
                        phaseName = "history-$revision",
                        semantics = CheckpointSemantics.READ_ONLY,
                        recordedAt = recordedAt,
                    )
                },
                recordedAt = recordedAt,
            )
        }
    }

    private class FakeJournal(
        private val listResult: OperationJournalResult<List<VersionedOperationSnapshot>>,
        private val histories: MutableMap<OperationId, OperationJournalResult<List<OperationJournalEntry>>> = mutableMapOf(),
    ) : OperationJournal {
        var createCalls: Int = 0
        var getCalls: Int = 0
        var advanceCalls: Int = 0
        var historyCalls: Int = 0

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
            createCalls += 1
            return OperationJournalResult.StorageFailure("create must not be called by bootstrap")
        }

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> {
            getCalls += 1
            return OperationJournalResult.StorageFailure("get must not be called by bootstrap")
        }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> = listResult

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCalls += 1
            return OperationJournalResult.StorageFailure("advance must not be called by bootstrap")
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> {
            historyCalls += 1
            return histories[operationId] ?: OperationJournalResult.NotFound
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
