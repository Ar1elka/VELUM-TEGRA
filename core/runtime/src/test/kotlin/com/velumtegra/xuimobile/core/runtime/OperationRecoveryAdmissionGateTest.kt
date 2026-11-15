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
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationRecoveryAdmissionGateTest {
    private val now = Instant.parse("2026-09-01T00:00:00Z")

    @Test
    fun `fresh automatic plan acquires exact runtime only after revision recheck`() = runSuspend {
        val current = versioned("op-fresh", revision = 4L)
        val journal = FakeJournal(OperationJournalResult.Success(current))
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)

        val result = gate.tryAdmit(
            plan = planFor(current, automaticAllowed = true),
            authority = RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted

        assertEquals(current.snapshot.operationId, result.admission.plan.operationId)
        assertEquals(1, journal.getCalls)
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(result.admission))
    }

    @Test
    fun `non automatic plan requires explicit authorization without taking runtime lease`() = runSuspend {
        val current = versioned("op-explicit", revision = 2L)
        val journal = FakeJournal(OperationJournalResult.Success(current))
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)
        val plan = planFor(current, automaticAllowed = false)

        assertEquals(
            RecoveryAdmissionResult.RequiresExplicitAuthorization,
            gate.tryAdmit(plan, RecoveryAdmissionAuthority.AUTOMATIC),
        )
        assertEquals(0, journal.getCalls)

        val explicit = gate.tryAdmit(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED)
            as RecoveryAdmissionResult.Admitted
        assertEquals(1, journal.getCalls)
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(explicit.admission))
    }

    @Test
    fun `no action and recovery blocked plans never acquire runtime ownership`() = runSuspend {
        val current = versioned("op-no-action", revision = 1L)
        val journal = FakeJournal(OperationJournalResult.Success(current))
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)

        val noAction = planFor(current, action = RecoveryAction.NO_ACTION, automaticAllowed = false)
        val blocked = ColdStartRecoveryPlan(
            operationId = current.snapshot.operationId,
            target = current.snapshot.target,
            expectedRevision = current.revision,
            action = RecoveryAction.RECOVERY_BLOCKED,
            automaticAllowed = false,
            blockReason = RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT,
        )

        assertEquals(
            RecoveryAdmissionResult.NotExecutable(RecoveryAction.NO_ACTION),
            gate.tryAdmit(noAction, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED),
        )
        assertEquals(
            RecoveryAdmissionResult.NotExecutable(RecoveryAction.RECOVERY_BLOCKED),
            gate.tryAdmit(blocked, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED),
        )
        assertEquals(0, journal.getCalls)
    }

    @Test
    fun `revision change releases lease and requires reload replan`() = runSuspend {
        val planned = versioned("op-stale", revision = 3L)
        val current = versioned("op-stale", revision = 4L)
        val journal = FakeJournal(OperationJournalResult.Success(current))
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)

        val stale = gate.tryAdmit(
            planFor(planned, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.StalePlan

        assertEquals(OperationRevision(3), stale.expectedRevision)
        assertEquals(OperationRevision(4), stale.actualRevision)

        val fresh = gate.tryAdmit(
            planFor(current, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(fresh.admission))
    }

    @Test
    fun `journal read failure releases lease and cannot start remote work`() = runSuspend {
        val current = versioned("op-storage", revision = 2L)
        val journal = FakeJournal(OperationJournalResult.StorageFailure("disk unavailable"))
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)

        val failed = gate.tryAdmit(
            planFor(current, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, failed.failure.kind)

        journal.getResult = OperationJournalResult.Success(current)
        val retry = gate.tryAdmit(
            planFor(current, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Admitted
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(retry.admission))
    }

    @Test
    fun `missing operation releases lease and fails contract closed`() = runSuspend {
        val current = versioned("op-missing", revision = 2L)
        val journal = FakeJournal(OperationJournalResult.NotFound)
        val gate = OperationRecoveryAdmissionGate(journal, OperationRuntimeLeaseRegistry())

        val failed = gate.tryAdmit(
            planFor(current, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, failed.failure.kind)
    }

    @Test
    fun `same revision with changed exact target fails as journal corruption`() = runSuspend {
        val planned = versioned("op-target", revision = 5L)
        val changed = planned.copy(
            snapshot = planned.snapshot.copy(
                target = OperationTarget.ServerTarget(
                    serverId = planned.snapshot.target.serverId,
                    serverAccessId = ServerAccessId("different-access"),
                ),
            ),
        )
        val gate = OperationRecoveryAdmissionGate(
            FakeJournal(OperationJournalResult.Success(changed)),
            OperationRuntimeLeaseRegistry(),
        )

        val failed = gate.tryAdmit(
            planFor(planned, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, failed.failure.kind)
    }

    @Test
    fun `terminal durable state cannot be admitted even at expected revision`() = runSuspend {
        val planned = versioned("op-terminal-race", revision = 7L)
        val terminal = versioned(
            id = "op-terminal-race",
            revision = 7L,
            status = OperationStatus.SUCCEEDED,
            semantics = CheckpointSemantics.TERMINAL,
        )
        val gate = OperationRecoveryAdmissionGate(
            FakeJournal(OperationJournalResult.Success(terminal)),
            OperationRuntimeLeaseRegistry(),
        )

        val failed = gate.tryAdmit(
            planFor(planned, automaticAllowed = true),
            RecoveryAdmissionAuthority.AUTOMATIC,
        ) as RecoveryAdmissionResult.Failed

        assertEquals(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, failed.failure.kind)
    }

    @Test
    fun `cancellation during durable revision recheck releases exact runtime lease`() {
        val current = versioned("op-cancelled-admission", revision = 3L)
        val journal = FakeJournal(OperationJournalResult.Success(current)).apply {
            getThrowable = CancellationException("host destroyed during durable reread")
        }
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)
        val plan = planFor(current, automaticAllowed = true)

        var cancelled = false
        try {
            runSuspend {
                gate.tryAdmit(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED)
            }
        } catch (_: CancellationException) {
            cancelled = true
        }
        assertTrue(cancelled)

        journal.getThrowable = null
        val replacement = runSuspend {
            gate.tryAdmit(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED)
        } as RecoveryAdmissionResult.Admitted
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(replacement.admission))
    }

    @Test
    fun `parallel duplicate admission has exactly one owner`() {
        val current = versioned("op-race", revision = 1L)
        val journal = FakeJournal(OperationJournalResult.Success(current))
        val registry = OperationRuntimeLeaseRegistry()
        val gate = OperationRecoveryAdmissionGate(journal, registry)
        val plan = planFor(current, automaticAllowed = true)
        val workers = 24
        val start = CountDownLatch(1)
        val done = CountDownLatch(workers)
        val pool = Executors.newFixedThreadPool(workers)
        val results = java.util.Collections.synchronizedList(mutableListOf<RecoveryAdmissionResult>())

        repeat(workers) {
            pool.execute {
                start.await()
                results += runSuspend {
                    gate.tryAdmit(plan, RecoveryAdmissionAuthority.AUTOMATIC)
                }
                done.countDown()
            }
        }
        start.countDown()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        pool.shutdownNow()

        val admitted = results.filterIsInstance<RecoveryAdmissionResult.Admitted>()
        assertEquals(1, admitted.size)
        assertEquals(workers - 1, results.count { it == RecoveryAdmissionResult.AlreadyOwned })
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(admitted.single().admission))
    }

    @Test
    fun `late cleanup from old admission cannot release replacement admission`() = runSuspend {
        val current = versioned("op-cleanup", revision = 2L)
        val journal = FakeJournal(OperationJournalResult.Success(current))
        val gate = OperationRecoveryAdmissionGate(journal, OperationRuntimeLeaseRegistry())
        val plan = planFor(current, automaticAllowed = true)

        val first = (gate.tryAdmit(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted).admission
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(first))

        val replacement = (gate.tryAdmit(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as RecoveryAdmissionResult.Admitted).admission
        assertEquals(OperationRuntimeReleaseResult.STALE_OR_ALREADY_RELEASED, gate.release(first))

        assertEquals(
            RecoveryAdmissionResult.AlreadyOwned,
            gate.tryAdmit(plan, RecoveryAdmissionAuthority.AUTOMATIC),
        )
        assertEquals(OperationRuntimeReleaseResult.RELEASED, gate.release(replacement))
    }

    private fun planFor(
        current: VersionedOperationSnapshot,
        action: RecoveryAction = RecoveryAction.RECONNECT_EXACT_OWNER,
        automaticAllowed: Boolean,
    ): ColdStartRecoveryPlan = ColdStartRecoveryPlan(
        operationId = current.snapshot.operationId,
        target = current.snapshot.target,
        expectedRevision = current.revision,
        action = action,
        automaticAllowed = automaticAllowed,
    )

    private fun versioned(
        id: String,
        revision: Long,
        status: OperationStatus = OperationStatus.RUNNING,
        semantics: CheckpointSemantics = CheckpointSemantics.READ_ONLY,
    ): VersionedOperationSnapshot {
        val instant = now.plusSeconds(revision)
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
                    recordedAt = instant,
                ),
                startedAt = now,
                updatedAt = instant,
            ),
            revision = OperationRevision(revision),
        )
    }

    private class FakeJournal(
        var getResult: OperationJournalResult<VersionedOperationSnapshot>,
    ) : OperationJournal {
        var getCalls: Int = 0
        var getThrowable: Throwable? = null

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.StorageFailure("not used")

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> {
            getCalls += 1
            getThrowable?.let { throw it }
            return getResult
        }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.StorageFailure("not used")

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> = OperationJournalResult.StorageFailure("not used")

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.StorageFailure("not used")
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
