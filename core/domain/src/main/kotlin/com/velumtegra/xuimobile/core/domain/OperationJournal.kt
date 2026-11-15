package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import java.time.Instant

@JvmInline
value class OperationRevision(val value: Long) {
    init {
        require(value >= 0) { "Operation revision must be non-negative" }
    }
}

data class VersionedOperationSnapshot(
    val snapshot: OperationSnapshot,
    val revision: OperationRevision,
)

data class OperationJournalEntry(
    val operationId: OperationId,
    val revision: OperationRevision,
    val status: OperationStatus,
    val checkpoint: OperationCheckpoint,
    val recordedAt: Instant,
)

sealed interface OperationJournalResult<out T> {
    data class Success<T>(val value: T) : OperationJournalResult<T>
    data object NotFound : OperationJournalResult<Nothing>
    data object AlreadyExists : OperationJournalResult<Nothing>
    data class StaleRevision(
        val expected: OperationRevision,
        val actual: OperationRevision,
    ) : OperationJournalResult<Nothing>
    data class InvalidTransition(val reason: String) : OperationJournalResult<Nothing>
    data class Corruption(val reason: String) : OperationJournalResult<Nothing>
    data class StorageFailure(val reason: String) : OperationJournalResult<Nothing>
}

interface OperationJournal {
    suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot>
    suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot>
    suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>>

    /** Atomically update current snapshot and append exactly one journal entry. */
    suspend fun advance(
        operationId: OperationId,
        expectedRevision: OperationRevision,
        next: OperationSnapshot,
    ): OperationJournalResult<VersionedOperationSnapshot>

    suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>>
}

sealed interface OperationSnapshotValidation {
    data object Valid : OperationSnapshotValidation
    data class Invalid(val reason: String) : OperationSnapshotValidation
}

/** Pure Phase 2.1 guardrails used by any later persistence implementation. */
object OperationJournalContractPolicy {
    private val terminalStatuses = setOf(
        OperationStatus.SUCCEEDED,
        OperationStatus.FAILED,
        OperationStatus.CANCELLED,
    )

    fun validateInitial(snapshot: OperationSnapshot): OperationSnapshotValidation {
        return validateTimeAndTerminalCoherence(snapshot)
    }

    fun validateAdvance(
        previous: OperationSnapshot,
        next: OperationSnapshot,
    ): OperationSnapshotValidation {
        if (previous.operationId != next.operationId) {
            return OperationSnapshotValidation.Invalid("OperationId cannot change across revisions")
        }
        if (previous.type != next.type) {
            return OperationSnapshotValidation.Invalid("Operation type cannot change across revisions")
        }
        if (previous.target != next.target) {
            return OperationSnapshotValidation.Invalid("Operation target cannot change across revisions")
        }
        if (previous.startedAt != next.startedAt) {
            return OperationSnapshotValidation.Invalid("Operation startedAt cannot change across revisions")
        }
        if (previous.status in terminalStatuses || previous.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return OperationSnapshotValidation.Invalid("Terminal operation cannot advance")
        }
        if (next.updatedAt.isBefore(previous.updatedAt)) {
            return OperationSnapshotValidation.Invalid("Operation updatedAt cannot move backward")
        }
        return validateTimeAndTerminalCoherence(next)
    }

    private fun validateTimeAndTerminalCoherence(
        snapshot: OperationSnapshot,
    ): OperationSnapshotValidation {
        if (snapshot.updatedAt.isBefore(snapshot.startedAt)) {
            return OperationSnapshotValidation.Invalid("updatedAt cannot be before startedAt")
        }
        if (snapshot.checkpoint.recordedAt.isBefore(snapshot.startedAt)) {
            return OperationSnapshotValidation.Invalid("checkpoint cannot be before operation start")
        }
        if (snapshot.updatedAt.isBefore(snapshot.checkpoint.recordedAt)) {
            return OperationSnapshotValidation.Invalid("updatedAt cannot be before checkpoint time")
        }

        val terminalStatus = snapshot.status in terminalStatuses
        val terminalCheckpoint = snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        if (terminalStatus != terminalCheckpoint) {
            return OperationSnapshotValidation.Invalid(
                "Terminal status and TERMINAL checkpoint semantics must agree",
            )
        }

        return OperationSnapshotValidation.Valid
    }
}
