package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import java.time.Instant

sealed interface OperationDurabilityValidation {
    data object Valid : OperationDurabilityValidation
    data class Corrupt(val reason: String) : OperationDurabilityValidation
}

/**
 * Evidence needed to prove that the current durable snapshot and its append-only journal agree.
 * This is intentionally storage-agnostic so reopen/recovery rules are regression-testable on the JVM.
 */
data class OperationJournalEvidence(
    val entryCount: Long,
    val minRevision: Long?,
    val maxRevision: Long?,
    val latestEntry: OperationJournalEntry?,
)

object OperationDurabilityPolicy {
    fun validateEvidence(
        current: VersionedOperationSnapshot,
        evidence: OperationJournalEvidence,
    ): OperationDurabilityValidation {
        when (val snapshotValidation = OperationJournalContractPolicy.validateInitial(current.snapshot)) {
            OperationSnapshotValidation.Valid -> Unit
            is OperationSnapshotValidation.Invalid -> {
                return OperationDurabilityValidation.Corrupt(
                    "Current operation snapshot violates contract: ${snapshotValidation.reason}",
                )
            }
        }

        if (evidence.entryCount <= 0L) {
            return OperationDurabilityValidation.Corrupt("Operation snapshot has no journal history")
        }
        if (evidence.minRevision != 0L) {
            return OperationDurabilityValidation.Corrupt("Operation journal must start at revision 0")
        }
        if (evidence.maxRevision != current.revision.value) {
            return OperationDurabilityValidation.Corrupt(
                "Operation journal max revision does not match current snapshot revision",
            )
        }
        if (evidence.entryCount - 1L != current.revision.value) {
            return OperationDurabilityValidation.Corrupt(
                "Operation journal revisions are not a complete contiguous 0..currentRevision sequence",
            )
        }

        val latest = evidence.latestEntry
            ?: return OperationDurabilityValidation.Corrupt("Operation journal latest entry is missing")
        return validateLatestMatches(current, latest)
    }

    fun validateHistory(
        current: VersionedOperationSnapshot,
        history: List<OperationJournalEntry>,
    ): OperationDurabilityValidation {
        if (history.isEmpty()) {
            return OperationDurabilityValidation.Corrupt("Operation snapshot has no journal history")
        }

        var previousRecordedAt: Instant? = null
        history.forEachIndexed { index, entry ->
            if (entry.operationId != current.snapshot.operationId) {
                return OperationDurabilityValidation.Corrupt("Journal entry belongs to a different OperationId")
            }
            if (entry.revision.value != index.toLong()) {
                return OperationDurabilityValidation.Corrupt("Operation journal contains a revision gap or reorder")
            }
            if (entry.checkpoint.recordedAt.isBefore(current.snapshot.startedAt)) {
                return OperationDurabilityValidation.Corrupt("Journal checkpoint predates operation start")
            }
            if (entry.recordedAt.isBefore(entry.checkpoint.recordedAt)) {
                return OperationDurabilityValidation.Corrupt("Journal recordedAt predates its checkpoint")
            }
            if (previousRecordedAt != null && entry.recordedAt.isBefore(previousRecordedAt)) {
                return OperationDurabilityValidation.Corrupt("Journal recordedAt moved backward")
            }

            val terminalStatus = entry.status in TERMINAL_STATUSES
            val terminalCheckpoint = entry.checkpoint.semantics == CheckpointSemantics.TERMINAL
            if (terminalStatus != terminalCheckpoint) {
                return OperationDurabilityValidation.Corrupt(
                    "Journal terminal status and TERMINAL checkpoint semantics disagree",
                )
            }
            if (terminalStatus && index != history.lastIndex) {
                return OperationDurabilityValidation.Corrupt("Journal advanced after a terminal entry")
            }
            previousRecordedAt = entry.recordedAt
        }

        if (history.last().revision != current.revision) {
            return OperationDurabilityValidation.Corrupt("Journal latest revision does not match current snapshot")
        }
        return validateLatestMatches(current, history.last())
    }

    private fun validateLatestMatches(
        current: VersionedOperationSnapshot,
        latest: OperationJournalEntry,
    ): OperationDurabilityValidation {
        val snapshot = current.snapshot
        if (latest.operationId != snapshot.operationId) {
            return OperationDurabilityValidation.Corrupt("Latest journal OperationId does not match snapshot")
        }
        if (latest.revision != current.revision) {
            return OperationDurabilityValidation.Corrupt("Latest journal revision does not match snapshot")
        }
        if (latest.status != snapshot.status) {
            return OperationDurabilityValidation.Corrupt("Latest journal status does not match snapshot")
        }
        if (latest.checkpoint != snapshot.checkpoint) {
            return OperationDurabilityValidation.Corrupt("Latest journal checkpoint does not match snapshot")
        }
        if (latest.recordedAt != snapshot.updatedAt) {
            return OperationDurabilityValidation.Corrupt("Latest journal recordedAt does not match snapshot updatedAt")
        }
        return OperationDurabilityValidation.Valid
    }

    private val TERMINAL_STATUSES = setOf(
        OperationStatus.SUCCEEDED,
        OperationStatus.FAILED,
        OperationStatus.CANCELLED,
    )
}

/** Small bounded batch prevents a maintenance pass from holding one Room write transaction indefinitely. */
@JvmInline
value class TerminalRetentionBatchSize(val value: Int) {
    init {
        require(value in 1..100) { "Terminal retention batch size must be in 1..100" }
    }
}

data class TerminalOperationRetentionRequest(
    /** Only terminal operations whose updatedAt is strictly before this instant may be removed. */
    val updatedBefore: Instant,
    /** Wall-clock observation used to reject an accidental cutoff from the future. */
    val observedAt: Instant,
    val batchSize: TerminalRetentionBatchSize = TerminalRetentionBatchSize(50),
) {
    init {
        require(!updatedBefore.isAfter(observedAt)) { "Terminal retention cutoff cannot be after observedAt" }
    }
}

data class TerminalOperationRetentionReport(
    val prunedOperationIds: List<OperationId>,
)

/**
 * Deliberately separate from OperationJournal: Runtime reads/advances operations; maintenance owns destructive retention.
 */
interface OperationJournalMaintenance {
    suspend fun pruneTerminalOperations(
        request: TerminalOperationRetentionRequest,
    ): OperationJournalResult<TerminalOperationRetentionReport>
}
