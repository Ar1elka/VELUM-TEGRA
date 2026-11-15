package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationDurabilityPolicy
import com.velumtegra.xuimobile.core.domain.OperationDurabilityValidation
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget

/**
 * Failure to read enough durable evidence to build a safe cold-start plan.
 *
 * This is intentionally distinct from [RecoveryBlockReason]. A storage outage or a repository
 * contract violation is not rewritten as if the persisted operation itself had been proven corrupt.
 */
enum class RecoveryBootstrapFailureKind {
    JOURNAL_STORAGE_FAILURE,
    JOURNAL_CORRUPTION,
    JOURNAL_CONTRACT_VIOLATION,
}

data class RecoveryBootstrapFailure(
    val kind: RecoveryBootstrapFailureKind,
    val reason: String,
)

sealed interface RecoveryBootstrapItem {
    val operationId: OperationId
    val target: OperationTarget
    val expectedRevision: OperationRevision

    /** A complete durable history was available, so the normal recovery policy could produce a plan. */
    data class Planned(
        val plan: ColdStartRecoveryPlan,
    ) : RecoveryBootstrapItem {
        override val operationId: OperationId = plan.operationId
        override val target: OperationTarget = plan.target
        override val expectedRevision: OperationRevision = plan.expectedRevision
    }

    /**
     * The exact operation remains durable, but its history could not be read safely enough to plan.
     * Future runtime code must surface/retry the local read problem; it must not start remote work.
     */
    data class Unavailable(
        override val operationId: OperationId,
        override val target: OperationTarget,
        override val expectedRevision: OperationRevision,
        val failure: RecoveryBootstrapFailure,
    ) : RecoveryBootstrapItem
}

sealed interface RecoveryBootstrapResult {
    data class Success(val items: List<RecoveryBootstrapItem>) : RecoveryBootstrapResult
    data class Failed(val failure: RecoveryBootstrapFailure) : RecoveryBootstrapResult
}

/**
 * Journal-first cold-start bootstrap for Phase 4.4.
 *
 * This component performs no Android work, acquires no OperationRuntime lease, opens no SSH
 * session and advances no durable state. It only turns the durable nonterminal set plus one
 * normalized previous-process provenance into exact recovery plans.
 *
 * Exact runtime ownership is deliberately acquired later, immediately before execution, after the
 * plan revision has been re-checked. Planning itself must not make an operation look "active".
 */
class OperationRecoveryBootstrap(
    private val journal: OperationJournal,
) {
    suspend fun plan(exitProvenance: RecoveryExitProvenance): RecoveryBootstrapResult {
        val currentOperations = when (val result = journal.listNonTerminal()) {
            is OperationJournalResult.Success -> result.value
            is OperationJournalResult.Corruption -> {
                return RecoveryBootstrapResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        reason = result.reason,
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return RecoveryBootstrapResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                        reason = result.reason,
                    ),
                )
            }
            else -> {
                return RecoveryBootstrapResult.Failed(
                    contractFailure("listNonTerminal returned ${result::class.simpleName}"),
                )
            }
        }

        validateNonTerminalIndex(currentOperations)?.let {
            return RecoveryBootstrapResult.Failed(it)
        }

        val items = ArrayList<RecoveryBootstrapItem>(currentOperations.size)
        for (current in currentOperations) {
            items += planOne(current, exitProvenance)
        }
        return RecoveryBootstrapResult.Success(items)
    }

    private suspend fun planOne(
        current: VersionedOperationSnapshot,
        exitProvenance: RecoveryExitProvenance,
    ): RecoveryBootstrapItem {
        val durabilityValidation = when (val historyResult = journal.history(current.snapshot.operationId)) {
            is OperationJournalResult.Success -> {
                OperationDurabilityPolicy.validateHistory(current, historyResult.value)
            }
            OperationJournalResult.NotFound -> {
                OperationDurabilityValidation.Corrupt(
                    "Nonterminal operation has no journal history",
                )
            }
            is OperationJournalResult.Corruption -> {
                OperationDurabilityValidation.Corrupt(historyResult.reason)
            }
            is OperationJournalResult.StorageFailure -> {
                return current.unavailable(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                        reason = historyResult.reason,
                    ),
                )
            }
            else -> {
                return current.unavailable(
                    contractFailure(
                        "history(${current.snapshot.operationId.value}) returned ${historyResult::class.simpleName}",
                    ),
                )
            }
        }

        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = current,
                durabilityValidation = durabilityValidation,
                exitProvenance = exitProvenance,
            ),
        )
        return RecoveryBootstrapItem.Planned(plan)
    }

    private fun validateNonTerminalIndex(
        operations: List<VersionedOperationSnapshot>,
    ): RecoveryBootstrapFailure? {
        val seen = HashSet<OperationId>(operations.size)
        for (current in operations) {
            val snapshot = current.snapshot
            if (!seen.add(snapshot.operationId)) {
                return RecoveryBootstrapFailure(
                    kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                    reason = "Nonterminal operation list contains duplicate OperationId",
                )
            }
            if (
                snapshot.status in terminalStatuses ||
                snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
            ) {
                return contractFailure(
                    "listNonTerminal returned a terminal operation",
                )
            }
        }
        return null
    }

    private fun VersionedOperationSnapshot.unavailable(
        failure: RecoveryBootstrapFailure,
    ): RecoveryBootstrapItem.Unavailable = RecoveryBootstrapItem.Unavailable(
        operationId = snapshot.operationId,
        target = snapshot.target,
        expectedRevision = revision,
        failure = failure,
    )

    private fun contractFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        kind = RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason = reason,
    )

    private companion object {
        val terminalStatuses = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}
