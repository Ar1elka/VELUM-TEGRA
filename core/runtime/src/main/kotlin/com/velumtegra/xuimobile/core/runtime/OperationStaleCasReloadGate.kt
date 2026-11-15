package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationDurabilityPolicy
import com.velumtegra.xuimobile.core.domain.OperationDurabilityValidation
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationTarget

/**
 * Exact evidence captured from one failed OperationJournal CAS advance.
 *
 * A stale CAS is evidence that another durable writer won. It is never permission to repeat the
 * original advance or any remote command that led to it.
 */
data class StaleCasConflict(
    val operationId: OperationId,
    val target: OperationTarget,
    val attemptedExpectedRevision: OperationRevision,
    val observedActualRevision: OperationRevision,
) {
    init {
        require(observedActualRevision.value > attemptedExpectedRevision.value) {
            "A stale CAS conflict must prove a strictly newer durable revision"
        }
    }

    companion object {
        fun from(
            operationId: OperationId,
            target: OperationTarget,
            attemptedExpectedRevision: OperationRevision,
            stale: OperationJournalResult.StaleRevision,
        ): StaleCasConflict? {
            if (stale.expected != attemptedExpectedRevision) return null
            if (stale.actual.value <= stale.expected.value) return null
            return StaleCasConflict(
                operationId = operationId,
                target = target,
                attemptedExpectedRevision = attemptedExpectedRevision,
                observedActualRevision = stale.actual,
            )
        }
    }
}

/**
 * Durable state that has been reloaded and fully journal-validated after a stale CAS.
 *
 * The caller must build a fresh plan from [current]. Reusing the pre-conflict plan or replaying the
 * failed advance would violate the stale-writer rule.
 */
data class OperationReplanContext(
    val current: VersionedOperationSnapshot,
    val staleConflict: StaleCasConflict,
)

sealed interface StaleCasReloadResult {
    data class ReplanRequired(val context: OperationReplanContext) : StaleCasReloadResult
    data class Failed(val failure: RecoveryBootstrapFailure) : StaleCasReloadResult
}

/**
 * Phase 4.4 stale-CAS reload barrier.
 *
 * It performs no journal advance, no SSH work and no automatic retry. After a CAS conflict it reads
 * the exact durable operation again, verifies that the store has not moved backward relative to the
 * already-observed conflict, validates complete append-only history, and returns only the newest
 * durable truth as a re-plan input.
 */
class OperationStaleCasReloadGate(
    private val journal: OperationJournal,
) {
    suspend fun reloadForReplan(conflict: StaleCasConflict): StaleCasReloadResult {
        val current = when (val result = journal.get(conflict.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> {
                return StaleCasReloadResult.Failed(
                    contractFailure("Stale-CAS operation no longer exists in OperationJournal"),
                )
            }
            is OperationJournalResult.Corruption -> {
                return StaleCasReloadResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        reason = result.reason,
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return StaleCasReloadResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                        reason = result.reason,
                    ),
                )
            }
            else -> {
                return StaleCasReloadResult.Failed(
                    contractFailure("get(${conflict.operationId.value}) returned ${result::class.simpleName}"),
                )
            }
        }

        if (current.snapshot.operationId != conflict.operationId) {
            return StaleCasReloadResult.Failed(
                RecoveryBootstrapFailure(
                    kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                    reason = "OperationJournal returned a different OperationId for stale-CAS reload",
                ),
            )
        }
        if (current.snapshot.target != conflict.target) {
            return StaleCasReloadResult.Failed(
                RecoveryBootstrapFailure(
                    kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                    reason = "Operation target changed during stale-CAS reload",
                ),
            )
        }
        if (current.revision.value < conflict.observedActualRevision.value) {
            return StaleCasReloadResult.Failed(
                contractFailure(
                    "OperationJournal moved backward below the revision already proven by StaleRevision",
                ),
            )
        }

        val durability = when (val historyResult = journal.history(conflict.operationId)) {
            is OperationJournalResult.Success -> OperationDurabilityPolicy.validateHistory(
                current = current,
                history = historyResult.value,
            )
            OperationJournalResult.NotFound -> OperationDurabilityValidation.Corrupt(
                "Reloaded stale-CAS operation has no journal history",
            )
            is OperationJournalResult.Corruption -> OperationDurabilityValidation.Corrupt(
                historyResult.reason,
            )
            is OperationJournalResult.StorageFailure -> {
                return StaleCasReloadResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                        reason = historyResult.reason,
                    ),
                )
            }
            else -> {
                return StaleCasReloadResult.Failed(
                    contractFailure(
                        "history(${conflict.operationId.value}) returned ${historyResult::class.simpleName}",
                    ),
                )
            }
        }

        if (durability is OperationDurabilityValidation.Corrupt) {
            return StaleCasReloadResult.Failed(
                RecoveryBootstrapFailure(
                    kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                    reason = durability.reason,
                ),
            )
        }

        return StaleCasReloadResult.ReplanRequired(
            OperationReplanContext(
                current = current,
                staleConflict = conflict,
            ),
        )
    }

    private fun contractFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        kind = RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason = reason,
    )
}
