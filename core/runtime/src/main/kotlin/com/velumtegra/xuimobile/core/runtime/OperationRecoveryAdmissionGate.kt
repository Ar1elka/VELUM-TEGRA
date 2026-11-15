package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus

/**
 * Authority under which a previously built recovery plan is being admitted for execution.
 *
 * Automatic cold-start work may only use plans that explicitly opted into automatic execution.
 * A later explicit user/platform entry may admit the same exact non-automatic read-only/reconnect
 * plan, but it still cannot bypass revision, target or runtime-ownership checks.
 */
enum class RecoveryAdmissionAuthority {
    AUTOMATIC,
    EXPLICIT_USER_ALLOWED,
}

/**
 * Exact process-local ownership granted only after a recovery plan is proven current enough to run.
 *
 * The underlying lease is intentionally not exposed. Callers release through the same gate so stale
 * cleanup cannot remove a replacement lease for the same OperationId.
 */
class RecoveryRuntimeAdmission internal constructor(
    val plan: ColdStartRecoveryPlan,
    internal val runtimeLease: OperationRuntimeLease,
)

sealed interface RecoveryAdmissionResult {
    data class Admitted(val admission: RecoveryRuntimeAdmission) : RecoveryAdmissionResult

    /** The plan is intentionally non-automatic and needs an explicit allowed entry before admission. */
    data object RequiresExplicitAuthorization : RecoveryAdmissionResult

    /** NO_ACTION/RECOVERY_BLOCKED are outcomes to surface, not executable remote-work plans. */
    data class NotExecutable(val action: RecoveryAction) : RecoveryAdmissionResult

    /** Another exact runtime already owns this OperationId in the current process. */
    data object AlreadyOwned : RecoveryAdmissionResult

    /** Durable truth moved after planning. Caller must reload durable evidence and build a new plan. */
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : RecoveryAdmissionResult

    /** Journal evidence could not be re-read safely enough to execute any remote work. */
    data class Failed(val failure: RecoveryBootstrapFailure) : RecoveryAdmissionResult
}

/**
 * Admission barrier between a pure recovery plan and future coordinator execution.
 *
 * Ordering is deliberate:
 * 1. reject non-executable or unauthorized plans without acquiring ownership;
 * 2. acquire the exact process-local OperationId lease;
 * 3. while owning that lease, re-read the exact durable operation;
 * 4. require the same revision and immutable target identity before returning an admission.
 *
 * This component performs no SSH work and no journal write. Revision mismatch never means "retry the
 * command"; it means release ownership and reload/re-plan from durable truth.
 */
class OperationRecoveryAdmissionGate(
    private val journal: OperationJournal,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
) {
    suspend fun tryAdmit(
        plan: ColdStartRecoveryPlan,
        authority: RecoveryAdmissionAuthority,
    ): RecoveryAdmissionResult {
        if (plan.action == RecoveryAction.NO_ACTION || plan.action == RecoveryAction.RECOVERY_BLOCKED) {
            return RecoveryAdmissionResult.NotExecutable(plan.action)
        }
        if (!plan.automaticAllowed && authority == RecoveryAdmissionAuthority.AUTOMATIC) {
            return RecoveryAdmissionResult.RequiresExplicitAuthorization
        }

        val lease = when (val acquire = runtimeRegistry.tryAcquire(plan.operationId)) {
            is OperationRuntimeAcquireResult.Acquired -> acquire.lease
            OperationRuntimeAcquireResult.AlreadyOwned -> return RecoveryAdmissionResult.AlreadyOwned
        }

        var retainLease = false
        try {
            val current = when (val result = journal.get(plan.operationId)) {
                is OperationJournalResult.Success -> result.value
                OperationJournalResult.NotFound -> {
                    return RecoveryAdmissionResult.Failed(
                        contractFailure("Planned operation no longer exists in OperationJournal"),
                    )
                }
                is OperationJournalResult.Corruption -> {
                    return RecoveryAdmissionResult.Failed(
                        RecoveryBootstrapFailure(
                            kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            reason = result.reason,
                        ),
                    )
                }
                is OperationJournalResult.StorageFailure -> {
                    return RecoveryAdmissionResult.Failed(
                        RecoveryBootstrapFailure(
                            kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            reason = result.reason,
                        ),
                    )
                }
                else -> {
                    return RecoveryAdmissionResult.Failed(
                        contractFailure("get(${plan.operationId.value}) returned ${result::class.simpleName}"),
                    )
                }
            }

            if (current.snapshot.operationId != plan.operationId) {
                return RecoveryAdmissionResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        reason = "OperationJournal returned a different OperationId for exact lookup",
                    ),
                )
            }
            if (current.snapshot.target != plan.target) {
                return RecoveryAdmissionResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        reason = "Operation target changed without a new exact recovery plan",
                    ),
                )
            }
            if (current.revision != plan.expectedRevision) {
                return RecoveryAdmissionResult.StalePlan(
                    operationId = plan.operationId,
                    expectedRevision = plan.expectedRevision,
                    actualRevision = current.revision,
                )
            }
            if (
                current.snapshot.status in terminalStatuses ||
                current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
            ) {
                return RecoveryAdmissionResult.Failed(
                    contractFailure("Executable recovery plan points at terminal durable state"),
                )
            }

            retainLease = true
            return RecoveryAdmissionResult.Admitted(
                RecoveryRuntimeAdmission(
                    plan = plan,
                    runtimeLease = lease,
                ),
            )
        } finally {
            if (!retainLease) {
                check(runtimeRegistry.release(lease) == OperationRuntimeReleaseResult.RELEASED) {
                    "Fresh recovery admission lease must be releasable when admission does not complete"
                }
            }
        }
    }

    fun release(admission: RecoveryRuntimeAdmission): OperationRuntimeReleaseResult =
        runtimeRegistry.release(admission.runtimeLease)


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
