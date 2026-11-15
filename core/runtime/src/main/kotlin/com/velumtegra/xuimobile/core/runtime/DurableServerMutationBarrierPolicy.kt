package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.ServerId

/**
 * Durable evidence explaining why a new mutation must not start on one exact Server.
 *
 * The blocker comes only from persisted Operation state. It is not a process-local lock and it
 * intentionally contains no transport/session state.
 */
data class UncertainMutationBlocker(
    val operationId: OperationId,
    val status: OperationStatus,
    val checkpointSemantics: CheckpointSemantics,
)

sealed interface ServerMutationBarrierDecision {
    data object Allowed : ServerMutationBarrierDecision

    data class BlockedByUncertainMutation(
        val blockers: List<UncertainMutationBlocker>,
    ) : ServerMutationBarrierDecision {
        init {
            require(blockers.isNotEmpty()) { "Blocked mutation decision requires durable blocker evidence" }
        }
    }
}

/**
 * Pure durable precondition for starting a new server mutation.
 *
 * A nonterminal Operation on the same stable [ServerId] blocks new mutation whenever its durable
 * checkpoint says a previous mutation/restart may still be unresolved. The caller is responsible
 * for loading current durable Operation snapshots (and validating their journal evidence) before
 * invoking this policy. Read-only reconciliation does not pass through this mutation-only gate.
 *
 * Because the decision is derived solely from durable snapshots, process death cannot erase the
 * barrier. No lease is acquired here; live-process serialization remains the responsibility of
 * [ServerMutationLeaseRegistry].
 */
object DurableServerMutationBarrierPolicy {
    private val terminalStatuses = setOf(
        OperationStatus.SUCCEEDED,
        OperationStatus.FAILED,
        OperationStatus.CANCELLED,
    )

    private val unsafeCheckpointSemantics = setOf(
        CheckpointSemantics.MUTATION_IN_FLIGHT,
        CheckpointSemantics.RESTART_IN_FLIGHT,
        CheckpointSemantics.POST_VERIFY_REQUIRED,
    )

    fun evaluate(
        serverId: ServerId,
        durableOperations: Iterable<OperationSnapshot>,
    ): ServerMutationBarrierDecision {
        val blockers = durableOperations
            .asSequence()
            .filter { it.target.serverId == serverId }
            .filter { it.status !in terminalStatuses }
            .filter { it.checkpoint.semantics in unsafeCheckpointSemantics }
            .map {
                UncertainMutationBlocker(
                    operationId = it.operationId,
                    status = it.status,
                    checkpointSemantics = it.checkpoint.semantics,
                )
            }
            .sortedBy { it.operationId.value }
            .toList()

        return if (blockers.isEmpty()) {
            ServerMutationBarrierDecision.Allowed
        } else {
            ServerMutationBarrierDecision.BlockedByUncertainMutation(blockers)
        }
    }
}
