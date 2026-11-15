package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.InterruptionReason
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus

enum class ResumeAction {
    CONTINUE,
    WAIT_FOR_NETWORK,
    RECONNECT_EXACT_OWNER,
    RECONCILE_READ_ONLY,
    NO_ACTION,
}

data class ResumePlan(
    val action: ResumeAction,
    val automaticAllowed: Boolean,
)

/** Platform-independent lifecycle rulebook. Android execution is implemented later in Phase 4. */
object ResumePolicy {
    fun plan(
        operation: OperationSnapshot,
        interruption: InterruptionReason,
        connectivity: ConnectivityState,
    ): ResumePlan {
        if (operation.status in setOf(
                OperationStatus.SUCCEEDED,
                OperationStatus.FAILED,
                OperationStatus.CANCELLED,
            ) || operation.checkpoint.semantics == CheckpointSemantics.TERMINAL
        ) {
            return ResumePlan(ResumeAction.NO_ACTION, automaticAllowed = false)
        }

        if (connectivity == ConnectivityState.OFFLINE) {
            return ResumePlan(ResumeAction.WAIT_FOR_NETWORK, automaticAllowed = true)
        }

        val unsafeToReplay = operation.checkpoint.semantics in setOf(
            CheckpointSemantics.MUTATION_IN_FLIGHT,
            CheckpointSemantics.RESTART_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
        )

        return when (interruption) {
            InterruptionReason.ACTIVITY_RECREATED,
            InterruptionReason.APP_BACKGROUNDED,
            -> ResumePlan(ResumeAction.CONTINUE, automaticAllowed = true)

            InterruptionReason.NETWORK_LOSS ->
                if (unsafeToReplay) {
                    ResumePlan(ResumeAction.RECONCILE_READ_ONLY, automaticAllowed = true)
                } else {
                    ResumePlan(ResumeAction.RECONNECT_EXACT_OWNER, automaticAllowed = true)
                }

            InterruptionReason.PROCESS_DEATH,
            InterruptionReason.SYSTEM_STOP,
            -> if (unsafeToReplay) {
                ResumePlan(ResumeAction.RECONCILE_READ_ONLY, automaticAllowed = true)
            } else {
                ResumePlan(ResumeAction.RECONNECT_EXACT_OWNER, automaticAllowed = true)
            }

            InterruptionReason.USER_FORCE_STOP,
            InterruptionReason.DEVICE_REBOOT,
            -> ResumePlan(ResumeAction.RECONCILE_READ_ONLY, automaticAllowed = false)
        }
    }
}
