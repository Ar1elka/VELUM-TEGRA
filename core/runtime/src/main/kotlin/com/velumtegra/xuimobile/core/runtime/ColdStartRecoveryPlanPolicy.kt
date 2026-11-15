package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationDurabilityValidation
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget

/**
 * Platform-neutral cold-start provenance supplied by a later Android exit-evidence adapter.
 *
 * This policy never reads ApplicationExitInfo directly. UNKNOWN deliberately represents every
 * platform/version/startup case where the previous process exit cannot be proven trustworthy.
 */
enum class RecoveryExitProvenance {
    PROCESS_DEATH,
    SYSTEM_STOP,
    USER_REQUESTED_STOP,
    DEVICE_REBOOT,
    UNKNOWN,
}

enum class RecoveryBlockReason {
    DURABILITY_EVIDENCE_CORRUPT,
    EXACT_ACCESS_MISSING,
    REQUIRED_SECRET_MISSING,
    HOST_IDENTITY_MISMATCH,
    AUTHENTICATION_REJECTED,
}

enum class RecoveryAction {
    NO_ACTION,
    RECOVERY_BLOCKED,
    RECONNECT_EXACT_OWNER,
    RECONCILE_READ_ONLY,
}

data class RecoveryPlanInput(
    val current: VersionedOperationSnapshot,
    val durabilityValidation: OperationDurabilityValidation,
    val exitProvenance: RecoveryExitProvenance,
    /** Optional invariant/trust blocker already established by an exact recovery prerequisite. */
    val prerequisiteBlock: RecoveryBlockReason? = null,
)

data class ColdStartRecoveryPlan(
    val operationId: OperationId,
    val target: OperationTarget,
    /** Revision the future coordinator must still own when it attempts a durable advance. */
    val expectedRevision: OperationRevision,
    val action: RecoveryAction,
    val automaticAllowed: Boolean,
    val blockReason: RecoveryBlockReason? = null,
) {
    init {
        require((action == RecoveryAction.RECOVERY_BLOCKED) == (blockReason != null)) {
            "Recovery block reason must exist exactly when action is RECOVERY_BLOCKED"
        }
        if (action == RecoveryAction.NO_ACTION || action == RecoveryAction.RECOVERY_BLOCKED) {
            require(!automaticAllowed) { "$action cannot authorize automatic remote work" }
        }
    }
}

/**
 * Pure cold-start recovery planner.
 *
 * It performs no I/O, owns no Android lifecycle object, opens no SSH connection and mutates no
 * OperationJournal state. Callers must obtain a fresh exact OperationRuntime lease and re-check
 * revision/CAS before executing a remote action from the returned plan.
 *
 * Unknown/user-stop/reboot provenance deliberately fail conservative: unfinished work may be
 * inspected only through a later user-allowed read-only reconciliation path, never blind replay.
 */
object ColdStartRecoveryPlanPolicy {
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

    fun plan(input: RecoveryPlanInput): ColdStartRecoveryPlan {
        val snapshot = input.current.snapshot
        val identity = PlanIdentity(
            operationId = snapshot.operationId,
            target = snapshot.target,
            expectedRevision = input.current.revision,
        )

        when (input.durabilityValidation) {
            OperationDurabilityValidation.Valid -> Unit
            is OperationDurabilityValidation.Corrupt -> {
                return identity.blocked(RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT)
            }
        }

        input.prerequisiteBlock?.let { return identity.blocked(it) }

        if (snapshot.status in terminalStatuses || snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return identity.plan(
                action = RecoveryAction.NO_ACTION,
                automaticAllowed = false,
            )
        }

        // Log snapshots and update preflight are explicit requests, including after proven process death.
        if (snapshot.type in setOf(OperationType.SERVICE_LOG_READ, OperationType.UPDATE_PREFLIGHT, OperationType.RESTORE_COMPATIBILITY)) return identity.plan(
            action = if (snapshot.checkpoint.semantics == CheckpointSemantics.READ_ONLY)
                RecoveryAction.RECONNECT_EXACT_OWNER else RecoveryAction.NO_ACTION,
            automaticAllowed = false,
        )

        if (snapshot.type in setOf(OperationType.DATABASE_BACKUP, OperationType.INSTALLATION_BACKUP, OperationType.INSTALLATION_RESTORE_CHECK, OperationType.WORKING_DATABASE_RESTORE, OperationType.RESTORED_PANEL_START, OperationType.KNOWN_FILE_RESTORE)) return identity.plan(
            action = if (snapshot.checkpoint.semantics in unsafeCheckpointSemantics) RecoveryAction.RECONCILE_READ_ONLY
                else RecoveryAction.RECONNECT_EXACT_OWNER,
            automaticAllowed = false,
        )

        val reconciliationRequired =
            snapshot.status == OperationStatus.RECONCILIATION_REQUIRED ||
                snapshot.checkpoint.semantics in unsafeCheckpointSemantics

        return when (input.exitProvenance) {
            RecoveryExitProvenance.PROCESS_DEATH,
            RecoveryExitProvenance.SYSTEM_STOP,
            -> identity.plan(
                action = if (reconciliationRequired) {
                    RecoveryAction.RECONCILE_READ_ONLY
                } else {
                    RecoveryAction.RECONNECT_EXACT_OWNER
                },
                automaticAllowed = true,
            )

            RecoveryExitProvenance.USER_REQUESTED_STOP,
            RecoveryExitProvenance.DEVICE_REBOOT,
            -> identity.plan(
                action = RecoveryAction.RECONCILE_READ_ONLY,
                automaticAllowed = false,
            )

            RecoveryExitProvenance.UNKNOWN -> identity.plan(
                action = if (reconciliationRequired) {
                    RecoveryAction.RECONCILE_READ_ONLY
                } else {
                    RecoveryAction.RECONNECT_EXACT_OWNER
                },
                automaticAllowed = false,
            )
        }
    }

    private data class PlanIdentity(
        val operationId: OperationId,
        val target: OperationTarget,
        val expectedRevision: OperationRevision,
    ) {
        fun blocked(reason: RecoveryBlockReason): ColdStartRecoveryPlan = ColdStartRecoveryPlan(
            operationId = operationId,
            target = target,
            expectedRevision = expectedRevision,
            action = RecoveryAction.RECOVERY_BLOCKED,
            automaticAllowed = false,
            blockReason = reason,
        )

        fun plan(
            action: RecoveryAction,
            automaticAllowed: Boolean,
        ): ColdStartRecoveryPlan = ColdStartRecoveryPlan(
            operationId = operationId,
            target = target,
            expectedRevision = expectedRevision,
            action = action,
            automaticAllowed = automaticAllowed,
        )
    }
}
