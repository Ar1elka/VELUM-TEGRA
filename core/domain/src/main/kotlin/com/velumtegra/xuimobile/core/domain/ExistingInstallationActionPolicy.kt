package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionPhase
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionResult
import com.velumtegra.xuimobile.core.model.ExistingInstallationUncertaintyKind
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.time.Instant

/**
 * Process-local authorization for one exact Phase 9 action. This value is deliberately created
 * only after a fresh VerifiedInstallationTarget is rebound to one durable OperationSnapshot.
 */
class VerifiedExistingInstallationAction internal constructor(
    val operationId: OperationId,
    val operationRevision: OperationRevision,
    val action: OperationType,
    val operationTarget: OperationTarget.InstallationTarget,
    val verifiedTarget: VerifiedInstallationTarget,
    val ownership: InstallationOwnership,
)

sealed interface ExistingInstallationActionAuthorizationResult {
    data class Verified(
        val authorization: VerifiedExistingInstallationAction,
    ) : ExistingInstallationActionAuthorizationResult

    data class Rejected(
        val reason: String,
    ) : ExistingInstallationActionAuthorizationResult
}

/** Exact target + action + ownership binding for Phase 9. No command execution exists here. */
object ExistingInstallationActionAuthorizationPolicy {
    private val allowedActions = setOf(
        OperationType.RESTART,
        OperationType.RECOVERY,
        OperationType.UNINSTALL,
        OperationType.REINSTALL,
    )

    private val preDispatchStatuses = setOf(
        OperationStatus.PENDING,
        OperationStatus.RUNNING,
    )

    fun verify(
        operation: VersionedOperationSnapshot,
        installation: XuiInstallation,
        verifiedTarget: VerifiedInstallationTarget,
        now: Instant,
    ): ExistingInstallationActionAuthorizationResult {
        val snapshot = operation.snapshot
        if (snapshot.type !in allowedActions) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Operation type is not a Phase 9 existing-installation action",
            )
        }
        val operationTarget = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationActionAuthorizationResult.Rejected(
                "Phase 9 action requires an exact InstallationTarget",
            )
        if (snapshot.status !in preDispatchStatuses) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Phase 9 action authorization requires a pre-dispatch operation status",
            )
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Phase 9 action authorization requires MUTATION_NOT_STARTED",
            )
        }
        if (operationTarget != verifiedTarget.operationTarget) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Verified target does not match the durable operation target",
            )
        }
        if (installation.id != operationTarget.installationId || installation.serverId != operationTarget.serverId) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Installation does not match the durable operation target",
            )
        }
        if (!MutationAuthorizationPolicy.mayEnterMutation(verifiedTarget)) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Verified target identity is internally inconsistent",
            )
        }
        val proof = verifiedTarget.proof
        if (proof.installationId != installation.id || proof.serverId != installation.serverId) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Proof does not belong to the exact installation",
            )
        }
        if (proof.serverAccessId != operationTarget.serverAccessId) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Proof was observed through a different access path",
            )
        }
        if (proof.observedIdentity != installation.identity) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Observed installation identity no longer matches",
            )
        }
        if (now.isBefore(proof.observedAt)) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Installation proof observation is in the future",
            )
        }
        if (now.isAfter(proof.validUntil)) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "Installation proof is stale",
            )
        }
        if (snapshot.type == OperationType.REINSTALL && installation.ownership == InstallationOwnership.ADOPTED) {
            return ExistingInstallationActionAuthorizationResult.Rejected(
                "ADOPTED reinstall is not authorized without an accepted takeover policy",
            )
        }

        return ExistingInstallationActionAuthorizationResult.Verified(
            VerifiedExistingInstallationAction(
                operationId = snapshot.operationId,
                operationRevision = operation.revision,
                action = snapshot.type,
                operationTarget = operationTarget,
                verifiedTarget = verifiedTarget,
                ownership = installation.ownership,
            ),
        )
    }
}

/** Pure feature-state mapping. It cannot advance a journal or dispatch a remote action. */
object ExistingInstallationActionStatePolicy {
    fun checkpointForPhase(phase: ExistingInstallationActionPhase): CheckpointSemantics = when (phase) {
        ExistingInstallationActionPhase.READ_ONLY_DIAGNOSIS -> CheckpointSemantics.READ_ONLY
        ExistingInstallationActionPhase.PREPARING -> CheckpointSemantics.MUTATION_NOT_STARTED
        ExistingInstallationActionPhase.MUTATION_DISPATCHED -> CheckpointSemantics.MUTATION_IN_FLIGHT
        ExistingInstallationActionPhase.MUTATION_VERIFIED -> CheckpointSemantics.MUTATION_VERIFIED
        ExistingInstallationActionPhase.RESTART_DISPATCHED -> CheckpointSemantics.RESTART_IN_FLIGHT
        ExistingInstallationActionPhase.POST_VERIFY -> CheckpointSemantics.POST_VERIFY_REQUIRED
        ExistingInstallationActionPhase.COMMIT_VERIFIED -> CheckpointSemantics.COMMIT_VERIFIED
    }

    fun checkpointForResult(result: ExistingInstallationActionResult): CheckpointSemantics = when (result) {
        is ExistingInstallationActionResult.RejectedBeforeDispatch,
        is ExistingInstallationActionResult.CancelledBeforeDispatch,
        is ExistingInstallationActionResult.CommittedSuccess -> CheckpointSemantics.TERMINAL

        is ExistingInstallationActionResult.ReconciliationRequired -> when (result.reason) {
            ExistingInstallationUncertaintyKind.MUTATION_MAY_HAVE_DISPATCHED ->
                CheckpointSemantics.MUTATION_IN_FLIGHT
            ExistingInstallationUncertaintyKind.RESTART_MAY_HAVE_DISPATCHED ->
                CheckpointSemantics.RESTART_IN_FLIGHT
            ExistingInstallationUncertaintyKind.POST_VERIFY_INCOMPLETE,
            ExistingInstallationUncertaintyKind.LOCAL_COMMIT_INCOMPLETE ->
                CheckpointSemantics.POST_VERIFY_REQUIRED
        }
    }
}
