package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.FreshInstallConflictState
import com.velumtegra.xuimobile.core.model.FreshInstallPreflightProof
import com.velumtegra.xuimobile.core.model.InstallerPhase
import com.velumtegra.xuimobile.core.model.InstallerResult
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/** Narrow authority for one exact fresh INSTALL operation only. */
class VerifiedFreshInstallTarget internal constructor(
    val operationId: OperationId,
    val operationTarget: OperationTarget.ServerTarget,
    val proof: FreshInstallPreflightProof,
    val managedInstallId: ManagedInstallId,
)

sealed interface FreshInstallVerificationResult {
    data class Verified(val target: VerifiedFreshInstallTarget) : FreshInstallVerificationResult
    data class Rejected(val reason: String) : FreshInstallVerificationResult
}

object FreshInstallAuthorizationPolicy {
    fun verify(
        operation: OperationSnapshot,
        proof: FreshInstallPreflightProof,
        now: Instant,
    ): FreshInstallVerificationResult {
        if (operation.type != OperationType.INSTALL) {
            return FreshInstallVerificationResult.Rejected("Fresh-install proof authorizes INSTALL only")
        }
        val target = operation.target as? OperationTarget.ServerTarget
            ?: return FreshInstallVerificationResult.Rejected("Fresh INSTALL requires an exact ServerTarget")
        if (operation.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return FreshInstallVerificationResult.Rejected("Fresh-install authorization requires a pre-dispatch checkpoint")
        }
        if (proof.scope.operationId != operation.operationId) {
            return FreshInstallVerificationResult.Rejected("Proof belongs to a different operation")
        }
        if (proof.scope.serverId != target.serverId) {
            return FreshInstallVerificationResult.Rejected("Proof belongs to a different server")
        }
        if (proof.scope.serverAccessId != target.serverAccessId) {
            return FreshInstallVerificationResult.Rejected("Proof was observed through a different access path")
        }
        if (proof.conflictState != FreshInstallConflictState.PROVEN_CLEAR) {
            return FreshInstallVerificationResult.Rejected("Fresh-install target is not proven clear")
        }
        if (now.isAfter(proof.validUntil)) {
            return FreshInstallVerificationResult.Rejected("Fresh-install proof is stale")
        }
        if (now.isBefore(proof.observedAt)) {
            return FreshInstallVerificationResult.Rejected("Fresh-install proof observation is in the future")
        }

        return FreshInstallVerificationResult.Verified(
            VerifiedFreshInstallTarget(
                operationId = operation.operationId,
                operationTarget = target,
                proof = proof,
                managedInstallId = ManagedInstallIdentityPolicy.forOperation(operation.operationId),
            ),
        )
    }
}

object InstallerCheckpointPolicy {
    fun forPhase(phase: InstallerPhase): CheckpointSemantics = when (phase) {
        InstallerPhase.PREPARING -> CheckpointSemantics.MUTATION_NOT_STARTED
        InstallerPhase.DOWNLOADING,
        InstallerPhase.INSTALLING -> CheckpointSemantics.MUTATION_IN_FLIGHT
        InstallerPhase.VERIFYING -> CheckpointSemantics.POST_VERIFY_REQUIRED
    }

    fun forResult(result: InstallerResult): CheckpointSemantics = when (result) {
        is InstallerResult.Success,
        is InstallerResult.Failed,
        is InstallerResult.CancelledBeforeDispatch -> CheckpointSemantics.TERMINAL
        is InstallerResult.ReconciliationRequired -> CheckpointSemantics.POST_VERIFY_REQUIRED
    }
}

/**
 * Stable, non-secret managed marker identity derived from durable OperationId only.
 * Version prefix leaves room for an explicit future marker-format migration.
 */
object ManagedInstallIdentityPolicy {
    private const val DOMAIN = "velum-tegra:managed-install:v1:"

    fun forOperation(operationId: OperationId): ManagedInstallId {
        require(operationId.value.isNotBlank()) { "OperationId must not be blank" }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest((DOMAIN + operationId.value).toByteArray(StandardCharsets.UTF_8))
            .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
        return ManagedInstallId("v1-${digest.take(32)}")
    }
}
