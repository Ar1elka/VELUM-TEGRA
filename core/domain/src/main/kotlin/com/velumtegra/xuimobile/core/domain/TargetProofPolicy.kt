package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.InstallationProof
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.time.Instant

/** Only this type may enter a mutating use-case. */
class VerifiedInstallationTarget internal constructor(
    val operationTarget: OperationTarget.InstallationTarget,
    val proof: InstallationProof,
)

sealed interface TargetVerificationResult {
    data class Verified(val target: VerifiedInstallationTarget) : TargetVerificationResult
    data class Rejected(val reason: String) : TargetVerificationResult
}

object TargetProofPolicy {
    fun verifyKnownInstallation(
        installation: XuiInstallation,
        access: ServerAccess,
        proof: InstallationProof,
        now: Instant,
    ): TargetVerificationResult {
        if (access.serverId != installation.serverId) {
            return TargetVerificationResult.Rejected("Access belongs to a different server")
        }
        if (proof.installationId != installation.id) {
            return TargetVerificationResult.Rejected("Proof belongs to a different installation")
        }
        if (proof.serverId != installation.serverId) {
            return TargetVerificationResult.Rejected("Proof belongs to a different server")
        }
        if (proof.serverAccessId != access.id) {
            return TargetVerificationResult.Rejected("Proof was observed through a different access path")
        }
        if (proof.observedIdentity != installation.identity) {
            return TargetVerificationResult.Rejected("Observed installation identity does not match")
        }
        if (now.isAfter(proof.validUntil)) {
            return TargetVerificationResult.Rejected("Target proof is stale")
        }

        return TargetVerificationResult.Verified(
            VerifiedInstallationTarget(
                operationTarget = OperationTarget.InstallationTarget(
                    serverId = installation.serverId,
                    serverAccessId = access.id,
                    installationId = installation.id,
                ),
                proof = proof,
            ),
        )
    }
}
