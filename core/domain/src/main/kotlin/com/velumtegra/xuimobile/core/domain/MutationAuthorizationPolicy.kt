package com.velumtegra.xuimobile.core.domain

/**
 * Mutating use-cases accept VerifiedInstallationTarget, not ids/selection/global state.
 * Possession of this value means exact target proof already passed TargetProofPolicy.
 */
object MutationAuthorizationPolicy {
    fun mayEnterMutation(target: VerifiedInstallationTarget): Boolean =
        target.proof.installationId == target.operationTarget.installationId &&
            target.proof.serverId == target.operationTarget.serverId &&
            target.proof.serverAccessId == target.operationTarget.serverAccessId
}
