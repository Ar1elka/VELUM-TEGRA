package com.velumtegra.xuimobile.core.site

data class SiteProductionDeploymentFixtureRuntimeBinding(
    val fixtureId: String,
    val runtimeIdentity: SiteProductionDeploymentRuntimeIdentity,
    val fixtureOnly: Boolean,
    val productionTransportEnabled: Boolean,
    val realVpsAccessAllowed: Boolean,
)

interface SiteProductionDeploymentFixtureRuntime : SiteDeploymentRemoteRuntime {
    val fixtureBinding: SiteProductionDeploymentFixtureRuntimeBinding
}

fun interface SiteProductionDeploymentCoordinatorInvocationUsePort {
    /**
     * Atomically records the first coordinator handoff for [invocationAuthorizationSha256].
     * False means the authorization was already handed off or the replay fence cannot prove first use.
     */
    fun consumeOnce(invocationAuthorizationSha256: String): Boolean
}

data class SiteProductionDeploymentFixtureInvocationRequest(
    val invocationAuthorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
    val runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
    val invokedAtEpochMillis: Long,
)

data class SiteProductionDeploymentFixtureInvocationReceipt(
    val fixtureId: String,
    val coordinatorInvocationId: String,
    val invocationAuthorizationSha256: String,
    val invokedAtEpochMillis: Long,
    val fixtureOnly: Boolean,
    val productionTransportEnabled: Boolean,
    val realVpsAccessAllowed: Boolean,
    val coordinatorResult: SiteDeploymentCoordinatorResult,
)
