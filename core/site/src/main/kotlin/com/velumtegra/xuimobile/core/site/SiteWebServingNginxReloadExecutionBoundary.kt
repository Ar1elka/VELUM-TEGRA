package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.61 grants exactly one nginx reload after Phase 11.60 has produced an exact activated
 * config proof. No config write is authorized here. Before the reload the exact config SHA, nginx
 * syntax and a still-free target listener must be revalidated; a durable replay fence is consumed
 * immediately before the reload. Uncertain dispatch is reconciliation-only and never retried.
 */
object SiteWebServingNginxReloadExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val exactSteps = listOf(
        SiteWebServingNginxReloadAuthorizedStep.REVALIDATE_EXACT_CONFIG_SHA256,
        SiteWebServingNginxReloadAuthorizedStep.REVALIDATE_NGINX_SYNTAX,
        SiteWebServingNginxReloadAuthorizedStep.VERIFY_LISTENER_STILL_FREE_BEFORE_RELOAD,
        SiteWebServingNginxReloadAuthorizedStep.DURABLE_PRE_RELOAD_CHECKPOINT,
        SiteWebServingNginxReloadAuthorizedStep.RELOAD_NGINX_ONCE,
        SiteWebServingNginxReloadAuthorizedStep.VERIFY_EXACT_CONFIG_SHA256_AFTER_RELOAD,
        SiteWebServingNginxReloadAuthorizedStep.VERIFY_NGINX_MASTER_STILL_RUNNING,
        SiteWebServingNginxReloadAuthorizedStep.VERIFY_EXPECTED_LISTENER_LIVE,
    )
    private val exactCounteractions = listOf(
        SiteWebServingNginxReloadCounteraction.READ_ONLY_RECONCILIATION_AFTER_UNCERTAIN_RELOAD,
        SiteWebServingNginxReloadCounteraction.EXPLICIT_SHA_BOUND_ROLLBACK_REQUIRES_SEPARATE_AUTHORITY,
    )

    fun prepare(
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
    ): SiteWebServingNginxReloadExecutionPlan {
        SiteWebServingConfigActivationExecutionBoundary.validate(activationPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(activationPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(activationPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(activationPlan.configPath == publicationPlan.configPath)
        require(activationPlan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(activationPlan.exactConfigActivationAuthorized)
        require(activationPlan.nginxSyntaxValidationAuthorized)
        require(!activationPlan.webServerReloadAuthorized)

        val base = SiteWebServingNginxReloadExecutionPlan(
            contractVersion = CONTRACT_VERSION,
            activationPlanSha256 = activationPlan.activationPlanSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            configPath = publicationPlan.configPath,
            desiredConfigSha256 = publicationPlan.desiredConfigSha256,
            expectedListenerPort = publicationPlan.port,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresSuccessfulActivationProof = true,
            requiresExactConfigShaBeforeReload = true,
            requiresSuccessfulNginxSyntaxBeforeReload = true,
            requiresListenerFreeBeforeReload = true,
            requiresDurablePreReloadCheckpoint = true,
            reloadNginxOnceAuthorized = true,
            requiresExactConfigShaAfterReload = true,
            requiresExpectedListenerLiveAfterReload = true,
            configMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            reloadPlanSha256 = "",
        )
        return base.copy(reloadPlanSha256 = digest(base)).also(::validate)
    }

    fun validate(plan: SiteWebServingNginxReloadExecutionPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.activationPlanSha256))
        require(sha256.matches(plan.publicationPlanSha256))
        require(sha256.matches(plan.desiredConfigSha256))
        require(sha256.matches(plan.reloadPlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.configPath) == plan.configPath)
        require(plan.configPath.startsWith("/etc/nginx/conf.d/") && plan.configPath.endsWith(".conf"))
        require(plan.expectedListenerPort in 1..65535)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.requiresSuccessfulActivationProof)
        require(plan.requiresExactConfigShaBeforeReload)
        require(plan.requiresSuccessfulNginxSyntaxBeforeReload)
        require(plan.requiresListenerFreeBeforeReload)
        require(plan.requiresDurablePreReloadCheckpoint)
        require(plan.reloadNginxOnceAuthorized)
        require(plan.requiresExactConfigShaAfterReload)
        require(plan.requiresExpectedListenerLiveAfterReload)
        require(!plan.configMutationAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.reloadPlanSha256 == digest(plan.copy(reloadPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingNginxReloadExecutionPlan,
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
    ) {
        validate(plan)
        SiteWebServingConfigActivationExecutionBoundary.validate(activationPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(plan.activationPlanSha256 == activationPlan.activationPlanSha256)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.configPath == publicationPlan.configPath)
        require(plan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(plan.expectedListenerPort == publicationPlan.port)
    }

    private fun digest(plan: SiteWebServingNginxReloadExecutionPlan): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("activationPlan=").append(plan.activationPlanSha256).append('\n')
            append("publicationPlan=").append(plan.publicationPlanSha256).append('\n')
            append("host=").append(plan.remoteHostIdentity).append('\n')
            append("config=").append(plan.configPath).append('\n')
            append("desiredSha=").append(plan.desiredConfigSha256).append('\n')
            append("port=").append(plan.expectedListenerPort).append('\n')
            append("steps=").append(plan.steps.joinToString(",") { it.name }).append('\n')
            append("counteractions=").append(plan.counteractions.joinToString(",") { it.name }).append('\n')
            append("requiresSuccessfulActivationProof=").append(plan.requiresSuccessfulActivationProof).append('\n')
            append("requiresExactConfigShaBeforeReload=").append(plan.requiresExactConfigShaBeforeReload).append('\n')
            append("requiresSuccessfulNginxSyntaxBeforeReload=").append(plan.requiresSuccessfulNginxSyntaxBeforeReload).append('\n')
            append("requiresListenerFreeBeforeReload=").append(plan.requiresListenerFreeBeforeReload).append('\n')
            append("requiresDurablePreReloadCheckpoint=").append(plan.requiresDurablePreReloadCheckpoint).append('\n')
            append("reloadOnce=").append(plan.reloadNginxOnceAuthorized).append('\n')
            append("requiresExactConfigShaAfterReload=").append(plan.requiresExactConfigShaAfterReload).append('\n')
            append("requiresExpectedListenerLiveAfterReload=").append(plan.requiresExpectedListenerLiveAfterReload).append('\n')
            append("configMutation=").append(plan.configMutationAuthorized).append('\n')
            append("dns=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewall=").append(plan.firewallMutationAuthorized).append('\n')
            append("packageInstall=").append(plan.packageInstallAuthorized).append('\n')
            append("automaticRetry=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
