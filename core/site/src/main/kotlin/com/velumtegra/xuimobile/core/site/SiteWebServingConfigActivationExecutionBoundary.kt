package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.60 grants only exact nginx config activation after Phase 11.59 proved the same desired
 * bytes can be staged and syntax-validated in isolation. The activation plan recreates the exact
 * operation-owned staging file, verifies its SHA-256, atomically promotes it to the exact *.conf
 * path, verifies the final SHA and runs read-only nginx syntax validation. nginx reload remains
 * unauthorized. Failed/uncertain activation is reconciliation-only and may delete only files whose
 * SHA-256 is exactly the reviewed desired config.
 */
object SiteWebServingConfigActivationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalStagingPath = Regex("^/etc/nginx/conf\\.d/\\.[A-Za-z0-9._-]+\\.stage$")

    private val exactSteps = listOf(
        SiteWebServingConfigActivationAuthorizedStep.REVALIDATE_EXACT_BASELINE,
        SiteWebServingConfigActivationAuthorizedStep.DURABLE_PREACTIVATION_CHECKPOINT,
        SiteWebServingConfigActivationAuthorizedStep.WRITE_OPERATION_OWNED_STAGING_CONFIG,
        SiteWebServingConfigActivationAuthorizedStep.VERIFY_STAGING_CONFIG_SHA256,
        SiteWebServingConfigActivationAuthorizedStep.ATOMIC_ACTIVATE_EXACT_CONFIG_PATH,
        SiteWebServingConfigActivationAuthorizedStep.VERIFY_EXACT_CONFIG_SHA256,
        SiteWebServingConfigActivationAuthorizedStep.VALIDATE_NGINX_SYNTAX_WITH_EXACT_CONFIG,
        SiteWebServingConfigActivationAuthorizedStep.VERIFY_STAGING_PATH_ABSENT,
        SiteWebServingConfigActivationAuthorizedStep.VERIFY_LISTENER_STILL_FREE,
    )

    private val exactCounteractions = listOf(
        SiteWebServingConfigActivationCounteraction.DELETE_OPERATION_OWNED_STAGING_ONLY_IF_DESIRED_SHA_MATCHES,
        SiteWebServingConfigActivationCounteraction.DELETE_EXACT_CONFIG_ONLY_IF_DESIRED_SHA_MATCHES,
        SiteWebServingConfigActivationCounteraction.READ_ONLY_RECONCILIATION_TO_ABSENT_AFTER_UNCERTAIN_DISPATCH,
    )

    fun prepare(
        mutationPreparation: SiteWebServingConfigMutationPreparation,
        stagingSyntaxPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ): SiteWebServingConfigActivationExecutionPlan {
        SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
            stagingSyntaxPlan,
            mutationPreparation,
            publicationPlan,
            readOnlyPreflight,
        )
        require(stagingSyntaxPlan.stagingConfigWriteAuthorized)
        require(stagingSyntaxPlan.isolatedNginxSyntaxValidationAuthorized)
        require(!stagingSyntaxPlan.exactConfigActivationAuthorized)
        require(!stagingSyntaxPlan.webServerReloadAuthorized)
        require(mutationPreparation.rollbackBaseline == SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT)

        val base = SiteWebServingConfigActivationExecutionPlan(
            contractVersion = CONTRACT_VERSION,
            mutationTransactionId = mutationPreparation.mutationTransactionId,
            mutationPreparationSha256 = mutationPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = stagingSyntaxPlan.executionPlanSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            configPath = publicationPlan.configPath,
            stagingConfigPath = mutationPreparation.stagingConfigPath,
            desiredConfigSha256 = publicationPlan.desiredConfigSha256,
            rollbackBaseline = SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresSuccessfulStagingSyntaxProof = true,
            requiresDurablePreactivationCheckpoint = true,
            stagingConfigWriteAuthorized = true,
            exactConfigActivationAuthorized = true,
            nginxSyntaxValidationAuthorized = true,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            activationPlanSha256 = "",
        )
        return base.copy(activationPlanSha256 = digest(base)).also {
            validateAgainst(it, mutationPreparation, stagingSyntaxPlan, publicationPlan, readOnlyPreflight)
        }
    }

    fun validate(plan: SiteWebServingConfigActivationExecutionPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.mutationPreparationSha256))
        require(sha256.matches(plan.stagingSyntaxExecutionPlanSha256))
        require(sha256.matches(plan.publicationPlanSha256))
        require(sha256.matches(plan.readOnlyPreflightSha256))
        require(sha256.matches(plan.desiredConfigSha256))
        require(sha256.matches(plan.activationPlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.configPath) == plan.configPath)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.stagingConfigPath) == plan.stagingConfigPath)
        require(plan.configPath.startsWith("/etc/nginx/conf.d/") && plan.configPath.endsWith(".conf"))
        require(canonicalStagingPath.matches(plan.stagingConfigPath))
        require(plan.configPath != plan.stagingConfigPath)
        require(plan.rollbackBaseline == SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.requiresSuccessfulStagingSyntaxProof)
        require(plan.requiresDurablePreactivationCheckpoint)
        require(plan.stagingConfigWriteAuthorized)
        require(plan.exactConfigActivationAuthorized)
        require(plan.nginxSyntaxValidationAuthorized)
        require(!plan.webServerReloadAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.activationPlanSha256 == digest(plan.copy(activationPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingConfigActivationExecutionPlan,
        mutationPreparation: SiteWebServingConfigMutationPreparation,
        stagingSyntaxPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ) {
        validate(plan)
        SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
            stagingSyntaxPlan,
            mutationPreparation,
            publicationPlan,
            readOnlyPreflight,
        )
        require(plan.mutationTransactionId == mutationPreparation.mutationTransactionId)
        require(plan.mutationPreparationSha256 == mutationPreparation.mutationPreparationSha256)
        require(plan.stagingSyntaxExecutionPlanSha256 == stagingSyntaxPlan.executionPlanSha256)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.configPath == mutationPreparation.configPath && plan.configPath == publicationPlan.configPath)
        require(plan.stagingConfigPath == mutationPreparation.stagingConfigPath)
        require(plan.desiredConfigSha256 == mutationPreparation.desiredConfigSha256)
        require(plan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
    }

    private fun digest(plan: SiteWebServingConfigActivationExecutionPlan): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("transaction=").append(plan.mutationTransactionId).append('\n')
            append("mutationPreparation=").append(plan.mutationPreparationSha256).append('\n')
            append("stagingSyntaxPlan=").append(plan.stagingSyntaxExecutionPlanSha256).append('\n')
            append("publicationPlan=").append(plan.publicationPlanSha256).append('\n')
            append("preflight=").append(plan.readOnlyPreflightSha256).append('\n')
            append("host=").append(plan.remoteHostIdentity).append('\n')
            append("config=").append(plan.configPath).append('\n')
            append("staging=").append(plan.stagingConfigPath).append('\n')
            append("desiredSha=").append(plan.desiredConfigSha256).append('\n')
            append("rollbackBaseline=").append(plan.rollbackBaseline.name).append('\n')
            append("steps=").append(plan.steps.joinToString(",") { it.name }).append('\n')
            append("counteractions=").append(plan.counteractions.joinToString(",") { it.name }).append('\n')
            append("requiresSuccessfulStagingSyntaxProof=").append(plan.requiresSuccessfulStagingSyntaxProof).append('\n')
            append("requiresDurablePreactivationCheckpoint=").append(plan.requiresDurablePreactivationCheckpoint).append('\n')
            append("stagingWrite=").append(plan.stagingConfigWriteAuthorized).append('\n')
            append("activation=").append(plan.exactConfigActivationAuthorized).append('\n')
            append("syntaxValidation=").append(plan.nginxSyntaxValidationAuthorized).append('\n')
            append("reload=").append(plan.webServerReloadAuthorized).append('\n')
            append("dns=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewall=").append(plan.firewallMutationAuthorized).append('\n')
            append("package=").append(plan.packageInstallAuthorized).append('\n')
            append("retry=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
