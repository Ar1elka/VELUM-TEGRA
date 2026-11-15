package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.59 grants only the first bounded web-server config write capability.
 *
 * The exact production *.conf path remains untouched. One operation-owned staging file and one
 * operation-owned nginx validation wrapper may be written, verified, syntax-tested and removed.
 * A durable replay/checkpoint record is mandatory before the first write. Exact config activation,
 * nginx reload and every unrelated mutation class remain unauthorized.
 */
object SiteWebServingConfigStagingSyntaxExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalPathToken = Regex("^/etc/nginx/conf\\.d/\\.[A-Za-z0-9._-]+$")

    private val exactSteps = listOf(
        SiteWebServingConfigStagingSyntaxAuthorizedStep.REVALIDATE_EXACT_BASELINE,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.DURABLE_BASELINE_CHECKPOINT,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.WRITE_OPERATION_OWNED_STAGING_CONFIG,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_STAGING_CONFIG_SHA256,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.WRITE_OPERATION_OWNED_VALIDATION_CONFIG,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_VALIDATION_CONFIG_SHA256,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.VALIDATE_NGINX_SYNTAX_AGAINST_STAGING,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.DELETE_OPERATION_OWNED_VALIDATION_CONFIG,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.DELETE_OPERATION_OWNED_STAGING_CONFIG,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_EXACT_CONFIG_STILL_ABSENT,
        SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_LISTENER_STILL_FREE,
    )

    private val exactCounteractions = listOf(
        SiteWebServingConfigStagingSyntaxCounteraction.DELETE_OPERATION_OWNED_VALIDATION_CONFIG_ONLY,
        SiteWebServingConfigStagingSyntaxCounteraction.DELETE_OPERATION_OWNED_STAGING_CONFIG_ONLY,
        SiteWebServingConfigStagingSyntaxCounteraction.READ_ONLY_RECONCILIATION_AFTER_UNCERTAIN_DISPATCH,
    )

    fun prepare(
        preparation: SiteWebServingConfigMutationPreparation,
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ): SiteWebServingConfigStagingSyntaxExecutionPlan {
        SiteWebServingConfigMutationPreparationBoundary.validateAgainst(
            preparation = preparation,
            plan = publicationPlan,
            preflight = readOnlyPreflight,
        )
        require(!preparation.configMutationAuthorized && !preparation.webServerReloadAuthorized)
        require(preparation.rollbackBaseline == SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT)
        require(preparation.stagingConfigPath.endsWith(".stage"))
        require(!preparation.stagingConfigPath.endsWith(".conf"))

        val validationPath = validationConfigPath(preparation)
        val validationPidPath = "/tmp/velum-tegra-nginx-test-${preparation.mutationPreparationSha256.take(20)}.pid"
        val validationConfig = renderValidationConfig(
            stagingConfigPath = preparation.stagingConfigPath,
            pidPath = validationPidPath,
        )
        val validationSha = SiteBundleDigest.sha256(validationConfig.encodeToByteArray())
        val base = SiteWebServingConfigStagingSyntaxExecutionPlan(
            contractVersion = CONTRACT_VERSION,
            mutationTransactionId = preparation.mutationTransactionId,
            mutationPreparationSha256 = preparation.mutationPreparationSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            configPath = publicationPlan.configPath,
            stagingConfigPath = preparation.stagingConfigPath,
            validationConfigPath = validationPath,
            validationPidPath = validationPidPath,
            desiredConfigSha256 = publicationPlan.desiredConfigSha256,
            validationConfigUtf8 = validationConfig,
            validationConfigSha256 = validationSha,
            rollbackBaseline = SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresDurableBaselineCheckpointBeforeFirstWrite = true,
            stagingConfigWriteAuthorized = true,
            validationConfigWriteAuthorized = true,
            isolatedNginxSyntaxValidationAuthorized = true,
            exactConfigActivationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            executionPlanSha256 = "",
        )
        return base.copy(executionPlanSha256 = digest(base)).also {
            validateAgainst(it, preparation, publicationPlan, readOnlyPreflight)
        }
    }

    fun validate(plan: SiteWebServingConfigStagingSyntaxExecutionPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.mutationPreparationSha256))
        require(sha256.matches(plan.publicationPlanSha256))
        require(sha256.matches(plan.readOnlyPreflightSha256))
        require(sha256.matches(plan.desiredConfigSha256))
        require(sha256.matches(plan.validationConfigSha256))
        require(sha256.matches(plan.executionPlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.configPath) == plan.configPath)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.stagingConfigPath) == plan.stagingConfigPath)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.validationConfigPath) == plan.validationConfigPath)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.validationPidPath) == plan.validationPidPath)
        require(plan.configPath.startsWith("/etc/nginx/conf.d/") && plan.configPath.endsWith(".conf"))
        require(canonicalPathToken.matches(plan.stagingConfigPath))
        require(canonicalPathToken.matches(plan.validationConfigPath))
        require(plan.stagingConfigPath.endsWith(".stage") && !plan.stagingConfigPath.endsWith(".conf"))
        require(plan.validationConfigPath.endsWith(".validate") && !plan.validationConfigPath.endsWith(".conf"))
        require(plan.stagingConfigPath != plan.validationConfigPath)
        require(plan.configPath != plan.stagingConfigPath && plan.configPath != plan.validationConfigPath)
        require(plan.validationPidPath.startsWith("/tmp/velum-tegra-nginx-test-") && plan.validationPidPath.endsWith(".pid"))
        require(plan.rollbackBaseline == SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.requiresDurableBaselineCheckpointBeforeFirstWrite)
        require(plan.stagingConfigWriteAuthorized)
        require(plan.validationConfigWriteAuthorized)
        require(plan.isolatedNginxSyntaxValidationAuthorized)
        require(!plan.exactConfigActivationAuthorized)
        require(!plan.webServerReloadAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.validationConfigUtf8 == renderValidationConfig(plan.stagingConfigPath, plan.validationPidPath))
        require(plan.validationConfigSha256 == SiteBundleDigest.sha256(plan.validationConfigUtf8.encodeToByteArray()))
        require(plan.executionPlanSha256 == digest(plan.copy(executionPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        preparation: SiteWebServingConfigMutationPreparation,
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ) {
        validate(plan)
        SiteWebServingConfigMutationPreparationBoundary.validateAgainst(preparation, publicationPlan, readOnlyPreflight)
        require(plan.mutationTransactionId == preparation.mutationTransactionId)
        require(plan.mutationPreparationSha256 == preparation.mutationPreparationSha256)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.configPath == preparation.configPath && plan.configPath == publicationPlan.configPath)
        require(plan.stagingConfigPath == preparation.stagingConfigPath)
        require(plan.desiredConfigSha256 == preparation.desiredConfigSha256)
        require(plan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
    }

    private fun validationConfigPath(preparation: SiteWebServingConfigMutationPreparation): String {
        val baseName = preparation.configPath.substringAfterLast('/').removeSuffix(".conf")
        return "/etc/nginx/conf.d/.$baseName.${preparation.mutationPreparationSha256.take(16)}.validate"
    }

    private fun renderValidationConfig(stagingConfigPath: String, pidPath: String): String = buildString {
        append("worker_processes 1;\n")
        append("pid ").append(pidPath).append(";\n")
        append("error_log stderr notice;\n")
        append("events { worker_connections 16; }\n")
        append("http {\n")
        append("    include ").append(stagingConfigPath).append(";\n")
        append("}\n")
    }

    private fun digest(plan: SiteWebServingConfigStagingSyntaxExecutionPlan): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("mutationTransactionId=").append(plan.mutationTransactionId).append('\n')
            append("mutationPreparationSha256=").append(plan.mutationPreparationSha256).append('\n')
            append("publicationPlanSha256=").append(plan.publicationPlanSha256).append('\n')
            append("readOnlyPreflightSha256=").append(plan.readOnlyPreflightSha256).append('\n')
            append("remoteHostIdentity=").append(plan.remoteHostIdentity).append('\n')
            append("configPath=").append(plan.configPath).append('\n')
            append("stagingConfigPath=").append(plan.stagingConfigPath).append('\n')
            append("validationConfigPath=").append(plan.validationConfigPath).append('\n')
            append("validationPidPath=").append(plan.validationPidPath).append('\n')
            append("desiredConfigSha256=").append(plan.desiredConfigSha256).append('\n')
            append("validationConfigSha256=").append(plan.validationConfigSha256).append('\n')
            append("rollbackBaseline=").append(plan.rollbackBaseline.name).append('\n')
            plan.steps.forEach { append("step=").append(it.name).append('\n') }
            plan.counteractions.forEach { append("counteraction=").append(it.name).append('\n') }
            append("requiresDurableBaselineCheckpointBeforeFirstWrite=")
                .append(plan.requiresDurableBaselineCheckpointBeforeFirstWrite).append('\n')
            append("stagingConfigWriteAuthorized=").append(plan.stagingConfigWriteAuthorized).append('\n')
            append("validationConfigWriteAuthorized=").append(plan.validationConfigWriteAuthorized).append('\n')
            append("isolatedNginxSyntaxValidationAuthorized=")
                .append(plan.isolatedNginxSyntaxValidationAuthorized).append('\n')
            append("exactConfigActivationAuthorized=").append(plan.exactConfigActivationAuthorized).append('\n')
            append("webServerReloadAuthorized=").append(plan.webServerReloadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(plan.firewallMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(plan.packageInstallAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
