package com.velumtegra.xuimobile.core.site

/**
 * Pure preparation boundary immediately before the first web-server config mutation. It binds one
 * exact publication plan to one exact READY read-only preflight and derives a finite transaction
 * plus rollback/counteraction contract. It grants no network or mutation authority.
 */
object SiteWebServingConfigMutationPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    private val exactSteps = listOf(
        SiteWebServingConfigMutationPreparedStep.DURABLE_BASELINE_CHECKPOINT,
        SiteWebServingConfigMutationPreparedStep.WRITE_OPERATION_OWNED_STAGING_CONFIG,
        SiteWebServingConfigMutationPreparedStep.VERIFY_STAGING_CONFIG_SHA256,
        SiteWebServingConfigMutationPreparedStep.ATOMIC_ACTIVATE_EXACT_CONFIG_PATH,
        SiteWebServingConfigMutationPreparedStep.VALIDATE_NGINX_SYNTAX,
        SiteWebServingConfigMutationPreparedStep.DURABLE_PRE_RELOAD_CHECKPOINT,
        SiteWebServingConfigMutationPreparedStep.RELOAD_NGINX_ONCE,
        SiteWebServingConfigMutationPreparedStep.POST_SERVE_VERIFY,
    )
    private val exactCounteractions = listOf(
        SiteWebServingConfigMutationCounteraction.DELETE_OPERATION_OWNED_STAGING_ONLY,
        SiteWebServingConfigMutationCounteraction.DELETE_EXACT_CONFIG_ONLY_IF_DESIRED_SHA_MATCHES,
        SiteWebServingConfigMutationCounteraction.READ_ONLY_RECONCILIATION_AFTER_UNCERTAIN_RELOAD,
        SiteWebServingConfigMutationCounteraction.EXPLICIT_ROLLBACK_REMOVE_CONFIG_VALIDATE_RELOAD_POST_VERIFY,
    )

    fun prepare(request: SiteWebServingConfigMutationPreparationRequest): SiteWebServingConfigMutationPreparation {
        val plan = request.publicationPlan
        val preflight = request.readOnlyPreflight
        SiteWebServingPublicationPlanBoundary.validate(plan)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(preflight)
        require(transactionId.matches(request.mutationTransactionId)) {
            "Web-serving mutation transaction id must be a canonical 8..128 character identifier"
        }
        require(preflight.publicationPlanSha256 == plan.publicationPlanSha256) {
            "Read-only preflight belongs to a different publication plan"
        }
        require(preflight.status == SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY) {
            "Blocked read-only preflight cannot prepare config mutation"
        }
        require(preflight.checks.all { it.passed }) {
            "Every read-only preflight check must pass before config mutation preparation"
        }
        require(
            preflight.checks.any {
                it.code == SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT && it.passed
            },
        ) { "Exact config-path absence must be proven before config mutation preparation" }
        require(
            preflight.checks.any {
                it.code == SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE && it.passed
            },
        ) { "Exact live port must be proven free before config mutation preparation" }

        val stagingPath = stagingConfigPath(plan.configPath, request.mutationTransactionId, preflight.preflightSha256)
        val base = SiteWebServingConfigMutationPreparation(
            contractVersion = CONTRACT_VERSION,
            mutationTransactionId = request.mutationTransactionId,
            publicationPlanSha256 = plan.publicationPlanSha256,
            readOnlyPreflightSha256 = preflight.preflightSha256,
            remoteHostIdentity = plan.remoteHostIdentity,
            configPath = plan.configPath,
            stagingConfigPath = stagingPath,
            desiredConfigSha256 = plan.desiredConfigSha256,
            rollbackBaseline = SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresDurableBaselineCheckpointBeforeFirstWrite = true,
            requiresExactStagingShaVerification = true,
            requiresNginxSyntaxValidationBeforeReload = true,
            requiresDurablePreReloadCheckpoint = true,
            requiresPostServeVerification = true,
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            mutationPreparationSha256 = "",
        )
        return base.copy(mutationPreparationSha256 = digest(base)).also {
            validateAgainst(it, plan, preflight)
        }
    }

    fun validate(preparation: SiteWebServingConfigMutationPreparation) {
        require(preparation.contractVersion == CONTRACT_VERSION)
        require(transactionId.matches(preparation.mutationTransactionId))
        require(sha256.matches(preparation.publicationPlanSha256))
        require(sha256.matches(preparation.readOnlyPreflightSha256))
        require(sha256.matches(preparation.desiredConfigSha256))
        require(sha256.matches(preparation.mutationPreparationSha256))
        require(preparation.remoteHostIdentity.isNotBlank())
        require(SiteRemoteDeployPolicy.prepareTargetRoot(preparation.configPath) == preparation.configPath)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(preparation.stagingConfigPath) == preparation.stagingConfigPath)
        require(preparation.configPath.startsWith("/etc/nginx/conf.d/") && preparation.configPath.endsWith(".conf"))
        require(preparation.stagingConfigPath.startsWith("/etc/nginx/conf.d/"))
        require(!preparation.stagingConfigPath.endsWith(".conf")) {
            "Operation-owned staging config must not match nginx conf.d *.conf include"
        }
        require(preparation.stagingConfigPath != preparation.configPath)
        require(preparation.rollbackBaseline == SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT)
        require(preparation.steps == exactSteps)
        require(preparation.counteractions == exactCounteractions)
        require(preparation.requiresDurableBaselineCheckpointBeforeFirstWrite)
        require(preparation.requiresExactStagingShaVerification)
        require(preparation.requiresNginxSyntaxValidationBeforeReload)
        require(preparation.requiresDurablePreReloadCheckpoint)
        require(preparation.requiresPostServeVerification)
        require(!preparation.configMutationAuthorized)
        require(!preparation.webServerReloadAuthorized)
        require(!preparation.dnsMutationAuthorized)
        require(!preparation.firewallMutationAuthorized)
        require(!preparation.packageInstallAuthorized)
        require(!preparation.automaticRetryAuthorized)
        require(preparation.mutationPreparationSha256 == digest(preparation.copy(mutationPreparationSha256 = "")))
    }

    fun validateAgainst(
        preparation: SiteWebServingConfigMutationPreparation,
        plan: SiteWebServingPublicationPlan,
        preflight: SiteWebServingReadOnlyPreflightReport,
    ) {
        validate(preparation)
        SiteWebServingPublicationPlanBoundary.validate(plan)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(preflight)
        require(preparation.publicationPlanSha256 == plan.publicationPlanSha256)
        require(preparation.readOnlyPreflightSha256 == preflight.preflightSha256)
        require(preflight.publicationPlanSha256 == plan.publicationPlanSha256)
        require(preflight.status == SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY)
        require(preflight.checks.all { it.passed })
        require(preparation.remoteHostIdentity == plan.remoteHostIdentity)
        require(preparation.configPath == plan.configPath)
        require(preparation.desiredConfigSha256 == plan.desiredConfigSha256)
    }

    private fun stagingConfigPath(configPath: String, transactionId: String, preflightSha256: String): String {
        val baseName = configPath.substringAfterLast('/').removeSuffix(".conf")
        val identitySha = SiteBundleDigest.sha256(buildString {
            append("transactionId=").append(transactionId).append('\n')
            append("preflightSha256=").append(preflightSha256).append('\n')
            append("configPath=").append(configPath).append('\n')
        }.encodeToByteArray())
        return "/etc/nginx/conf.d/.$baseName.${identitySha.take(16)}.stage"
    }

    private fun digest(preparation: SiteWebServingConfigMutationPreparation): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(preparation.contractVersion).append('\n')
            append("mutationTransactionId=").append(preparation.mutationTransactionId).append('\n')
            append("publicationPlanSha256=").append(preparation.publicationPlanSha256).append('\n')
            append("readOnlyPreflightSha256=").append(preparation.readOnlyPreflightSha256).append('\n')
            append("remoteHostIdentity=").append(preparation.remoteHostIdentity).append('\n')
            append("configPath=").append(preparation.configPath).append('\n')
            append("stagingConfigPath=").append(preparation.stagingConfigPath).append('\n')
            append("desiredConfigSha256=").append(preparation.desiredConfigSha256).append('\n')
            append("rollbackBaseline=").append(preparation.rollbackBaseline.name).append('\n')
            preparation.steps.forEach { append("step=").append(it.name).append('\n') }
            preparation.counteractions.forEach { append("counteraction=").append(it.name).append('\n') }
            append("requiresDurableBaselineCheckpointBeforeFirstWrite=")
                .append(preparation.requiresDurableBaselineCheckpointBeforeFirstWrite).append('\n')
            append("requiresExactStagingShaVerification=").append(preparation.requiresExactStagingShaVerification).append('\n')
            append("requiresNginxSyntaxValidationBeforeReload=")
                .append(preparation.requiresNginxSyntaxValidationBeforeReload).append('\n')
            append("requiresDurablePreReloadCheckpoint=").append(preparation.requiresDurablePreReloadCheckpoint).append('\n')
            append("requiresPostServeVerification=").append(preparation.requiresPostServeVerification).append('\n')
            append("configMutationAuthorized=").append(preparation.configMutationAuthorized).append('\n')
            append("webServerReloadAuthorized=").append(preparation.webServerReloadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(preparation.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(preparation.firewallMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(preparation.packageInstallAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(preparation.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
