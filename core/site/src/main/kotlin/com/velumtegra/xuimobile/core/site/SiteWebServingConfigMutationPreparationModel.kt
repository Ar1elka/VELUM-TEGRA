package com.velumtegra.xuimobile.core.site

enum class SiteWebServingConfigRollbackBaseline {
    EXACT_CONFIG_PATH_PROVEN_ABSENT,
}

enum class SiteWebServingConfigMutationPreparedStep {
    DURABLE_BASELINE_CHECKPOINT,
    WRITE_OPERATION_OWNED_STAGING_CONFIG,
    VERIFY_STAGING_CONFIG_SHA256,
    ATOMIC_ACTIVATE_EXACT_CONFIG_PATH,
    VALIDATE_NGINX_SYNTAX,
    DURABLE_PRE_RELOAD_CHECKPOINT,
    RELOAD_NGINX_ONCE,
    POST_SERVE_VERIFY,
}

enum class SiteWebServingConfigMutationCounteraction {
    DELETE_OPERATION_OWNED_STAGING_ONLY,
    DELETE_EXACT_CONFIG_ONLY_IF_DESIRED_SHA_MATCHES,
    READ_ONLY_RECONCILIATION_AFTER_UNCERTAIN_RELOAD,
    EXPLICIT_ROLLBACK_REMOVE_CONFIG_VALIDATE_RELOAD_POST_VERIFY,
}

data class SiteWebServingConfigMutationPreparationRequest(
    val publicationPlan: SiteWebServingPublicationPlan,
    val readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    val mutationTransactionId: String,
)

data class SiteWebServingConfigMutationPreparation(
    val contractVersion: Int,
    val mutationTransactionId: String,
    val publicationPlanSha256: String,
    val readOnlyPreflightSha256: String,
    val remoteHostIdentity: String,
    val configPath: String,
    val stagingConfigPath: String,
    val desiredConfigSha256: String,
    val rollbackBaseline: SiteWebServingConfigRollbackBaseline,
    val steps: List<SiteWebServingConfigMutationPreparedStep>,
    val counteractions: List<SiteWebServingConfigMutationCounteraction>,
    val requiresDurableBaselineCheckpointBeforeFirstWrite: Boolean,
    val requiresExactStagingShaVerification: Boolean,
    val requiresNginxSyntaxValidationBeforeReload: Boolean,
    val requiresDurablePreReloadCheckpoint: Boolean,
    val requiresPostServeVerification: Boolean,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val mutationPreparationSha256: String,
)
