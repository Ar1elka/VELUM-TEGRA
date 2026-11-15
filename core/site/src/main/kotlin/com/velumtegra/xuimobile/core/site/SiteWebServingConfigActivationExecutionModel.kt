package com.velumtegra.xuimobile.core.site

enum class SiteWebServingConfigActivationAuthorizedStep {
    REVALIDATE_EXACT_BASELINE,
    DURABLE_PREACTIVATION_CHECKPOINT,
    WRITE_OPERATION_OWNED_STAGING_CONFIG,
    VERIFY_STAGING_CONFIG_SHA256,
    ATOMIC_ACTIVATE_EXACT_CONFIG_PATH,
    VERIFY_EXACT_CONFIG_SHA256,
    VALIDATE_NGINX_SYNTAX_WITH_EXACT_CONFIG,
    VERIFY_STAGING_PATH_ABSENT,
    VERIFY_LISTENER_STILL_FREE,
}

enum class SiteWebServingConfigActivationCounteraction {
    DELETE_OPERATION_OWNED_STAGING_ONLY_IF_DESIRED_SHA_MATCHES,
    DELETE_EXACT_CONFIG_ONLY_IF_DESIRED_SHA_MATCHES,
    READ_ONLY_RECONCILIATION_TO_ABSENT_AFTER_UNCERTAIN_DISPATCH,
}

data class SiteWebServingConfigActivationExecutionPlan(
    val contractVersion: Int,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String,
    val stagingSyntaxExecutionPlanSha256: String,
    val publicationPlanSha256: String,
    val readOnlyPreflightSha256: String,
    val remoteHostIdentity: String,
    val configPath: String,
    val stagingConfigPath: String,
    val desiredConfigSha256: String,
    val rollbackBaseline: SiteWebServingConfigRollbackBaseline,
    val steps: List<SiteWebServingConfigActivationAuthorizedStep>,
    val counteractions: List<SiteWebServingConfigActivationCounteraction>,
    val requiresSuccessfulStagingSyntaxProof: Boolean,
    val requiresDurablePreactivationCheckpoint: Boolean,
    val stagingConfigWriteAuthorized: Boolean,
    val exactConfigActivationAuthorized: Boolean,
    val nginxSyntaxValidationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val activationPlanSha256: String,
)

data class SiteWebServingConfigActivationExecutionObservation(
    val remoteHostIdentity: String,
    val verifiedHostKeySha256: String,
    val durablePreactivationCheckpointRecorded: Boolean,
    val stagingWritePerformed: Boolean,
    val stagingSha256Verified: Boolean,
    val exactConfigActivationPerformed: Boolean,
    val exactConfigSha256Verified: Boolean,
    val nginxSyntaxValidationPassed: Boolean,
    val exactConfigPathPresentAfterActivation: Boolean,
    val stagingConfigAbsentAfterActivation: Boolean,
    val listenerStillFreeAfterActivation: Boolean,
    val rollbackToAbsentPerformed: Boolean,
    val remoteCommandCount: Int,
    val arbitraryCommandAccepted: Boolean,
    val webServerReloadPerformed: Boolean,
    val dnsMutationPerformed: Boolean,
    val firewallMutationPerformed: Boolean,
    val packageInstallPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
)
