package com.velumtegra.xuimobile.core.site

enum class SiteWebServingNginxReloadAuthorizedStep {
    REVALIDATE_EXACT_CONFIG_SHA256,
    REVALIDATE_NGINX_SYNTAX,
    VERIFY_LISTENER_STILL_FREE_BEFORE_RELOAD,
    DURABLE_PRE_RELOAD_CHECKPOINT,
    RELOAD_NGINX_ONCE,
    VERIFY_EXACT_CONFIG_SHA256_AFTER_RELOAD,
    VERIFY_NGINX_MASTER_STILL_RUNNING,
    VERIFY_EXPECTED_LISTENER_LIVE,
}

enum class SiteWebServingNginxReloadCounteraction {
    READ_ONLY_RECONCILIATION_AFTER_UNCERTAIN_RELOAD,
    EXPLICIT_SHA_BOUND_ROLLBACK_REQUIRES_SEPARATE_AUTHORITY,
}

data class SiteWebServingNginxReloadExecutionPlan(
    val contractVersion: Int,
    val activationPlanSha256: String,
    val publicationPlanSha256: String,
    val remoteHostIdentity: String,
    val configPath: String,
    val desiredConfigSha256: String,
    val expectedListenerPort: Int,
    val steps: List<SiteWebServingNginxReloadAuthorizedStep>,
    val counteractions: List<SiteWebServingNginxReloadCounteraction>,
    val requiresSuccessfulActivationProof: Boolean,
    val requiresExactConfigShaBeforeReload: Boolean,
    val requiresSuccessfulNginxSyntaxBeforeReload: Boolean,
    val requiresListenerFreeBeforeReload: Boolean,
    val requiresDurablePreReloadCheckpoint: Boolean,
    val reloadNginxOnceAuthorized: Boolean,
    val requiresExactConfigShaAfterReload: Boolean,
    val requiresExpectedListenerLiveAfterReload: Boolean,
    val configMutationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val reloadPlanSha256: String,
)

data class SiteWebServingNginxReloadExecutionObservation(
    val remoteHostIdentity: String,
    val verifiedHostKeySha256: String,
    val exactConfigSha256VerifiedBeforeReload: Boolean,
    val nginxSyntaxValidationPassedBeforeReload: Boolean,
    val listenerFreeBeforeReload: Boolean,
    val durablePreReloadCheckpointRecorded: Boolean,
    val nginxReloadPerformed: Boolean,
    val exactConfigSha256VerifiedAfterReload: Boolean,
    val nginxMasterRunningAfterReload: Boolean,
    val expectedListenerLiveAfterReload: Boolean,
    val remoteCommandCount: Int,
    val arbitraryCommandAccepted: Boolean,
    val configMutationPerformed: Boolean,
    val dnsMutationPerformed: Boolean,
    val firewallMutationPerformed: Boolean,
    val packageInstallPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
)
