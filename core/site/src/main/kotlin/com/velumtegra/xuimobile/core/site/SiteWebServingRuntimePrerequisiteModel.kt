package com.velumtegra.xuimobile.core.site

enum class SiteWebServingRuntimePrerequisiteStatus {
    EXISTING_NGINX_PREREQUISITES_READY_REQUIRES_FRESH_PREFLIGHT,
    SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED,
    BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
}

data class SiteWebServingRuntimePrerequisiteObservation(
    val remoteHostIdentity: String,
    val verifiedHostKeySha256: String,
    val distributionId: String,
    val distributionVersionId: String?,
    val aptGetExecutablePath: String?,
    val dpkgQueryExecutablePath: String?,
    val nginxExecutablePath: String?,
    val nginxRootPathType: SiteWebServingObservedPathType,
    val confDPathType: SiteWebServingObservedPathType,
    val remoteCommandCount: Int,
    val mutationOperationPerformed: Boolean,
    val arbitraryCommandAccepted: Boolean,
)

data class SiteWebServingRuntimePrerequisiteReport(
    val contractVersion: Int,
    val publicationPlanSha256: String,
    val sourcePreflightSha256: String,
    val observationSha256: String,
    val status: SiteWebServingRuntimePrerequisiteStatus,
    val provisioningPreparationEligible: Boolean,
    val packageInstallAuthorized: Boolean,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val reportSha256: String,
)
