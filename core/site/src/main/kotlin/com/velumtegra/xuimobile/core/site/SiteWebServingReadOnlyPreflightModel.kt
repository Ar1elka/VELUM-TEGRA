package com.velumtegra.xuimobile.core.site

enum class SiteWebServingObservedPathType {
    ABSENT,
    FILE,
    DIRECTORY,
    SYMLINK,
    OTHER,
}

enum class SiteWebServingListenerState {
    FREE,
    OCCUPIED,
    OBSERVER_UNAVAILABLE,
}

data class SiteWebServingReadOnlyPreflightTrust(
    val expectedHostKeySha256: String,
)

data class SiteWebServingReadOnlyPreflightObservation(
    val remoteHostIdentity: String,
    val verifiedHostKeySha256: String,
    val nginxExecutablePath: String?,
    val confDPathType: SiteWebServingObservedPathType,
    val configPath: String,
    val configPathType: SiteWebServingObservedPathType,
    val existingConfigSha256: String?,
    val listenerState: SiteWebServingListenerState,
    val certificatePathType: SiteWebServingObservedPathType?,
    val observedCertificateSha256: String?,
    val privateKeyPathType: SiteWebServingObservedPathType?,
    val remoteCommandCount: Int,
    val mutationOperationPerformed: Boolean,
    val arbitraryCommandAccepted: Boolean,
    val privateKeyContentReadPerformed: Boolean,
)

enum class SiteWebServingReadOnlyPreflightCheckCode {
    REMOTE_HOST_IDENTITY,
    VERIFIED_HOST_KEY,
    NGINX_EXECUTABLE,
    NGINX_CONF_D_DIRECTORY,
    EXACT_CONFIG_PATH_ABSENT,
    LIVE_PORT_FREE,
    CERTIFICATE_FILE_PRESENT,
    CERTIFICATE_SHA256_MATCHES,
    PRIVATE_KEY_FILE_PRESENT_SERVER_SIDE,
}

data class SiteWebServingReadOnlyPreflightCheck(
    val code: SiteWebServingReadOnlyPreflightCheckCode,
    val passed: Boolean,
    val detail: String,
)

enum class SiteWebServingReadOnlyPreflightStatus {
    READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY,
    BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
}

data class SiteWebServingReadOnlyPreflightReport(
    val contractVersion: Int,
    val publicationPlanSha256: String,
    val observationSha256: String,
    val checks: List<SiteWebServingReadOnlyPreflightCheck>,
    val status: SiteWebServingReadOnlyPreflightStatus,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val preflightSha256: String,
)
