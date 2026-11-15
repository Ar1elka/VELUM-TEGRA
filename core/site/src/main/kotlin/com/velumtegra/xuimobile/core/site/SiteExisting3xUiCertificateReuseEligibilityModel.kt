package com.velumtegra.xuimobile.core.site

enum class SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep {
    REQUIRE_EXACT_REMOTE_HOST_IDENTITY,
    READ_3X_UI_CERTIFICATE_REFERENCES_FROM_DATABASE,
    VALIDATE_SERVER_SIDE_CERTIFICATE_AND_KEY_PATHS,
    READ_PUBLIC_CERTIFICATE_METADATA,
    NORMALIZE_CERTIFICATE_DNS_NAMES,
    VERIFY_CERTIFICATE_CURRENT_VALIDITY,
    VERIFY_PRIVATE_KEY_FILE_PRESENT_WITHOUT_READING_CONTENT,
}

enum class SiteExisting3xUiCertificateReuseEligibilityCounteraction {
    READ_ONLY_RECONCILIATION_AFTER_DISCOVERY_FAILURE,
    SEPARATE_CERTIFICATE_PROVISIONING_AUTHORITY_REQUIRED_IF_REUSE_IS_NOT_ELIGIBLE,
    SEPARATE_TLS_CONFIGURATION_AUTHORITY_REQUIRED_BEFORE_HTTPS,
}

data class SiteExisting3xUiCertificateReuseEligibilityPlan(
    val contractVersion: Int,
    val remoteHostIdentity: String,
    val databasePath: String,
    val maxDnsNames: Int,
    val steps: List<SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep>,
    val counteractions: List<SiteExisting3xUiCertificateReuseEligibilityCounteraction>,
    val sqliteReadOnlyQueryAuthorized: Boolean,
    val publicCertificateMetadataReadAuthorized: Boolean,
    val privateKeyPresenceProbeAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val certificateMutationAuthorized: Boolean,
    val tlsConfigurationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val eligibilityPlanSha256: String,
)

data class SiteExisting3xUiCertificateReuseEligibilityTrust(
    val expectedHostKeySha256: String,
)

data class SiteExisting3xUiCertificateReuseEligibilityObservation(
    val remoteHostIdentity: String,
    val verifiedHostKeySha256: String,
    val databasePath: String,
    val databasePathType: SiteWebServingObservedPathType,
    val sqliteReadOnlyAvailable: Boolean,
    val certificatePath: String?,
    val privateKeyPath: String?,
    val certificatePathType: SiteWebServingObservedPathType?,
    val privateKeyPathType: SiteWebServingObservedPathType?,
    val certificateSha256: String?,
    val certificateDnsNames: List<String>,
    val certificateNotBeforeEpochMillis: Long?,
    val certificateNotAfterEpochMillis: Long?,
    val remoteCommandCount: Int,
    val mutationOperationPerformed: Boolean,
    val arbitraryCommandAccepted: Boolean,
    val privateKeyContentReadPerformed: Boolean,
)

enum class SiteExisting3xUiCertificateReuseEligibilityCheckCode {
    REMOTE_HOST_IDENTITY,
    VERIFIED_HOST_KEY,
    XUI_DATABASE_REGULAR_FILE,
    SQLITE_READ_ONLY_AVAILABLE,
    CERTIFICATE_REFERENCE_CANONICAL,
    PRIVATE_KEY_REFERENCE_CANONICAL,
    CERTIFICATE_REGULAR_FILE,
    PRIVATE_KEY_REGULAR_FILE_SERVER_SIDE,
    CERTIFICATE_SHA256_OBSERVED,
    CERTIFICATE_DNS_NAMES_NORMALIZABLE,
    CERTIFICATE_CURRENTLY_VALID,
}

data class SiteExisting3xUiCertificateReuseEligibilityCheck(
    val code: SiteExisting3xUiCertificateReuseEligibilityCheckCode,
    val passed: Boolean,
    val detail: String,
)

enum class SiteExisting3xUiCertificateReuseEligibilityStatus {
    ELIGIBLE_FOR_EXACT_DOMAIN_BINDING,
    BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
}

data class SiteExisting3xUiCertificateReuseEligibilityReport(
    val contractVersion: Int,
    val eligibilityPlanSha256: String,
    val observationSha256: String,
    val observedAtEpochMillis: Long,
    val checks: List<SiteExisting3xUiCertificateReuseEligibilityCheck>,
    val status: SiteExisting3xUiCertificateReuseEligibilityStatus,
    val certificateReference: SiteServerCertificateFileReference?,
    val certificateMutationAuthorized: Boolean,
    val tlsConfigurationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val eligibilityReportSha256: String,
)
