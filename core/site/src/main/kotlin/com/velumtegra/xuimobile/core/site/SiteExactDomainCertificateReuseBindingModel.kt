package com.velumtegra.xuimobile.core.site

enum class SiteExactDomainCertificateReuseBindingAuthorizedStep {
    VALIDATE_LOCAL_PREPARATION_CERTIFICATE_REUSE_REQUIREMENT,
    VALIDATE_PHASE11_65_ELIGIBILITY_REPORT,
    REQUIRE_EXACT_OBSERVED_REMOTE_HOST_IDENTITY,
    REQUIRE_EXACT_NORMALIZED_PUBLICATION_DOMAIN,
    REQUIRE_EXACT_DOMAIN_IN_ELIGIBLE_CERTIFICATE_DNS_NAMES,
    EXPOSE_SERVER_SIDE_CERTIFICATE_REFERENCE_ONLY_AFTER_ALL_BINDING_CHECKS_PASS,
}

enum class SiteExactDomainCertificateReuseBindingCounteraction {
    PRESERVE_FAIL_CLOSED_NO_CONFIGURED_PANEL_CERTIFICATE_STATE,
    READ_ONLY_RECONCILIATION_AFTER_DOMAIN_OR_PROVENANCE_MISMATCH,
    SEPARATE_CERTIFICATE_PROVISIONING_AUTHORITY_REQUIRED_IF_REUSE_CANNOT_BIND,
    SEPARATE_HTTPS_PLANNING_AND_TLS_CONFIGURATION_AUTHORITY_REQUIRED_AFTER_BINDING,
}

enum class SiteExactDomainCertificateReuseBindingCheckCode {
    PHASE11_65_ELIGIBILITY_REPORT_ELIGIBLE,
    OBSERVED_REMOTE_HOST_MATCHES_PREPARATION,
    CERTIFICATE_REFERENCE_PRESENT,
    CERTIFICATE_REFERENCE_SAME_SERVER,
    EXACT_REQUIRED_DOMAIN_COVERED,
    CERTIFICATE_CURRENTLY_USABLE,
    PRIVATE_KEY_PRESENT_SERVER_SIDE,
}

data class SiteExactDomainCertificateReuseBindingCheck(
    val code: SiteExactDomainCertificateReuseBindingCheckCode,
    val passed: Boolean,
    val detail: String,
)

enum class SiteExactDomainCertificateReuseBindingStatus {
    BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING,
    BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
    BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
    BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
}

data class SiteExactDomainCertificateReuseBindingReport(
    val contractVersion: Int,
    val preparationSha256: String,
    val eligibilityReportSha256: String,
    val eligibilityStatus: SiteExisting3xUiCertificateReuseEligibilityStatus,
    val eligibilityFailedCheckCodes: List<SiteExisting3xUiCertificateReuseEligibilityCheckCode>,
    val observedRemoteHostIdentity: String,
    val requiredDomain: String,
    val steps: List<SiteExactDomainCertificateReuseBindingAuthorizedStep>,
    val counteractions: List<SiteExactDomainCertificateReuseBindingCounteraction>,
    val checks: List<SiteExactDomainCertificateReuseBindingCheck>,
    val status: SiteExactDomainCertificateReuseBindingStatus,
    val certificateReference: SiteServerCertificateFileReference?,
    val httpsPlanningAuthorized: Boolean,
    val tlsConfigurationAuthorized: Boolean,
    val certificateMutationAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val productionNetworkTouched: Boolean,
    val automaticRetryAuthorized: Boolean,
    val bindingReportSha256: String,
)
