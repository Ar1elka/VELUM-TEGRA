package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.66 binds an already validated Phase 11.65 certificate eligibility report to the exact
 * Site Deployer domain. It performs no network I/O, does not configure HTTPS, and never reads a
 * private key. A successful result only allows a later HTTPS planning boundary to consume the
 * exact same-server certificate reference.
 */
object SiteExactDomainCertificateReuseBindingBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val exactSteps = listOf(
        SiteExactDomainCertificateReuseBindingAuthorizedStep.VALIDATE_LOCAL_PREPARATION_CERTIFICATE_REUSE_REQUIREMENT,
        SiteExactDomainCertificateReuseBindingAuthorizedStep.VALIDATE_PHASE11_65_ELIGIBILITY_REPORT,
        SiteExactDomainCertificateReuseBindingAuthorizedStep.REQUIRE_EXACT_OBSERVED_REMOTE_HOST_IDENTITY,
        SiteExactDomainCertificateReuseBindingAuthorizedStep.REQUIRE_EXACT_NORMALIZED_PUBLICATION_DOMAIN,
        SiteExactDomainCertificateReuseBindingAuthorizedStep.REQUIRE_EXACT_DOMAIN_IN_ELIGIBLE_CERTIFICATE_DNS_NAMES,
        SiteExactDomainCertificateReuseBindingAuthorizedStep.EXPOSE_SERVER_SIDE_CERTIFICATE_REFERENCE_ONLY_AFTER_ALL_BINDING_CHECKS_PASS,
    )
    private val exactCounteractions = listOf(
        SiteExactDomainCertificateReuseBindingCounteraction.PRESERVE_FAIL_CLOSED_NO_CONFIGURED_PANEL_CERTIFICATE_STATE,
        SiteExactDomainCertificateReuseBindingCounteraction.READ_ONLY_RECONCILIATION_AFTER_DOMAIN_OR_PROVENANCE_MISMATCH,
        SiteExactDomainCertificateReuseBindingCounteraction.SEPARATE_CERTIFICATE_PROVISIONING_AUTHORITY_REQUIRED_IF_REUSE_CANNOT_BIND,
        SiteExactDomainCertificateReuseBindingCounteraction.SEPARATE_HTTPS_PLANNING_AND_TLS_CONFIGURATION_AUTHORITY_REQUIRED_AFTER_BINDING,
    )
    private val noConfiguredPanelCertificateFailedChecks = setOf(
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REFERENCE_CANONICAL,
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REFERENCE_CANONICAL,
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REGULAR_FILE,
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REGULAR_FILE_SERVER_SIDE,
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_SHA256_OBSERVED,
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_DNS_NAMES_NORMALIZABLE,
        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_CURRENTLY_VALID,
    )

    fun evaluate(
        preparation: SiteDeployerLocalPreparationResult,
        eligibilityReport: SiteExisting3xUiCertificateReuseEligibilityReport,
        observedRemoteHostIdentity: String,
    ): SiteExactDomainCertificateReuseBindingReport {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteRemoteDeployPolicy.validatePlan(preparation.remoteDeployPlan)
        SiteExisting3xUiCertificateReuseEligibilityBoundary.validateReport(eligibilityReport)

        require(preparation.remoteDeployPlan.certificate.mode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN) {
            "Phase 11.66 requires an explicit existing 3x-ui certificate reuse request"
        }
        val requiredDomain = SiteRemoteDeployPolicy.normalizeDomain(
            requireNotNull(preparation.remoteDeployPlan.certificate.requiredDomain) {
                "Phase 11.66 exact certificate-reuse domain is missing"
            },
        )
        require(requiredDomain == preparation.serviceBinding.domain) {
            "Phase 11.66 certificate requirement differs from exact service-binding domain"
        }
        require(observedRemoteHostIdentity.isNotBlank()) { "Phase 11.66 observed remote host identity is blank" }

        val reference = eligibilityReport.certificateReference
        val hostMatches = observedRemoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity
        val referenceSameServer = reference?.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity
        val exactDomainCovered = reference?.dnsNames?.contains(requiredDomain) == true
        val failedEligibilityCodes = eligibilityReport.checks.filterNot { it.passed }.map { it.code }
        val noConfiguredPanelCertificate =
            eligibilityReport.status == SiteExisting3xUiCertificateReuseEligibilityStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION &&
                eligibilityReport.certificateReference == null &&
                failedEligibilityCodes.toSet() == noConfiguredPanelCertificateFailedChecks

        val checks = listOf(
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.PHASE11_65_ELIGIBILITY_REPORT_ELIGIBLE,
                eligibilityReport.status == SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING,
                "Phase 11.65 must expose an eligible certificate before exact-domain reuse can bind",
            ),
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.OBSERVED_REMOTE_HOST_MATCHES_PREPARATION,
                hostMatches,
                "The validated Phase 11.65 observation must belong to the exact deployment host",
            ),
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.CERTIFICATE_REFERENCE_PRESENT,
                reference != null,
                "An eligible Phase 11.65 report must expose a server-side certificate reference",
            ),
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.CERTIFICATE_REFERENCE_SAME_SERVER,
                referenceSameServer,
                "Certificate reference must belong to the exact deployment host",
            ),
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.EXACT_REQUIRED_DOMAIN_COVERED,
                exactDomainCovered,
                "Certificate DNS names must contain the exact normalized Site Deployer domain",
            ),
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.CERTIFICATE_CURRENTLY_USABLE,
                reference?.usableNow == true,
                "Certificate reference must remain currently usable",
            ),
            check(
                SiteExactDomainCertificateReuseBindingCheckCode.PRIVATE_KEY_PRESENT_SERVER_SIDE,
                reference?.privateKeyPresentOnServer == true,
                "Matching private key must remain present on the server without reading its bytes",
            ),
        )

        val positive = checks.all { it.passed }
        val status = when {
            positive ->
                SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING
            hostMatches && noConfiguredPanelCertificate ->
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE
            eligibilityReport.status == SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING &&
                hostMatches && reference != null && referenceSameServer && !exactDomainCovered ->
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN
            else ->
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION
        }
        val base = SiteExactDomainCertificateReuseBindingReport(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            eligibilityReportSha256 = eligibilityReport.eligibilityReportSha256,
            eligibilityStatus = eligibilityReport.status,
            eligibilityFailedCheckCodes = failedEligibilityCodes,
            observedRemoteHostIdentity = observedRemoteHostIdentity,
            requiredDomain = requiredDomain,
            steps = exactSteps,
            counteractions = exactCounteractions,
            checks = checks,
            status = status,
            certificateReference = if (positive) requireNotNull(reference) else null,
            httpsPlanningAuthorized = false,
            tlsConfigurationAuthorized = false,
            certificateMutationAuthorized = false,
            privateKeyContentReadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            productionNetworkTouched = false,
            automaticRetryAuthorized = false,
            bindingReportSha256 = "",
        )
        return base.copy(bindingReportSha256 = reportSha256(base)).also(::validate)
    }

    fun validate(report: SiteExactDomainCertificateReuseBindingReport) {
        require(report.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(report.preparationSha256))
        require(sha256.matches(report.eligibilityReportSha256))
        require(report.requiredDomain == SiteRemoteDeployPolicy.normalizeDomain(report.requiredDomain))
        require(report.observedRemoteHostIdentity.isNotBlank())
        require(report.steps == exactSteps)
        require(report.counteractions == exactCounteractions)
        require(report.checks.map { it.code } == SiteExactDomainCertificateReuseBindingCheckCode.entries.toList())
        require(report.eligibilityFailedCheckCodes == report.eligibilityFailedCheckCodes.distinct())
        val positive = report.checks.all { it.passed }
        require(
            (report.status == SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING) == positive,
        )
        if (positive) {
            val reference = requireNotNull(report.certificateReference)
            require(report.eligibilityStatus == SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING)
            require(reference.remoteHostIdentity == report.observedRemoteHostIdentity)
            require(sha256.matches(reference.certificateSha256))
            require(reference.dnsNames.contains(report.requiredDomain))
            require(reference.dnsNames == reference.dnsNames.distinct().sorted())
            require(reference.usableNow && reference.privateKeyPresentOnServer)
            require(SiteRemoteDeployPolicy.prepareTargetRoot(reference.certificatePath) == reference.certificatePath)
            require(SiteRemoteDeployPolicy.prepareTargetRoot(reference.privateKeyPath) == reference.privateKeyPath)
            require(reference.certificatePath != reference.privateKeyPath)
        } else {
            require(report.certificateReference == null)
        }
        if (report.status ==
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE
        ) {
            require(report.eligibilityStatus ==
                SiteExisting3xUiCertificateReuseEligibilityStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION)
            require(report.eligibilityFailedCheckCodes.toSet() == noConfiguredPanelCertificateFailedChecks)
        }
        if (report.status ==
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN
        ) {
            require(report.eligibilityStatus ==
                SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING)
            require(report.checks.single {
                it.code == SiteExactDomainCertificateReuseBindingCheckCode.EXACT_REQUIRED_DOMAIN_COVERED
            }.passed.not())
        }
        require(!report.httpsPlanningAuthorized)
        require(!report.tlsConfigurationAuthorized)
        require(!report.certificateMutationAuthorized)
        require(!report.privateKeyContentReadAuthorized)
        require(!report.dnsMutationAuthorized)
        require(!report.firewallMutationAuthorized)
        require(!report.packageInstallAuthorized)
        require(!report.productionNetworkTouched)
        require(!report.automaticRetryAuthorized)
        require(report.bindingReportSha256 == reportSha256(report.copy(bindingReportSha256 = "")))
    }

    private fun check(
        code: SiteExactDomainCertificateReuseBindingCheckCode,
        passed: Boolean,
        detail: String,
    ) = SiteExactDomainCertificateReuseBindingCheck(code, passed, detail)

    private fun reportSha256(report: SiteExactDomainCertificateReuseBindingReport): String =
        SiteBundleDigest.sha256(buildString {
            append("phase=11.66\n")
            append("contractVersion=").append(report.contractVersion).append('\n')
            append("preparation=").append(report.preparationSha256).append('\n')
            append("eligibilityReport=").append(report.eligibilityReportSha256).append('\n')
            append("eligibilityStatus=").append(report.eligibilityStatus.name).append('\n')
            report.eligibilityFailedCheckCodes.forEach { append("eligibilityFailed=").append(it.name).append('\n') }
            append("observedRemoteHostIdentity=").append(report.observedRemoteHostIdentity).append('\n')
            append("requiredDomain=").append(report.requiredDomain).append('\n')
            report.steps.forEach { append("step=").append(it.name).append('\n') }
            report.counteractions.forEach { append("counteraction=").append(it.name).append('\n') }
            report.checks.forEach { append("check=").append(it.code.name).append(':').append(it.passed).append('\n') }
            append("status=").append(report.status.name).append('\n')
            report.certificateReference?.let { reference ->
                append("referenceHost=").append(reference.remoteHostIdentity).append('\n')
                append("certificateSha256=").append(reference.certificateSha256).append('\n')
                reference.dnsNames.forEach { append("dnsName=").append(it).append('\n') }
                append("certificatePath=").append(reference.certificatePath).append('\n')
                append("privateKeyPath=").append(reference.privateKeyPath).append('\n')
                append("usableNow=").append(reference.usableNow).append('\n')
                append("privateKeyPresentOnServer=").append(reference.privateKeyPresentOnServer).append('\n')
            }
            append("httpsPlanningAuthorized=").append(report.httpsPlanningAuthorized).append('\n')
            append("tlsConfigurationAuthorized=").append(report.tlsConfigurationAuthorized).append('\n')
            append("certificateMutationAuthorized=").append(report.certificateMutationAuthorized).append('\n')
            append("privateKeyContentReadAuthorized=").append(report.privateKeyContentReadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(report.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(report.firewallMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(report.packageInstallAuthorized).append('\n')
            append("productionNetworkTouched=").append(report.productionNetworkTouched).append('\n')
            append("automaticRetryAuthorized=").append(report.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
