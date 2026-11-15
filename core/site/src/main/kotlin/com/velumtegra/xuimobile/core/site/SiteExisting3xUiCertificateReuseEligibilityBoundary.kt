package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.65 discovers whether the existing 3x-ui web certificate is safe to carry forward as an
 * exact server-side reference. It never reads private-key bytes and grants no TLS/config mutation.
 */
object SiteExisting3xUiCertificateReuseEligibilityBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val DATABASE_PATH: String = "/etc/x-ui/x-ui.db"
    const val MAX_DNS_NAMES: Int = 32

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val hostIdentity = Regex("^[A-Za-z0-9._:-]{1,255}$")
    private val exactSteps = listOf(
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.REQUIRE_EXACT_REMOTE_HOST_IDENTITY,
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.READ_3X_UI_CERTIFICATE_REFERENCES_FROM_DATABASE,
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.VALIDATE_SERVER_SIDE_CERTIFICATE_AND_KEY_PATHS,
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.READ_PUBLIC_CERTIFICATE_METADATA,
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.NORMALIZE_CERTIFICATE_DNS_NAMES,
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.VERIFY_CERTIFICATE_CURRENT_VALIDITY,
        SiteExisting3xUiCertificateReuseEligibilityAuthorizedStep.VERIFY_PRIVATE_KEY_FILE_PRESENT_WITHOUT_READING_CONTENT,
    )
    private val exactCounteractions = listOf(
        SiteExisting3xUiCertificateReuseEligibilityCounteraction.READ_ONLY_RECONCILIATION_AFTER_DISCOVERY_FAILURE,
        SiteExisting3xUiCertificateReuseEligibilityCounteraction.SEPARATE_CERTIFICATE_PROVISIONING_AUTHORITY_REQUIRED_IF_REUSE_IS_NOT_ELIGIBLE,
        SiteExisting3xUiCertificateReuseEligibilityCounteraction.SEPARATE_TLS_CONFIGURATION_AUTHORITY_REQUIRED_BEFORE_HTTPS,
    )

    fun prepare(remoteHostIdentity: String): SiteExisting3xUiCertificateReuseEligibilityPlan {
        require(hostIdentity.matches(remoteHostIdentity)) { "Phase 11.65 remote host identity is not canonical" }
        val base = SiteExisting3xUiCertificateReuseEligibilityPlan(
            contractVersion = CONTRACT_VERSION,
            remoteHostIdentity = remoteHostIdentity,
            databasePath = DATABASE_PATH,
            maxDnsNames = MAX_DNS_NAMES,
            steps = exactSteps,
            counteractions = exactCounteractions,
            sqliteReadOnlyQueryAuthorized = true,
            publicCertificateMetadataReadAuthorized = true,
            privateKeyPresenceProbeAuthorized = true,
            privateKeyContentReadAuthorized = false,
            certificateMutationAuthorized = false,
            tlsConfigurationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            eligibilityPlanSha256 = "",
        )
        return base.copy(eligibilityPlanSha256 = planSha256(base)).also(::validatePlan)
    }

    fun evaluate(
        plan: SiteExisting3xUiCertificateReuseEligibilityPlan,
        trust: SiteExisting3xUiCertificateReuseEligibilityTrust,
        observation: SiteExisting3xUiCertificateReuseEligibilityObservation,
        observedAtEpochMillis: Long,
    ): SiteExisting3xUiCertificateReuseEligibilityReport {
        validatePlan(plan)
        validateTrust(trust)
        validateObservation(plan, observation)
        require(observedAtEpochMillis > 0L)

        val certificatePath = canonicalPathOrNull(observation.certificatePath)
        val privateKeyPath = canonicalPathOrNull(observation.privateKeyPath)
        val normalizedDnsNames = normalizeDnsNamesOrNull(observation.certificateDnsNames)
        val certificateSha = observation.certificateSha256?.takeIf(sha256::matches)
        val currentlyValid = observation.certificateNotBeforeEpochMillis?.let { notBefore ->
            observation.certificateNotAfterEpochMillis?.let { notAfter ->
                notBefore <= observedAtEpochMillis && observedAtEpochMillis < notAfter
            }
        } == true

        val checks = listOf(
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.REMOTE_HOST_IDENTITY,
                observation.remoteHostIdentity == plan.remoteHostIdentity,
                "Certificate discovery must run on the exact reviewed remote host",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.VERIFIED_HOST_KEY,
                observation.verifiedHostKeySha256 == trust.expectedHostKeySha256,
                "Live verified host key must exactly match reviewed trust",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.XUI_DATABASE_REGULAR_FILE,
                observation.databasePath == plan.databasePath &&
                    observation.databasePathType == SiteWebServingObservedPathType.FILE,
                "The exact 3x-ui database path must be a regular file",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.SQLITE_READ_ONLY_AVAILABLE,
                observation.sqliteReadOnlyAvailable,
                "Read-only SQLite access must be available for exact 3x-ui settings discovery",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REFERENCE_CANONICAL,
                certificatePath != null,
                "3x-ui certificate reference must be a canonical absolute server-side path",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REFERENCE_CANONICAL,
                privateKeyPath != null && privateKeyPath != certificatePath,
                "3x-ui private-key reference must be a distinct canonical absolute server-side path",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REGULAR_FILE,
                observation.certificatePathType == SiteWebServingObservedPathType.FILE,
                "Referenced certificate must be a regular non-symlink file",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REGULAR_FILE_SERVER_SIDE,
                observation.privateKeyPathType == SiteWebServingObservedPathType.FILE,
                "Referenced private key must remain a regular server-side file; key bytes are not read",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_SHA256_OBSERVED,
                certificateSha != null,
                "Certificate file SHA-256 must be observed",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_DNS_NAMES_NORMALIZABLE,
                normalizedDnsNames?.isNotEmpty() == true,
                "Certificate SAN DNS names must be bounded, exact, non-wildcard and normalizable",
            ),
            check(
                SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_CURRENTLY_VALID,
                currentlyValid,
                "Certificate validity window must contain the current observation time",
            ),
        )
        val eligible = checks.all { it.passed }
        val reference = if (eligible) {
            SiteServerCertificateFileReference(
                remoteHostIdentity = plan.remoteHostIdentity,
                certificateSha256 = requireNotNull(certificateSha),
                dnsNames = requireNotNull(normalizedDnsNames),
                certificatePath = requireNotNull(certificatePath),
                privateKeyPath = requireNotNull(privateKeyPath),
                usableNow = true,
                privateKeyPresentOnServer = true,
            )
        } else null
        val base = SiteExisting3xUiCertificateReuseEligibilityReport(
            contractVersion = CONTRACT_VERSION,
            eligibilityPlanSha256 = plan.eligibilityPlanSha256,
            observationSha256 = observationSha256(observation),
            observedAtEpochMillis = observedAtEpochMillis,
            checks = checks,
            status = if (eligible) {
                SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING
            } else {
                SiteExisting3xUiCertificateReuseEligibilityStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION
            },
            certificateReference = reference,
            certificateMutationAuthorized = false,
            tlsConfigurationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = false,
            eligibilityReportSha256 = "",
        )
        return base.copy(eligibilityReportSha256 = reportSha256(base)).also(::validateReport)
    }

    fun validatePlan(plan: SiteExisting3xUiCertificateReuseEligibilityPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(hostIdentity.matches(plan.remoteHostIdentity))
        require(plan.databasePath == DATABASE_PATH)
        require(plan.maxDnsNames == MAX_DNS_NAMES)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.sqliteReadOnlyQueryAuthorized)
        require(plan.publicCertificateMetadataReadAuthorized)
        require(plan.privateKeyPresenceProbeAuthorized)
        require(!plan.privateKeyContentReadAuthorized)
        require(!plan.certificateMutationAuthorized)
        require(!plan.tlsConfigurationAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.eligibilityPlanSha256 == planSha256(plan.copy(eligibilityPlanSha256 = "")))
    }

    fun validateReport(report: SiteExisting3xUiCertificateReuseEligibilityReport) {
        require(report.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(report.eligibilityPlanSha256))
        require(sha256.matches(report.observationSha256))
        require(report.observedAtEpochMillis > 0L)
        require(report.checks.map { it.code } == report.checks.map { it.code }.distinct())
        require(report.checks.size == SiteExisting3xUiCertificateReuseEligibilityCheckCode.entries.size)
        val eligible = report.checks.all { it.passed }
        require((report.status == SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING) == eligible)
        if (eligible) {
            val ref = requireNotNull(report.certificateReference)
            require(sha256.matches(ref.certificateSha256))
            require(ref.dnsNames.isNotEmpty() && ref.dnsNames.size <= MAX_DNS_NAMES)
            require(ref.dnsNames == ref.dnsNames.distinct().sorted())
            require(ref.dnsNames.all { SiteRemoteDeployPolicy.normalizeDomain(it) == it })
            require(SiteRemoteDeployPolicy.prepareTargetRoot(ref.certificatePath) == ref.certificatePath)
            require(SiteRemoteDeployPolicy.prepareTargetRoot(ref.privateKeyPath) == ref.privateKeyPath)
            require(ref.certificatePath != ref.privateKeyPath)
            require(ref.usableNow && ref.privateKeyPresentOnServer)
        } else {
            require(report.certificateReference == null)
        }
        require(!report.certificateMutationAuthorized)
        require(!report.tlsConfigurationAuthorized)
        require(!report.dnsMutationAuthorized)
        require(!report.firewallMutationAuthorized)
        require(!report.packageInstallAuthorized)
        require(!report.privateKeyContentReadAuthorized)
        require(!report.automaticRetryAuthorized)
        require(report.eligibilityReportSha256 == reportSha256(report.copy(eligibilityReportSha256 = "")))
    }

    private fun validateTrust(trust: SiteExisting3xUiCertificateReuseEligibilityTrust) {
        require(sha256.matches(trust.expectedHostKeySha256))
    }

    private fun validateObservation(
        plan: SiteExisting3xUiCertificateReuseEligibilityPlan,
        observation: SiteExisting3xUiCertificateReuseEligibilityObservation,
    ) {
        require(observation.remoteHostIdentity.isNotBlank())
        require(sha256.matches(observation.verifiedHostKeySha256))
        require(observation.databasePath == plan.databasePath)
        require(observation.remoteCommandCount in 1..3)
        require(observation.certificateDnsNames.size <= plan.maxDnsNames)
        require(observation.certificateDnsNames.all { it.length in 1..253 && it.none(Char::isISOControl) })
        observation.certificateNotBeforeEpochMillis?.let { require(it > 0L) }
        observation.certificateNotAfterEpochMillis?.let { require(it > 0L) }
        if (observation.certificateNotBeforeEpochMillis != null && observation.certificateNotAfterEpochMillis != null) {
            require(observation.certificateNotBeforeEpochMillis < observation.certificateNotAfterEpochMillis)
        }
        require(!observation.mutationOperationPerformed)
        require(!observation.arbitraryCommandAccepted)
        require(!observation.privateKeyContentReadPerformed)
    }

    private fun canonicalPathOrNull(value: String?): String? = value?.let { raw ->
        runCatching { SiteRemoteDeployPolicy.prepareTargetRoot(raw) }.getOrNull()?.takeIf { it == raw }
    }

    private fun normalizeDnsNamesOrNull(values: List<String>): List<String>? = runCatching {
        require(values.isNotEmpty() && values.size <= MAX_DNS_NAMES)
        values.map(SiteRemoteDeployPolicy::normalizeDomain).distinct().sorted().also {
            require(it.isNotEmpty() && it.size <= MAX_DNS_NAMES)
        }
    }.getOrNull()

    private fun check(
        code: SiteExisting3xUiCertificateReuseEligibilityCheckCode,
        passed: Boolean,
        detail: String,
    ) = SiteExisting3xUiCertificateReuseEligibilityCheck(code, passed, detail)

    private fun observationSha256(observation: SiteExisting3xUiCertificateReuseEligibilityObservation): String =
        SiteBundleDigest.sha256(buildString {
            append("remoteHostIdentity=").append(observation.remoteHostIdentity).append('\n')
            append("verifiedHostKeySha256=").append(observation.verifiedHostKeySha256).append('\n')
            append("databasePath=").append(observation.databasePath).append('\n')
            append("databasePathType=").append(observation.databasePathType.name).append('\n')
            append("sqliteReadOnlyAvailable=").append(observation.sqliteReadOnlyAvailable).append('\n')
            append("certificatePath=").append(observation.certificatePath ?: "").append('\n')
            append("privateKeyPath=").append(observation.privateKeyPath ?: "").append('\n')
            append("certificatePathType=").append(observation.certificatePathType?.name ?: "").append('\n')
            append("privateKeyPathType=").append(observation.privateKeyPathType?.name ?: "").append('\n')
            append("certificateSha256=").append(observation.certificateSha256 ?: "").append('\n')
            observation.certificateDnsNames.forEach { append("dnsName=").append(it).append('\n') }
            append("notBefore=").append(observation.certificateNotBeforeEpochMillis ?: 0L).append('\n')
            append("notAfter=").append(observation.certificateNotAfterEpochMillis ?: 0L).append('\n')
            append("remoteCommandCount=").append(observation.remoteCommandCount).append('\n')
            append("mutationOperationPerformed=").append(observation.mutationOperationPerformed).append('\n')
            append("arbitraryCommandAccepted=").append(observation.arbitraryCommandAccepted).append('\n')
            append("privateKeyContentReadPerformed=").append(observation.privateKeyContentReadPerformed).append('\n')
        }.encodeToByteArray())

    private fun planSha256(plan: SiteExisting3xUiCertificateReuseEligibilityPlan): String = SiteBundleDigest.sha256(buildString {
        append("phase=11.65\n")
        append("contractVersion=").append(plan.contractVersion).append('\n')
        append("remoteHostIdentity=").append(plan.remoteHostIdentity).append('\n')
        append("databasePath=").append(plan.databasePath).append('\n')
        append("maxDnsNames=").append(plan.maxDnsNames).append('\n')
        plan.steps.forEach { append("step=").append(it.name).append('\n') }
        plan.counteractions.forEach { append("counteraction=").append(it.name).append('\n') }
        append("sqliteReadOnlyQueryAuthorized=").append(plan.sqliteReadOnlyQueryAuthorized).append('\n')
        append("publicCertificateMetadataReadAuthorized=").append(plan.publicCertificateMetadataReadAuthorized).append('\n')
        append("privateKeyPresenceProbeAuthorized=").append(plan.privateKeyPresenceProbeAuthorized).append('\n')
        append("privateKeyContentReadAuthorized=").append(plan.privateKeyContentReadAuthorized).append('\n')
        append("certificateMutationAuthorized=").append(plan.certificateMutationAuthorized).append('\n')
        append("tlsConfigurationAuthorized=").append(plan.tlsConfigurationAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(plan.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(plan.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(plan.packageInstallAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(plan.automaticRetryAuthorized).append('\n')
    }.encodeToByteArray())

    private fun reportSha256(report: SiteExisting3xUiCertificateReuseEligibilityReport): String = SiteBundleDigest.sha256(buildString {
        append("phase=11.65\n")
        append("contractVersion=").append(report.contractVersion).append('\n')
        append("plan=").append(report.eligibilityPlanSha256).append('\n')
        append("observation=").append(report.observationSha256).append('\n')
        append("observedAt=").append(report.observedAtEpochMillis).append('\n')
        append("status=").append(report.status.name).append('\n')
        report.checks.forEach { check ->
            append("check=").append(check.code.name).append(':').append(check.passed).append('\n')
        }
        report.certificateReference?.let { ref ->
            append("referenceHost=").append(ref.remoteHostIdentity).append('\n')
            append("certificateSha256=").append(ref.certificateSha256).append('\n')
            ref.dnsNames.forEach { append("referenceDns=").append(it).append('\n') }
            append("certificatePath=").append(ref.certificatePath).append('\n')
            append("privateKeyPath=").append(ref.privateKeyPath).append('\n')
            append("usableNow=").append(ref.usableNow).append('\n')
            append("privateKeyPresentOnServer=").append(ref.privateKeyPresentOnServer).append('\n')
        }
        append("certificateMutationAuthorized=").append(report.certificateMutationAuthorized).append('\n')
        append("tlsConfigurationAuthorized=").append(report.tlsConfigurationAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(report.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(report.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(report.packageInstallAuthorized).append('\n')
        append("privateKeyContentReadAuthorized=").append(report.privateKeyContentReadAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(report.automaticRetryAuthorized).append('\n')
    }.encodeToByteArray())
}
