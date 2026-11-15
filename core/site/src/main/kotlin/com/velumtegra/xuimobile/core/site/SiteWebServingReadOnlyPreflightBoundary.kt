package com.velumtegra.xuimobile.core.site

object SiteWebServingReadOnlyPreflightBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun evaluate(
        plan: SiteWebServingPublicationPlan,
        trust: SiteWebServingReadOnlyPreflightTrust,
        observation: SiteWebServingReadOnlyPreflightObservation,
    ): SiteWebServingReadOnlyPreflightReport {
        SiteWebServingPublicationPlanBoundary.validate(plan)
        validateTrust(trust)
        validateObservation(plan, observation)

        val checks = buildList {
            add(check(
                SiteWebServingReadOnlyPreflightCheckCode.REMOTE_HOST_IDENTITY,
                observation.remoteHostIdentity == plan.remoteHostIdentity,
                "Observed remote host identity must exactly match the publication plan",
            ))
            add(check(
                SiteWebServingReadOnlyPreflightCheckCode.VERIFIED_HOST_KEY,
                observation.verifiedHostKeySha256 == trust.expectedHostKeySha256,
                "Live verified host key must exactly match reviewed trust",
            ))
            add(check(
                SiteWebServingReadOnlyPreflightCheckCode.NGINX_EXECUTABLE,
                observation.nginxExecutablePath?.startsWith('/') == true,
                "nginx executable must be discoverable by the reviewed remote identity",
            ))
            add(check(
                SiteWebServingReadOnlyPreflightCheckCode.NGINX_CONF_D_DIRECTORY,
                observation.confDPathType == SiteWebServingObservedPathType.DIRECTORY,
                "/etc/nginx/conf.d must be an existing non-symlink directory",
            ))
            add(check(
                SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT,
                observation.configPathType == SiteWebServingObservedPathType.ABSENT,
                "Exact deterministic config path must be absent; existing config requires a separate reconciliation boundary",
            ))
            add(check(
                SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE,
                observation.listenerState == SiteWebServingListenerState.FREE,
                "Exact requested listener port must be proven free before config mutation",
            ))
            if (plan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE) {
                add(check(
                    SiteWebServingReadOnlyPreflightCheckCode.CERTIFICATE_FILE_PRESENT,
                    observation.certificatePathType == SiteWebServingObservedPathType.FILE,
                    "Exact server-side certificate path must be a regular file",
                ))
                add(check(
                    SiteWebServingReadOnlyPreflightCheckCode.CERTIFICATE_SHA256_MATCHES,
                    observation.observedCertificateSha256 == plan.certificateSha256,
                    "Server-side certificate SHA-256 must match the publication plan",
                ))
                add(check(
                    SiteWebServingReadOnlyPreflightCheckCode.PRIVATE_KEY_FILE_PRESENT_SERVER_SIDE,
                    observation.privateKeyPathType == SiteWebServingObservedPathType.FILE,
                    "Matching private-key path must remain a regular file on the server; key bytes are never read",
                ))
            }
        }
        val base = SiteWebServingReadOnlyPreflightReport(
            contractVersion = CONTRACT_VERSION,
            publicationPlanSha256 = plan.publicationPlanSha256,
            observationSha256 = observationSha256(observation),
            checks = checks,
            status = if (checks.all { it.passed }) {
                SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY
            } else {
                SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION
            },
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            preflightSha256 = "",
        )
        return base.copy(preflightSha256 = reportSha256(base)).also(::validateReport)
    }

    fun validateReport(report: SiteWebServingReadOnlyPreflightReport) {
        require(report.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(report.publicationPlanSha256))
        require(sha256.matches(report.observationSha256))
        require(report.checks.isNotEmpty())
        require(report.checks.map { it.code } == report.checks.map { it.code }.distinct())
        require(!report.configMutationAuthorized)
        require(!report.webServerReloadAuthorized)
        require(!report.dnsMutationAuthorized)
        require(!report.firewallMutationAuthorized)
        require(!report.packageInstallAuthorized)
        require(!report.automaticRetryAuthorized)
        require(
            (report.status == SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY) ==
                report.checks.all { it.passed },
        )
        require(report.preflightSha256 == reportSha256(report.copy(preflightSha256 = "")))
    }

    fun observationSha256(observation: SiteWebServingReadOnlyPreflightObservation): String =
        SiteBundleDigest.sha256(buildString {
            append("remoteHostIdentity=").append(observation.remoteHostIdentity).append('\n')
            append("verifiedHostKeySha256=").append(observation.verifiedHostKeySha256).append('\n')
            append("nginxExecutablePath=").append(observation.nginxExecutablePath ?: "").append('\n')
            append("confDPathType=").append(observation.confDPathType.name).append('\n')
            append("configPath=").append(observation.configPath).append('\n')
            append("configPathType=").append(observation.configPathType.name).append('\n')
            append("existingConfigSha256=").append(observation.existingConfigSha256 ?: "").append('\n')
            append("listenerState=").append(observation.listenerState.name).append('\n')
            append("certificatePathType=").append(observation.certificatePathType?.name ?: "").append('\n')
            append("observedCertificateSha256=").append(observation.observedCertificateSha256 ?: "").append('\n')
            append("privateKeyPathType=").append(observation.privateKeyPathType?.name ?: "").append('\n')
            append("remoteCommandCount=").append(observation.remoteCommandCount).append('\n')
            append("mutationOperationPerformed=").append(observation.mutationOperationPerformed).append('\n')
            append("arbitraryCommandAccepted=").append(observation.arbitraryCommandAccepted).append('\n')
            append("privateKeyContentReadPerformed=").append(observation.privateKeyContentReadPerformed).append('\n')
        }.encodeToByteArray())

    private fun validateTrust(trust: SiteWebServingReadOnlyPreflightTrust) {
        require(sha256.matches(trust.expectedHostKeySha256)) { "Expected host-key SHA-256 is invalid" }
    }

    private fun validateObservation(
        plan: SiteWebServingPublicationPlan,
        observation: SiteWebServingReadOnlyPreflightObservation,
    ) {
        require(observation.remoteHostIdentity.isNotBlank())
        require(sha256.matches(observation.verifiedHostKeySha256))
        require(observation.configPath == plan.configPath)
        require(observation.remoteCommandCount in 4..8)
        require(!observation.mutationOperationPerformed)
        require(!observation.arbitraryCommandAccepted)
        require(!observation.privateKeyContentReadPerformed)
        observation.existingConfigSha256?.let { require(sha256.matches(it)) }
        observation.observedCertificateSha256?.let { require(sha256.matches(it)) }
        when (plan.protocol) {
            SiteWebServingProtocol.HTTP -> {
                require(observation.certificatePathType == null)
                require(observation.observedCertificateSha256 == null)
                require(observation.privateKeyPathType == null)
            }
            SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE -> {
                require(observation.certificatePathType != null)
                require(observation.privateKeyPathType != null)
                if (observation.certificatePathType == SiteWebServingObservedPathType.FILE) {
                    require(observation.observedCertificateSha256 != null)
                } else {
                    require(observation.observedCertificateSha256 == null)
                }
            }
        }
    }

    private fun reportSha256(report: SiteWebServingReadOnlyPreflightReport): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(report.contractVersion).append('\n')
            append("publicationPlanSha256=").append(report.publicationPlanSha256).append('\n')
            append("observationSha256=").append(report.observationSha256).append('\n')
            report.checks.forEach { check ->
                append("check=").append(check.code.name).append('|').append(check.passed).append('|').append(check.detail).append('\n')
            }
            append("status=").append(report.status.name).append('\n')
            append("configMutationAuthorized=").append(report.configMutationAuthorized).append('\n')
            append("webServerReloadAuthorized=").append(report.webServerReloadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(report.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(report.firewallMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(report.packageInstallAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(report.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())

    private fun check(code: SiteWebServingReadOnlyPreflightCheckCode, passed: Boolean, detail: String) =
        SiteWebServingReadOnlyPreflightCheck(code, passed, detail)
}
