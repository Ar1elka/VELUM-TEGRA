package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.59A classifies only the web-serving runtime prerequisite gap exposed by Phase 11.59.
 *
 * This boundary never authorizes package installation. It can prove that the already-reviewed nginx
 * prerequisite is now present, or that a clean Debian/Ubuntu apt-based nginx provisioning path may
 * be prepared by a separate explicit boundary. Any ambiguous/partial state remains blocked.
 */
object SiteWebServingRuntimePrerequisiteBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val distribution = Regex("^[a-z0-9][a-z0-9._-]{0,63}$")
    private val supportedAptDistributions = setOf("debian", "ubuntu")
    private val nginxGapCodes = setOf(
        SiteWebServingReadOnlyPreflightCheckCode.NGINX_EXECUTABLE,
        SiteWebServingReadOnlyPreflightCheckCode.NGINX_CONF_D_DIRECTORY,
    )

    fun evaluate(
        plan: SiteWebServingPublicationPlan,
        preflight: SiteWebServingReadOnlyPreflightReport,
        observation: SiteWebServingRuntimePrerequisiteObservation,
    ): SiteWebServingRuntimePrerequisiteReport {
        SiteWebServingPublicationPlanBoundary.validate(plan)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(preflight)
        require(preflight.publicationPlanSha256 == plan.publicationPlanSha256)
        validateObservation(plan, observation)

        val failedCodes = preflight.checks.filterNot { it.passed }.map { it.code }.toSet()
        val liveReady = observation.nginxExecutablePath?.startsWith('/') == true &&
            observation.confDPathType == SiteWebServingObservedPathType.DIRECTORY
        val cleanAptProvisioningCandidate =
            observation.distributionId in supportedAptDistributions &&
                observation.aptGetExecutablePath?.startsWith('/') == true &&
                observation.dpkgQueryExecutablePath?.startsWith('/') == true &&
                observation.nginxExecutablePath == null &&
                observation.nginxRootPathType == SiteWebServingObservedPathType.ABSENT &&
                observation.confDPathType == SiteWebServingObservedPathType.ABSENT &&
                preflight.status == SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION &&
                failedCodes == nginxGapCodes

        val status = when {
            liveReady -> SiteWebServingRuntimePrerequisiteStatus
                .EXISTING_NGINX_PREREQUISITES_READY_REQUIRES_FRESH_PREFLIGHT
            cleanAptProvisioningCandidate -> SiteWebServingRuntimePrerequisiteStatus
                .SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED
            else -> SiteWebServingRuntimePrerequisiteStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION
        }
        val base = SiteWebServingRuntimePrerequisiteReport(
            contractVersion = CONTRACT_VERSION,
            publicationPlanSha256 = plan.publicationPlanSha256,
            sourcePreflightSha256 = preflight.preflightSha256,
            observationSha256 = observationSha256(observation),
            status = status,
            provisioningPreparationEligible = status ==
                SiteWebServingRuntimePrerequisiteStatus.SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED,
            packageInstallAuthorized = false,
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            automaticRetryAuthorized = false,
            reportSha256 = "",
        )
        return base.copy(reportSha256 = reportSha256(base)).also(::validateReport)
    }

    fun validateReport(report: SiteWebServingRuntimePrerequisiteReport) {
        require(report.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(report.publicationPlanSha256))
        require(sha256.matches(report.sourcePreflightSha256))
        require(sha256.matches(report.observationSha256))
        require(sha256.matches(report.reportSha256))
        require(
            report.provisioningPreparationEligible ==
                (report.status == SiteWebServingRuntimePrerequisiteStatus.SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED),
        )
        require(!report.packageInstallAuthorized)
        require(!report.configMutationAuthorized)
        require(!report.webServerReloadAuthorized)
        require(!report.dnsMutationAuthorized)
        require(!report.firewallMutationAuthorized)
        require(!report.automaticRetryAuthorized)
        require(report.reportSha256 == reportSha256(report.copy(reportSha256 = "")))
    }

    fun observationSha256(observation: SiteWebServingRuntimePrerequisiteObservation): String =
        SiteBundleDigest.sha256(buildString {
            append("remoteHostIdentity=").append(observation.remoteHostIdentity).append('\n')
            append("verifiedHostKeySha256=").append(observation.verifiedHostKeySha256).append('\n')
            append("distributionId=").append(observation.distributionId).append('\n')
            append("distributionVersionId=").append(observation.distributionVersionId ?: "").append('\n')
            append("aptGetExecutablePath=").append(observation.aptGetExecutablePath ?: "").append('\n')
            append("dpkgQueryExecutablePath=").append(observation.dpkgQueryExecutablePath ?: "").append('\n')
            append("nginxExecutablePath=").append(observation.nginxExecutablePath ?: "").append('\n')
            append("nginxRootPathType=").append(observation.nginxRootPathType.name).append('\n')
            append("confDPathType=").append(observation.confDPathType.name).append('\n')
            append("remoteCommandCount=").append(observation.remoteCommandCount).append('\n')
            append("mutationOperationPerformed=").append(observation.mutationOperationPerformed).append('\n')
            append("arbitraryCommandAccepted=").append(observation.arbitraryCommandAccepted).append('\n')
        }.encodeToByteArray())

    private fun validateObservation(
        plan: SiteWebServingPublicationPlan,
        observation: SiteWebServingRuntimePrerequisiteObservation,
    ) {
        require(observation.remoteHostIdentity == plan.remoteHostIdentity)
        require(sha256.matches(observation.verifiedHostKeySha256))
        require(distribution.matches(observation.distributionId))
        observation.distributionVersionId?.let {
            require(it.isNotBlank() && it.length <= 64 && '\n' !in it && '\r' !in it && '\u0000' !in it)
        }
        listOf(
            observation.aptGetExecutablePath,
            observation.dpkgQueryExecutablePath,
            observation.nginxExecutablePath,
        ).forEach { path -> path?.let { require(it.startsWith('/') && '\n' !in it && '\r' !in it) } }
        require(observation.remoteCommandCount == 6)
        require(!observation.mutationOperationPerformed)
        require(!observation.arbitraryCommandAccepted)
    }

    private fun reportSha256(report: SiteWebServingRuntimePrerequisiteReport): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(report.contractVersion).append('\n')
            append("publicationPlanSha256=").append(report.publicationPlanSha256).append('\n')
            append("sourcePreflightSha256=").append(report.sourcePreflightSha256).append('\n')
            append("observationSha256=").append(report.observationSha256).append('\n')
            append("status=").append(report.status.name).append('\n')
            append("provisioningPreparationEligible=").append(report.provisioningPreparationEligible).append('\n')
            append("packageInstallAuthorized=").append(report.packageInstallAuthorized).append('\n')
            append("configMutationAuthorized=").append(report.configMutationAuthorized).append('\n')
            append("webServerReloadAuthorized=").append(report.webServerReloadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(report.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(report.firewallMutationAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(report.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
