package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.59B grants one narrow mutation capability: provision the exact Debian/Ubuntu `nginx`
 * package after Phase 11.59A proved a clean missing-runtime gap. It does not authorize the Site
 * Deployer's own nginx *.conf, explicit service commands, reload, DNS/firewall changes or retries.
 * Package-managed config creation and package-manager service lifecycle side effects are explicit
 * consequences of the reviewed package installation and are verified by a fresh Phase 11.57 gate.
 */
object SiteWebServingRuntimeProvisioningBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val PACKAGE_NAME: String = "nginx"
    const val APT_GET: String = "/usr/bin/apt-get"
    const val DPKG_QUERY: String = "/usr/bin/dpkg-query"

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val exactSteps = listOf(
        SiteWebServingRuntimeProvisioningAuthorizedStep.REVALIDATE_CLEAN_MISSING_NGINX_BASELINE,
        SiteWebServingRuntimeProvisioningAuthorizedStep.DURABLE_PREDISPATCH_CHECKPOINT,
        SiteWebServingRuntimeProvisioningAuthorizedStep.REFRESH_APT_METADATA_WITHOUT_RETRY,
        SiteWebServingRuntimeProvisioningAuthorizedStep.INSTALL_EXACT_NGINX_PACKAGE_WITHOUT_RECOMMENDS,
        SiteWebServingRuntimeProvisioningAuthorizedStep.VERIFY_DPKG_INSTALLED_STATE,
        SiteWebServingRuntimeProvisioningAuthorizedStep.VERIFY_NGINX_EXECUTABLE_AND_CONFIG_DIRECTORIES,
        SiteWebServingRuntimeProvisioningAuthorizedStep.VERIFY_NGINX_SYNTAX,
        SiteWebServingRuntimeProvisioningAuthorizedStep.VERIFY_SITE_CONFIG_STILL_ABSENT,
        SiteWebServingRuntimeProvisioningAuthorizedStep.VERIFY_LISTENER_STILL_FREE,
    )

    fun prepare(
        publicationPlan: SiteWebServingPublicationPlan,
        prerequisiteReport: SiteWebServingRuntimePrerequisiteReport,
    ): SiteWebServingRuntimeProvisioningPlan {
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingRuntimePrerequisiteBoundary.validateReport(prerequisiteReport)
        require(prerequisiteReport.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(
            prerequisiteReport.status ==
                SiteWebServingRuntimePrerequisiteStatus.SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED,
        )
        require(prerequisiteReport.provisioningPreparationEligible)
        require(!prerequisiteReport.packageInstallAuthorized)

        val base = SiteWebServingRuntimeProvisioningPlan(
            contractVersion = CONTRACT_VERSION,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            prerequisiteReportSha256 = prerequisiteReport.reportSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            configPath = publicationPlan.configPath,
            servicePort = publicationPlan.port,
            packageName = PACKAGE_NAME,
            aptGetExecutablePath = APT_GET,
            dpkgQueryExecutablePath = DPKG_QUERY,
            steps = exactSteps,
            requiresDurablePredispatchCheckpoint = true,
            aptMetadataRefreshAuthorized = true,
            packageInstallAuthorized = true,
            packageManagedConfigCreationAuthorized = true,
            packageManagedServiceLifecycleAuthorized = true,
            siteConfigMutationAuthorized = false,
            explicitServiceCommandAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            automaticRetryAuthorized = false,
            provisioningPlanSha256 = "",
        )
        return base.copy(provisioningPlanSha256 = digest(base)).also {
            validateAgainst(it, publicationPlan, prerequisiteReport)
        }
    }

    fun validate(plan: SiteWebServingRuntimeProvisioningPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.publicationPlanSha256))
        require(sha256.matches(plan.prerequisiteReportSha256))
        require(sha256.matches(plan.provisioningPlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        require(plan.configPath.startsWith("/etc/nginx/conf.d/") && plan.configPath.endsWith(".conf"))
        require(plan.servicePort in 1..65535)
        require(plan.packageName == PACKAGE_NAME)
        require(plan.aptGetExecutablePath == APT_GET)
        require(plan.dpkgQueryExecutablePath == DPKG_QUERY)
        require(plan.steps == exactSteps)
        require(plan.requiresDurablePredispatchCheckpoint)
        require(plan.aptMetadataRefreshAuthorized)
        require(plan.packageInstallAuthorized)
        require(plan.packageManagedConfigCreationAuthorized)
        require(plan.packageManagedServiceLifecycleAuthorized)
        require(!plan.siteConfigMutationAuthorized)
        require(!plan.explicitServiceCommandAuthorized)
        require(!plan.webServerReloadAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.provisioningPlanSha256 == digest(plan.copy(provisioningPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingRuntimeProvisioningPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        prerequisiteReport: SiteWebServingRuntimePrerequisiteReport,
    ) {
        validate(plan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingRuntimePrerequisiteBoundary.validateReport(prerequisiteReport)
        require(
            prerequisiteReport.status ==
                SiteWebServingRuntimePrerequisiteStatus.SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED,
        )
        require(prerequisiteReport.provisioningPreparationEligible)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.prerequisiteReportSha256 == prerequisiteReport.reportSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.configPath == publicationPlan.configPath)
        require(plan.servicePort == publicationPlan.port)
    }

    private fun digest(plan: SiteWebServingRuntimeProvisioningPlan): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("publicationPlanSha256=").append(plan.publicationPlanSha256).append('\n')
            append("prerequisiteReportSha256=").append(plan.prerequisiteReportSha256).append('\n')
            append("remoteHostIdentity=").append(plan.remoteHostIdentity).append('\n')
            append("configPath=").append(plan.configPath).append('\n')
            append("servicePort=").append(plan.servicePort).append('\n')
            append("packageName=").append(plan.packageName).append('\n')
            append("aptGetExecutablePath=").append(plan.aptGetExecutablePath).append('\n')
            append("dpkgQueryExecutablePath=").append(plan.dpkgQueryExecutablePath).append('\n')
            append("steps=").append(plan.steps.joinToString(",") { it.name }).append('\n')
            append("requiresDurablePredispatchCheckpoint=").append(plan.requiresDurablePredispatchCheckpoint).append('\n')
            append("aptMetadataRefreshAuthorized=").append(plan.aptMetadataRefreshAuthorized).append('\n')
            append("packageInstallAuthorized=").append(plan.packageInstallAuthorized).append('\n')
            append("packageManagedConfigCreationAuthorized=").append(plan.packageManagedConfigCreationAuthorized).append('\n')
            append("packageManagedServiceLifecycleAuthorized=").append(plan.packageManagedServiceLifecycleAuthorized).append('\n')
            append("siteConfigMutationAuthorized=").append(plan.siteConfigMutationAuthorized).append('\n')
            append("explicitServiceCommandAuthorized=").append(plan.explicitServiceCommandAuthorized).append('\n')
            append("webServerReloadAuthorized=").append(plan.webServerReloadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(plan.firewallMutationAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
