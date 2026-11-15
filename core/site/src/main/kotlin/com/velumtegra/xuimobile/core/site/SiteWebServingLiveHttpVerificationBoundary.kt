package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.62 proves that the exact already-published static index is served by the exact nginx
 * listener after Phase 11.61. The probe is read-only and deliberately uses loopback on the remote
 * host, so it proves nginx/static-content behavior without claiming public Internet reachability or
 * granting DNS/firewall/package authority.
 */
object SiteWebServingLiveHttpVerificationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_INDEX_BODY_BYTES: Int = 512 * 1024
    const val MAX_HEADER_BYTES: Int = 16 * 1024

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val exactSteps = listOf(
        SiteWebServingLiveHttpVerificationAuthorizedStep.REVALIDATE_SUCCESSFUL_NGINX_RELOAD_PROOF,
        SiteWebServingLiveHttpVerificationAuthorizedStep.REVALIDATE_EXACT_CONFIG_SHA256,
        SiteWebServingLiveHttpVerificationAuthorizedStep.REVALIDATE_NGINX_MASTER_RUNNING,
        SiteWebServingLiveHttpVerificationAuthorizedStep.REVALIDATE_EXPECTED_LISTENER_LIVE,
        SiteWebServingLiveHttpVerificationAuthorizedStep.HTTP_GET_EXACT_INDEX_OVER_LOOPBACK_ONCE,
        SiteWebServingLiveHttpVerificationAuthorizedStep.VERIFY_HTTP_STATUS_200,
        SiteWebServingLiveHttpVerificationAuthorizedStep.VERIFY_CONTENT_LENGTH,
        SiteWebServingLiveHttpVerificationAuthorizedStep.VERIFY_EXACT_INDEX_BODY_SHA256,
    )
    private val exactCounteractions = listOf(
        SiteWebServingLiveHttpVerificationCounteraction.READ_ONLY_RECONCILIATION_AFTER_VERIFICATION_FAILURE,
        SiteWebServingLiveHttpVerificationCounteraction.SEPARATE_NETWORK_POLICY_AUTHORITY_REQUIRED_FOR_EXTERNAL_REACHABILITY,
    )

    fun prepare(
        preparation: SiteDeployerLocalPreparationResult,
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
    ): SiteWebServingLiveHttpVerificationPlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingNginxReloadExecutionBoundary.validate(reloadPlan)
        require(publicationPlan.protocol == SiteWebServingProtocol.HTTP) {
            "Phase 11.62 is intentionally limited to plain HTTP; HTTPS live verification is separate authority"
        }
        require(publicationPlan.preparationSha256 == preparation.preparationSha256)
        require(publicationPlan.sourceTreeSha256 == preparation.bundle.manifest.treeSha256)
        require(publicationPlan.targetRoot == preparation.remoteDeployPlan.publish.targetRoot)
        require(publicationPlan.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity)
        require(reloadPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(reloadPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(reloadPlan.configPath == publicationPlan.configPath)
        require(reloadPlan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(reloadPlan.expectedListenerPort == publicationPlan.port)

        val index = preparation.bundle.documents.singleOrNull { it.path == "index.html" }
            ?: throw IllegalArgumentException("Phase 11.62 requires exactly one generated index.html")
        require(index.byteSize in 1..MAX_INDEX_BODY_BYTES) { "Phase 11.62 index.html exceeds bounded probe size" }
        require(index.sha256.matches(sha256))

        val base = SiteWebServingLiveHttpVerificationPlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            reloadPlanSha256 = reloadPlan.reloadPlanSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            configPath = publicationPlan.configPath,
            desiredConfigSha256 = publicationPlan.desiredConfigSha256,
            domain = publicationPlan.domain,
            port = publicationPlan.port,
            requestPath = "/index.html",
            expectedDocumentPath = index.path,
            expectedBodySha256 = index.sha256,
            expectedBodyBytes = index.byteSize,
            maxHeaderBytes = MAX_HEADER_BYTES,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresSuccessfulReloadProof = true,
            requiresExactConfigShaBeforeProbe = true,
            requiresNginxMasterRunningBeforeProbe = true,
            requiresExpectedListenerLiveBeforeProbe = true,
            loopbackHttpGetOnceAuthorized = true,
            requiresHttpStatus200 = true,
            requiresContentLengthMatch = true,
            requiresExactBodySha256 = true,
            externalReachabilityClaimAuthorized = false,
            configMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            verificationPlanSha256 = "",
        )
        return base.copy(verificationPlanSha256 = digest(base)).also(::validate)
    }

    fun validate(plan: SiteWebServingLiveHttpVerificationPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        listOf(
            plan.preparationSha256,
            plan.publicationPlanSha256,
            plan.reloadPlanSha256,
            plan.desiredConfigSha256,
            plan.expectedBodySha256,
            plan.verificationPlanSha256,
        ).forEach { require(sha256.matches(it)) }
        require(plan.remoteHostIdentity.isNotBlank())
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.configPath) == plan.configPath)
        require(plan.configPath.startsWith("/etc/nginx/conf.d/") && plan.configPath.endsWith(".conf"))
        require(plan.domain == SiteRemoteDeployPolicy.normalizeDomain(plan.domain))
        require(plan.port in 1..65535)
        require(plan.requestPath == "/index.html")
        require(plan.expectedDocumentPath == "index.html")
        require(plan.expectedBodyBytes in 1..MAX_INDEX_BODY_BYTES)
        require(plan.maxHeaderBytes == MAX_HEADER_BYTES)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.requiresSuccessfulReloadProof)
        require(plan.requiresExactConfigShaBeforeProbe)
        require(plan.requiresNginxMasterRunningBeforeProbe)
        require(plan.requiresExpectedListenerLiveBeforeProbe)
        require(plan.loopbackHttpGetOnceAuthorized)
        require(plan.requiresHttpStatus200)
        require(plan.requiresContentLengthMatch)
        require(plan.requiresExactBodySha256)
        require(!plan.externalReachabilityClaimAuthorized)
        require(!plan.configMutationAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.verificationPlanSha256 == digest(plan.copy(verificationPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingLiveHttpVerificationPlan,
        preparation: SiteDeployerLocalPreparationResult,
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
    ) {
        validate(plan)
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingNginxReloadExecutionBoundary.validate(reloadPlan)
        val index = preparation.bundle.documents.single { it.path == "index.html" }
        require(plan.preparationSha256 == preparation.preparationSha256)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.reloadPlanSha256 == reloadPlan.reloadPlanSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.configPath == publicationPlan.configPath)
        require(plan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(plan.domain == publicationPlan.domain)
        require(plan.port == publicationPlan.port)
        require(plan.expectedBodySha256 == index.sha256)
        require(plan.expectedBodyBytes == index.byteSize)
    }

    private fun digest(plan: SiteWebServingLiveHttpVerificationPlan): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("preparation=").append(plan.preparationSha256).append('\n')
            append("publicationPlan=").append(plan.publicationPlanSha256).append('\n')
            append("reloadPlan=").append(plan.reloadPlanSha256).append('\n')
            append("host=").append(plan.remoteHostIdentity).append('\n')
            append("config=").append(plan.configPath).append('\n')
            append("desiredConfigSha=").append(plan.desiredConfigSha256).append('\n')
            append("domain=").append(plan.domain).append('\n')
            append("port=").append(plan.port).append('\n')
            append("requestPath=").append(plan.requestPath).append('\n')
            append("expectedDocumentPath=").append(plan.expectedDocumentPath).append('\n')
            append("expectedBodySha=").append(plan.expectedBodySha256).append('\n')
            append("expectedBodyBytes=").append(plan.expectedBodyBytes).append('\n')
            append("maxHeaderBytes=").append(plan.maxHeaderBytes).append('\n')
            append("steps=").append(plan.steps.joinToString(",") { it.name }).append('\n')
            append("counteractions=").append(plan.counteractions.joinToString(",") { it.name }).append('\n')
            append("requiresSuccessfulReloadProof=").append(plan.requiresSuccessfulReloadProof).append('\n')
            append("requiresExactConfigShaBeforeProbe=").append(plan.requiresExactConfigShaBeforeProbe).append('\n')
            append("requiresNginxMasterRunningBeforeProbe=").append(plan.requiresNginxMasterRunningBeforeProbe).append('\n')
            append("requiresExpectedListenerLiveBeforeProbe=").append(plan.requiresExpectedListenerLiveBeforeProbe).append('\n')
            append("loopbackHttpGetOnceAuthorized=").append(plan.loopbackHttpGetOnceAuthorized).append('\n')
            append("requiresHttpStatus200=").append(plan.requiresHttpStatus200).append('\n')
            append("requiresContentLengthMatch=").append(plan.requiresContentLengthMatch).append('\n')
            append("requiresExactBodySha256=").append(plan.requiresExactBodySha256).append('\n')
            append("externalReachabilityClaimAuthorized=").append(plan.externalReachabilityClaimAuthorized).append('\n')
            append("configMutation=").append(plan.configMutationAuthorized).append('\n')
            append("dns=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewall=").append(plan.firewallMutationAuthorized).append('\n')
            append("packageInstall=").append(plan.packageInstallAuthorized).append('\n')
            append("automaticRetry=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
