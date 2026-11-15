package com.velumtegra.xuimobile.core.site

/**
 * Phase 11.63 proves one external plain-HTTP network path from the Android device to the already
 * accepted nginx listener. The socket target must be a literal IPv4 address so success does not
 * imply DNS resolution. No DNS/firewall/config/package/TLS mutation is authorized.
 */
object SiteWebServingExternalHttpReachabilityVerificationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val CONNECT_TIMEOUT_MILLIS: Int = 6_000
    const val READ_TIMEOUT_MILLIS: Int = 8_000

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val exactSteps = listOf(
        SiteWebServingExternalHttpReachabilityAuthorizedStep.REVALIDATE_SUCCESSFUL_LOOPBACK_HTTP_PROOF,
        SiteWebServingExternalHttpReachabilityAuthorizedStep.REQUIRE_LITERAL_IPV4_REMOTE_TARGET,
        SiteWebServingExternalHttpReachabilityAuthorizedStep.CONNECT_FROM_ANDROID_DEVICE_ONCE,
        SiteWebServingExternalHttpReachabilityAuthorizedStep.HTTP_GET_EXACT_INDEX_WITH_EXACT_HOST_ONCE,
        SiteWebServingExternalHttpReachabilityAuthorizedStep.VERIFY_HTTP_STATUS_200,
        SiteWebServingExternalHttpReachabilityAuthorizedStep.VERIFY_CONTENT_LENGTH,
        SiteWebServingExternalHttpReachabilityAuthorizedStep.VERIFY_EXACT_INDEX_BODY_SHA256,
    )
    private val exactCounteractions = listOf(
        SiteWebServingExternalHttpReachabilityCounteraction.READ_ONLY_RECONCILIATION_AFTER_EXTERNAL_CONNECT_OR_HTTP_FAILURE,
        SiteWebServingExternalHttpReachabilityCounteraction.SEPARATE_DNS_AUTHORITY_REQUIRED_BEFORE_DOMAIN_RESOLUTION,
        SiteWebServingExternalHttpReachabilityCounteraction.SEPARATE_FIREWALL_AUTHORITY_REQUIRED_BEFORE_FIREWALL_MUTATION,
        SiteWebServingExternalHttpReachabilityCounteraction.SEPARATE_TLS_AUTHORITY_REQUIRED_BEFORE_HTTPS,
    )

    fun prepare(
        preparation: SiteDeployerLocalPreparationResult,
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
    ): SiteWebServingExternalHttpReachabilityVerificationPlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingNginxReloadExecutionBoundary.validate(reloadPlan)
        SiteWebServingLiveHttpVerificationBoundary.validateAgainst(
            loopbackVerificationPlan,
            preparation,
            publicationPlan,
            reloadPlan,
        )
        require(publicationPlan.protocol == SiteWebServingProtocol.HTTP) {
            "Phase 11.63 is plain HTTP only; HTTPS requires separate authority"
        }
        require(canonicalIpv4(publicationPlan.remoteHostIdentity) == publicationPlan.remoteHostIdentity) {
            "Phase 11.63 requires a canonical literal IPv4 remote target and performs no DNS resolution"
        }

        val base = SiteWebServingExternalHttpReachabilityVerificationPlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            reloadPlanSha256 = reloadPlan.reloadPlanSha256,
            loopbackVerificationPlanSha256 = loopbackVerificationPlan.verificationPlanSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            targetIpv4Literal = publicationPlan.remoteHostIdentity,
            domain = publicationPlan.domain,
            port = publicationPlan.port,
            requestPath = loopbackVerificationPlan.requestPath,
            expectedDocumentPath = loopbackVerificationPlan.expectedDocumentPath,
            expectedBodySha256 = loopbackVerificationPlan.expectedBodySha256,
            expectedBodyBytes = loopbackVerificationPlan.expectedBodyBytes,
            maxHeaderBytes = loopbackVerificationPlan.maxHeaderBytes,
            connectTimeoutMillis = CONNECT_TIMEOUT_MILLIS,
            readTimeoutMillis = READ_TIMEOUT_MILLIS,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresSuccessfulLoopbackHttpProof = true,
            literalIpv4TargetRequired = true,
            externalTcpConnectOnceAuthorized = true,
            externalHttpGetOnceAuthorized = true,
            exactHostHeaderRequired = true,
            requiresHttpStatus200 = true,
            requiresContentLengthMatch = true,
            requiresExactBodySha256 = true,
            externalNetworkPathReachabilityClaimAuthorized = true,
            dnsResolutionAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            httpsAuthorized = false,
            configMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            verificationPlanSha256 = "",
        )
        return base.copy(verificationPlanSha256 = digest(base)).also(::validate)
    }

    fun validate(plan: SiteWebServingExternalHttpReachabilityVerificationPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        listOf(
            plan.preparationSha256,
            plan.publicationPlanSha256,
            plan.reloadPlanSha256,
            plan.loopbackVerificationPlanSha256,
            plan.expectedBodySha256,
            plan.verificationPlanSha256,
        ).forEach { require(sha256.matches(it)) }
        require(plan.remoteHostIdentity == plan.targetIpv4Literal)
        require(canonicalIpv4(plan.targetIpv4Literal) == plan.targetIpv4Literal)
        require(plan.domain == SiteRemoteDeployPolicy.normalizeDomain(plan.domain))
        require(plan.port in 1..65535)
        require(plan.requestPath == "/index.html")
        require(plan.expectedDocumentPath == "index.html")
        require(plan.expectedBodyBytes in 1..SiteWebServingLiveHttpVerificationBoundary.MAX_INDEX_BODY_BYTES)
        require(plan.maxHeaderBytes == SiteWebServingLiveHttpVerificationBoundary.MAX_HEADER_BYTES)
        require(plan.connectTimeoutMillis == CONNECT_TIMEOUT_MILLIS)
        require(plan.readTimeoutMillis == READ_TIMEOUT_MILLIS)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.requiresSuccessfulLoopbackHttpProof)
        require(plan.literalIpv4TargetRequired)
        require(plan.externalTcpConnectOnceAuthorized)
        require(plan.externalHttpGetOnceAuthorized)
        require(plan.exactHostHeaderRequired)
        require(plan.requiresHttpStatus200)
        require(plan.requiresContentLengthMatch)
        require(plan.requiresExactBodySha256)
        require(plan.externalNetworkPathReachabilityClaimAuthorized)
        require(!plan.dnsResolutionAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.httpsAuthorized)
        require(!plan.configMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.verificationPlanSha256 == digest(plan.copy(verificationPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingExternalHttpReachabilityVerificationPlan,
        preparation: SiteDeployerLocalPreparationResult,
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
    ) {
        validate(plan)
        SiteWebServingLiveHttpVerificationBoundary.validateAgainst(
            loopbackVerificationPlan,
            preparation,
            publicationPlan,
            reloadPlan,
        )
        require(plan.preparationSha256 == preparation.preparationSha256)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.reloadPlanSha256 == reloadPlan.reloadPlanSha256)
        require(plan.loopbackVerificationPlanSha256 == loopbackVerificationPlan.verificationPlanSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.domain == publicationPlan.domain)
        require(plan.port == publicationPlan.port)
        require(plan.requestPath == loopbackVerificationPlan.requestPath)
        require(plan.expectedBodySha256 == loopbackVerificationPlan.expectedBodySha256)
        require(plan.expectedBodyBytes == loopbackVerificationPlan.expectedBodyBytes)
    }

    fun literalIpv4Bytes(value: String): ByteArray {
        require(canonicalIpv4(value) == value) { "Phase 11.63 target is not a canonical IPv4 literal" }
        return value.split('.').map { it.toInt().toByte() }.toByteArray()
    }

    private fun canonicalIpv4(value: String): String? {
        val parts = value.split('.')
        if (parts.size != 4) return null
        val octets = parts.map { part ->
            if (part.isEmpty() || part.any { !it.isDigit() }) return null
            if (part.length > 1 && part.startsWith('0')) return null
            part.toIntOrNull()?.takeIf { it in 0..255 } ?: return null
        }
        return octets.joinToString(".")
    }

    private fun digest(plan: SiteWebServingExternalHttpReachabilityVerificationPlan): String =
        SiteBundleDigest.sha256(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("preparation=").append(plan.preparationSha256).append('\n')
            append("publicationPlan=").append(plan.publicationPlanSha256).append('\n')
            append("reloadPlan=").append(plan.reloadPlanSha256).append('\n')
            append("loopbackVerificationPlan=").append(plan.loopbackVerificationPlanSha256).append('\n')
            append("remoteHostIdentity=").append(plan.remoteHostIdentity).append('\n')
            append("targetIpv4Literal=").append(plan.targetIpv4Literal).append('\n')
            append("domain=").append(plan.domain).append('\n')
            append("port=").append(plan.port).append('\n')
            append("requestPath=").append(plan.requestPath).append('\n')
            append("expectedDocumentPath=").append(plan.expectedDocumentPath).append('\n')
            append("expectedBodySha256=").append(plan.expectedBodySha256).append('\n')
            append("expectedBodyBytes=").append(plan.expectedBodyBytes).append('\n')
            append("maxHeaderBytes=").append(plan.maxHeaderBytes).append('\n')
            append("connectTimeoutMillis=").append(plan.connectTimeoutMillis).append('\n')
            append("readTimeoutMillis=").append(plan.readTimeoutMillis).append('\n')
            append("steps=").append(plan.steps.joinToString(",") { it.name }).append('\n')
            append("counteractions=").append(plan.counteractions.joinToString(",") { it.name }).append('\n')
            append("requiresSuccessfulLoopbackHttpProof=").append(plan.requiresSuccessfulLoopbackHttpProof).append('\n')
            append("literalIpv4TargetRequired=").append(plan.literalIpv4TargetRequired).append('\n')
            append("externalTcpConnectOnceAuthorized=").append(plan.externalTcpConnectOnceAuthorized).append('\n')
            append("externalHttpGetOnceAuthorized=").append(plan.externalHttpGetOnceAuthorized).append('\n')
            append("exactHostHeaderRequired=").append(plan.exactHostHeaderRequired).append('\n')
            append("requiresHttpStatus200=").append(plan.requiresHttpStatus200).append('\n')
            append("requiresContentLengthMatch=").append(plan.requiresContentLengthMatch).append('\n')
            append("requiresExactBodySha256=").append(plan.requiresExactBodySha256).append('\n')
            append("externalNetworkPathReachabilityClaimAuthorized=").append(plan.externalNetworkPathReachabilityClaimAuthorized).append('\n')
            append("dnsResolutionAuthorized=").append(plan.dnsResolutionAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(plan.firewallMutationAuthorized).append('\n')
            append("httpsAuthorized=").append(plan.httpsAuthorized).append('\n')
            append("configMutationAuthorized=").append(plan.configMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(plan.packageInstallAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())
}
