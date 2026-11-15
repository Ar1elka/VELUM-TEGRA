package com.velumtegra.xuimobile.core.site

import java.net.IDN
import java.security.MessageDigest
import java.util.Locale

/**
 * Phase 11.64 proves one bounded DNS resolution for the exact normalized publication domain and
 * then one exact-body HTTP read through the matching resolved IPv4 address. DNS mutation/provider
 * automation, firewall mutation, TLS/HTTPS and automatic retry remain outside this boundary.
 */
object SiteWebServingDomainDnsResolutionVerificationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_RESOLVED_ADDRESSES: Int = 16
    const val DNS_RESOLUTION_TIMEOUT_MILLIS: Int = 6_000
    const val CONNECT_TIMEOUT_MILLIS: Int = 6_000
    const val READ_TIMEOUT_MILLIS: Int = 8_000

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val exactSteps = listOf(
        SiteWebServingDomainDnsResolutionAuthorizedStep.REVALIDATE_SUCCESSFUL_EXTERNAL_IPV4_HTTP_PROOF,
        SiteWebServingDomainDnsResolutionAuthorizedStep.REQUIRE_NORMALIZED_PUBLICATION_DOMAIN,
        SiteWebServingDomainDnsResolutionAuthorizedStep.RESOLVE_EXACT_DOMAIN_ONCE,
        SiteWebServingDomainDnsResolutionAuthorizedStep.VERIFY_RESOLVED_ADDRESS_SET_CONTAINS_ACCEPTED_IPV4,
        SiteWebServingDomainDnsResolutionAuthorizedStep.CONNECT_USING_MATCHING_RESOLVED_ADDRESS_ONCE,
        SiteWebServingDomainDnsResolutionAuthorizedStep.HTTP_GET_EXACT_INDEX_WITH_EXACT_HOST_ONCE,
        SiteWebServingDomainDnsResolutionAuthorizedStep.VERIFY_HTTP_STATUS_200,
        SiteWebServingDomainDnsResolutionAuthorizedStep.VERIFY_CONTENT_LENGTH,
        SiteWebServingDomainDnsResolutionAuthorizedStep.VERIFY_EXACT_INDEX_BODY_SHA256,
    )
    private val exactCounteractions = listOf(
        SiteWebServingDomainDnsResolutionCounteraction.READ_ONLY_RECONCILIATION_AFTER_DNS_OR_DOMAIN_HTTP_FAILURE,
        SiteWebServingDomainDnsResolutionCounteraction.SEPARATE_DNS_MUTATION_AUTHORITY_REQUIRED_BEFORE_PROVIDER_CHANGES,
        SiteWebServingDomainDnsResolutionCounteraction.SEPARATE_FIREWALL_AUTHORITY_REQUIRED_BEFORE_FIREWALL_MUTATION,
        SiteWebServingDomainDnsResolutionCounteraction.SEPARATE_TLS_AUTHORITY_REQUIRED_BEFORE_HTTPS,
    )

    fun prepare(
        preparation: SiteDeployerLocalPreparationResult,
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
        externalVerificationPlan: SiteWebServingExternalHttpReachabilityVerificationPlan,
    ): SiteWebServingDomainDnsResolutionVerificationPlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingNginxReloadExecutionBoundary.validate(reloadPlan)
        SiteWebServingLiveHttpVerificationBoundary.validateAgainst(
            loopbackVerificationPlan,
            preparation,
            publicationPlan,
            reloadPlan,
        )
        SiteWebServingExternalHttpReachabilityVerificationBoundary.validateAgainst(
            externalVerificationPlan,
            preparation,
            publicationPlan,
            reloadPlan,
            loopbackVerificationPlan,
        )
        require(publicationPlan.protocol == SiteWebServingProtocol.HTTP) {
            "Phase 11.64 remains plain HTTP; HTTPS requires separate authority"
        }
        require(publicationPlan.domain == canonicalDnsName(publicationPlan.domain))
        require(publicationPlan.domain != externalVerificationPlan.targetIpv4Literal) {
            "Phase 11.64 requires a DNS name distinct from the accepted literal IPv4 target"
        }

        val base = SiteWebServingDomainDnsResolutionVerificationPlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            reloadPlanSha256 = reloadPlan.reloadPlanSha256,
            loopbackVerificationPlanSha256 = loopbackVerificationPlan.verificationPlanSha256,
            externalVerificationPlanSha256 = externalVerificationPlan.verificationPlanSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            acceptedTargetIpv4Literal = externalVerificationPlan.targetIpv4Literal,
            domain = publicationPlan.domain,
            port = publicationPlan.port,
            requestPath = externalVerificationPlan.requestPath,
            expectedDocumentPath = externalVerificationPlan.expectedDocumentPath,
            expectedBodySha256 = externalVerificationPlan.expectedBodySha256,
            expectedBodyBytes = externalVerificationPlan.expectedBodyBytes,
            maxHeaderBytes = externalVerificationPlan.maxHeaderBytes,
            maxResolvedAddresses = MAX_RESOLVED_ADDRESSES,
            dnsResolutionTimeoutMillis = DNS_RESOLUTION_TIMEOUT_MILLIS,
            connectTimeoutMillis = CONNECT_TIMEOUT_MILLIS,
            readTimeoutMillis = READ_TIMEOUT_MILLIS,
            steps = exactSteps,
            counteractions = exactCounteractions,
            requiresSuccessfulExternalIpv4HttpProof = true,
            dnsResolutionOnceAuthorized = true,
            requiresResolvedAddressSetContainsAcceptedIpv4 = true,
            domainAddressedTcpConnectOnceAuthorized = true,
            domainAddressedHttpGetOnceAuthorized = true,
            exactHostHeaderRequired = true,
            requiresHttpStatus200 = true,
            requiresContentLengthMatch = true,
            requiresExactBodySha256 = true,
            dnsResolutionClaimAuthorized = true,
            externalDomainHttpReachabilityClaimAuthorized = true,
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

    fun validate(plan: SiteWebServingDomainDnsResolutionVerificationPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        listOf(
            plan.preparationSha256,
            plan.publicationPlanSha256,
            plan.reloadPlanSha256,
            plan.loopbackVerificationPlanSha256,
            plan.externalVerificationPlanSha256,
            plan.expectedBodySha256,
            plan.verificationPlanSha256,
        ).forEach { require(sha256.matches(it)) }
        require(plan.remoteHostIdentity == plan.acceptedTargetIpv4Literal)
        SiteWebServingExternalHttpReachabilityVerificationBoundary.literalIpv4Bytes(plan.acceptedTargetIpv4Literal)
        require(plan.domain == canonicalDnsName(plan.domain))
        require(plan.domain != plan.acceptedTargetIpv4Literal)
        require(plan.port in 1..65535)
        require(plan.requestPath == "/index.html")
        require(plan.expectedDocumentPath == "index.html")
        require(plan.expectedBodyBytes in 1..SiteWebServingLiveHttpVerificationBoundary.MAX_INDEX_BODY_BYTES)
        require(plan.maxHeaderBytes == SiteWebServingLiveHttpVerificationBoundary.MAX_HEADER_BYTES)
        require(plan.maxResolvedAddresses == MAX_RESOLVED_ADDRESSES)
        require(plan.dnsResolutionTimeoutMillis == DNS_RESOLUTION_TIMEOUT_MILLIS)
        require(plan.connectTimeoutMillis == CONNECT_TIMEOUT_MILLIS)
        require(plan.readTimeoutMillis == READ_TIMEOUT_MILLIS)
        require(plan.steps == exactSteps)
        require(plan.counteractions == exactCounteractions)
        require(plan.requiresSuccessfulExternalIpv4HttpProof)
        require(plan.dnsResolutionOnceAuthorized)
        require(plan.requiresResolvedAddressSetContainsAcceptedIpv4)
        require(plan.domainAddressedTcpConnectOnceAuthorized)
        require(plan.domainAddressedHttpGetOnceAuthorized)
        require(plan.exactHostHeaderRequired)
        require(plan.requiresHttpStatus200)
        require(plan.requiresContentLengthMatch)
        require(plan.requiresExactBodySha256)
        require(plan.dnsResolutionClaimAuthorized)
        require(plan.externalDomainHttpReachabilityClaimAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.httpsAuthorized)
        require(!plan.configMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(plan.verificationPlanSha256 == digest(plan.copy(verificationPlanSha256 = "")))
    }

    fun validateAgainst(
        plan: SiteWebServingDomainDnsResolutionVerificationPlan,
        preparation: SiteDeployerLocalPreparationResult,
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
        externalVerificationPlan: SiteWebServingExternalHttpReachabilityVerificationPlan,
    ) {
        validate(plan)
        SiteWebServingExternalHttpReachabilityVerificationBoundary.validateAgainst(
            externalVerificationPlan,
            preparation,
            publicationPlan,
            reloadPlan,
            loopbackVerificationPlan,
        )
        require(plan.preparationSha256 == preparation.preparationSha256)
        require(plan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(plan.reloadPlanSha256 == reloadPlan.reloadPlanSha256)
        require(plan.loopbackVerificationPlanSha256 == loopbackVerificationPlan.verificationPlanSha256)
        require(plan.externalVerificationPlanSha256 == externalVerificationPlan.verificationPlanSha256)
        require(plan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(plan.acceptedTargetIpv4Literal == externalVerificationPlan.targetIpv4Literal)
        require(plan.domain == publicationPlan.domain)
        require(plan.port == publicationPlan.port)
        require(plan.requestPath == externalVerificationPlan.requestPath)
        require(plan.expectedBodySha256 == externalVerificationPlan.expectedBodySha256)
        require(plan.expectedBodyBytes == externalVerificationPlan.expectedBodyBytes)
    }

    private fun digest(plan: SiteWebServingDomainDnsResolutionVerificationPlan): String =
        sha256Bytes(buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("preparation=").append(plan.preparationSha256).append('\n')
            append("publicationPlan=").append(plan.publicationPlanSha256).append('\n')
            append("reloadPlan=").append(plan.reloadPlanSha256).append('\n')
            append("loopbackVerificationPlan=").append(plan.loopbackVerificationPlanSha256).append('\n')
            append("externalVerificationPlan=").append(plan.externalVerificationPlanSha256).append('\n')
            append("remoteHostIdentity=").append(plan.remoteHostIdentity).append('\n')
            append("acceptedTargetIpv4Literal=").append(plan.acceptedTargetIpv4Literal).append('\n')
            append("domain=").append(plan.domain).append('\n')
            append("port=").append(plan.port).append('\n')
            append("requestPath=").append(plan.requestPath).append('\n')
            append("expectedDocumentPath=").append(plan.expectedDocumentPath).append('\n')
            append("expectedBodySha256=").append(plan.expectedBodySha256).append('\n')
            append("expectedBodyBytes=").append(plan.expectedBodyBytes).append('\n')
            append("maxHeaderBytes=").append(plan.maxHeaderBytes).append('\n')
            append("maxResolvedAddresses=").append(plan.maxResolvedAddresses).append('\n')
            append("dnsResolutionTimeoutMillis=").append(plan.dnsResolutionTimeoutMillis).append('\n')
            append("connectTimeoutMillis=").append(plan.connectTimeoutMillis).append('\n')
            append("readTimeoutMillis=").append(plan.readTimeoutMillis).append('\n')
            append("steps=").append(plan.steps.joinToString(",") { it.name }).append('\n')
            append("counteractions=").append(plan.counteractions.joinToString(",") { it.name }).append('\n')
            append("requiresSuccessfulExternalIpv4HttpProof=").append(plan.requiresSuccessfulExternalIpv4HttpProof).append('\n')
            append("dnsResolutionOnceAuthorized=").append(plan.dnsResolutionOnceAuthorized).append('\n')
            append("requiresResolvedAddressSetContainsAcceptedIpv4=").append(plan.requiresResolvedAddressSetContainsAcceptedIpv4).append('\n')
            append("domainAddressedTcpConnectOnceAuthorized=").append(plan.domainAddressedTcpConnectOnceAuthorized).append('\n')
            append("domainAddressedHttpGetOnceAuthorized=").append(plan.domainAddressedHttpGetOnceAuthorized).append('\n')
            append("exactHostHeaderRequired=").append(plan.exactHostHeaderRequired).append('\n')
            append("requiresHttpStatus200=").append(plan.requiresHttpStatus200).append('\n')
            append("requiresContentLengthMatch=").append(plan.requiresContentLengthMatch).append('\n')
            append("requiresExactBodySha256=").append(plan.requiresExactBodySha256).append('\n')
            append("dnsResolutionClaimAuthorized=").append(plan.dnsResolutionClaimAuthorized).append('\n')
            append("externalDomainHttpReachabilityClaimAuthorized=").append(plan.externalDomainHttpReachabilityClaimAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(plan.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(plan.firewallMutationAuthorized).append('\n')
            append("httpsAuthorized=").append(plan.httpsAuthorized).append('\n')
            append("configMutationAuthorized=").append(plan.configMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(plan.packageInstallAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(plan.automaticRetryAuthorized).append('\n')
        }.encodeToByteArray())

    private fun canonicalDnsName(value: String): String {
        require(value.isNotBlank())
        require(value == value.trim())
        require(value.length <= 253)
        require(value.none(Char::isISOControl))
        require('*' !in value)
        val ascii = IDN.toASCII(value.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
        require(ascii.length <= 253 && '.' in ascii)
        require(ascii.split('.').all { label ->
            label.length in 1..63 && label.firstOrNull()?.isLetterOrDigit() == true &&
                label.lastOrNull()?.isLetterOrDigit() == true &&
                label.all { it.isLetterOrDigit() || it == '-' }
        })
        return ascii
    }

    private fun sha256Bytes(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
