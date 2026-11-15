package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityStatus
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
import com.velumtegra.xuimobile.core.site.SiteServerCertificateFileReference
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.io.ByteArrayOutputStream
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Locale
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Phase 11.97: final read-only HTTPS/TLS serving verifier for the post-coordinator certificate-reuse path.
 *
 * The boundary requires a validated Phase 11.67 composition, the exact Phase 11.68 HTTPS selection,
 * the successful Phase 11.91 nginx reload, and a fresh post-reload Phase 11.65 certificate observation
 * proving that the exact server-side certificate/key reference did not drift after reload. It then
 * performs one bounded DNS resolution and one platform-trusted HTTPS request to the exact resolved VPS
 * IPv4 with exact-domain SNI/hostname verification and exact generated index-body verification.
 *
 * No remote mutation, private-key content read, retry, coordinator replay or static-publication replay
 * is authorized by this phase.
 */
internal object SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_RESOLVED_ADDRESSES: Int = 16
    const val MAX_HEADER_BYTES: Int = 16 * 1024
    const val MAX_INDEX_BODY_BYTES: Int = 512 * 1024
    const val CONNECT_TIMEOUT_MILLIS: Int = 6_000
    const val READ_TIMEOUT_MILLIS: Int = 8_000

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    private val allowedTlsProtocols = listOf("TLSv1.3", "TLSv1.2")

    fun prepare(
        preparation: SiteDeployerLocalPreparationResult,
        certificateComposition: SiteProductionDeploymentCertificatePublicationCompositionResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        phase1191Execution: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
        freshCertificateEligibilityProof:
            SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionProof,
    ): SiteProductionDeploymentHttpsTlsServingVerificationPlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.validate(certificateComposition)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
            .validateExecutionResult(phase1191Execution)
        SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary
            .validateProof(freshCertificateEligibilityProof)

        require(
            selection.status == SiteProductionDeploymentServingPolicySelectionStatus
                .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
        ) { "Phase 11.97 requires the exact Phase 11.68 HTTPS existing-certificate selection" }
        require(selection.selectedProtocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
        require(selection.certificateCompositionSha256 == certificateComposition.compositionSha256)
        require(
            certificateComposition.status == SiteProductionDeploymentCertificatePublicationCompositionStatus
                .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE,
        )
        val publicationPlan = requireNotNull(selection.publicationPlan)
        val compositionPlan = requireNotNull(certificateComposition.publicationPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(publicationPlan == compositionPlan) {
            "Phase 11.97 selection publication plan differs from the validated certificate composition"
        }
        require(publicationPlan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
        require(preparation.remoteDeployPlan.certificate.mode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN)
        require(phase1191Execution.servingPolicySelectionSha256 == selection.selectionSha256)
        require(phase1191Execution.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(phase1191Execution.selectedProtocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
        require(phase1191Execution.expectedListenerLiveAfterReload)
        require(phase1191Execution.nginxReloadPerformed)
        require(!phase1191Execution.configMutationPerformed)
        require(!phase1191Execution.coordinatorReinvoked)
        require(!phase1191Execution.staticPublicationReplayPerformed)
        require(!phase1191Execution.automaticRetryPerformed)

        val freshReport = freshCertificateEligibilityProof.eligibilityReport
        require(
            freshReport.status == SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING,
        ) { "Phase 11.97 requires a fresh post-reload eligible Phase 11.65 certificate proof" }
        val freshReference = requireNotNull(freshReport.certificateReference)
        val boundReference = requireNotNull(certificateComposition.bindingReport.certificateReference)
        require(freshReference == boundReference) {
            "Phase 11.97 fresh post-reload certificate reference drifted from the exact Phase 11.67 binding"
        }
        require(freshCertificateEligibilityProof.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(freshReference.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(freshReference.certificateSha256 == publicationPlan.certificateSha256)
        require(freshReference.certificatePath == publicationPlan.certificatePath)
        require(freshReference.privateKeyPath == publicationPlan.privateKeyPath)
        require(publicationPlan.domain in freshReference.dnsNames)

        val reloadExecutedAt = phase1191Execution.phase1176ExecutionResult.phase11_61ExecutionProof.executedAtEpochMillis
        require(freshCertificateEligibilityProof.certificateEvaluatedAtEpochMillis >= reloadExecutedAt) {
            "Phase 11.97 certificate proof must be observed after the successful nginx reload"
        }

        return prepareAfterValidatedReload(
            preparation = preparation,
            certificateComposition = certificateComposition,
            selection = selection,
            postCoordinatorNginxReloadExecutionResultSha256 = phase1191Execution.executionResultSha256,
            freshCertificateEligibilityExecutionProofSha256 = freshCertificateEligibilityProof.executionProofSha256,
            freshCertificateReference = freshReference,
        )
    }

    /** Deterministic seam for unit tests after reload/certificate proofs have already been validated. */
    internal fun prepareAfterValidatedReload(
        preparation: SiteDeployerLocalPreparationResult,
        certificateComposition: SiteProductionDeploymentCertificatePublicationCompositionResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        postCoordinatorNginxReloadExecutionResultSha256: String,
        freshCertificateEligibilityExecutionProofSha256: String,
        freshCertificateReference: SiteServerCertificateFileReference,
    ): SiteProductionDeploymentHttpsTlsServingVerificationPlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.validate(certificateComposition)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        require(sha256.matches(postCoordinatorNginxReloadExecutionResultSha256))
        require(sha256.matches(freshCertificateEligibilityExecutionProofSha256))
        require(
            selection.status == SiteProductionDeploymentServingPolicySelectionStatus
                .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
        )
        require(selection.selectedProtocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
        require(selection.certificateCompositionSha256 == certificateComposition.compositionSha256)
        val publicationPlan = requireNotNull(selection.publicationPlan)
        val compositionPlan = requireNotNull(certificateComposition.publicationPlan)
        require(publicationPlan == compositionPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(publicationPlan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
        val boundReference = requireNotNull(certificateComposition.bindingReport.certificateReference)
        require(freshCertificateReference == boundReference)
        require(freshCertificateReference.certificateSha256 == publicationPlan.certificateSha256)
        require(freshCertificateReference.certificatePath == publicationPlan.certificatePath)
        require(freshCertificateReference.privateKeyPath == publicationPlan.privateKeyPath)
        require(publicationPlan.domain in freshCertificateReference.dnsNames)
        require(canonicalIpv4(publicationPlan.remoteHostIdentity) == publicationPlan.remoteHostIdentity) {
            "Phase 11.97 requires the accepted remote host to be a canonical literal IPv4 target"
        }

        val index = preparation.bundle.documents.singleOrNull { it.path == "index.html" }
            ?: throw IllegalArgumentException("Phase 11.97 requires exactly one generated index.html")
        require(index.byteSize in 1..MAX_INDEX_BODY_BYTES)
        require(sha256.matches(index.sha256))

        val base = SiteProductionDeploymentHttpsTlsServingVerificationPlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            certificateCompositionSha256 = certificateComposition.compositionSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            postCoordinatorNginxReloadExecutionResultSha256 = postCoordinatorNginxReloadExecutionResultSha256,
            freshCertificateEligibilityExecutionProofSha256 = freshCertificateEligibilityExecutionProofSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            targetIpv4Literal = publicationPlan.remoteHostIdentity,
            domain = publicationPlan.domain,
            port = publicationPlan.port,
            expectedCertificateFileSha256 = freshCertificateReference.certificateSha256,
            expectedCertificateDnsNames = freshCertificateReference.dnsNames,
            expectedCertificatePath = freshCertificateReference.certificatePath,
            expectedPrivateKeyPath = freshCertificateReference.privateKeyPath,
            expectedBodySha256 = index.sha256,
            expectedBodyBytes = index.byteSize,
            requestPath = "/index.html",
            maxResolvedAddresses = MAX_RESOLVED_ADDRESSES,
            maxHeaderBytes = MAX_HEADER_BYTES,
            connectTimeoutMillis = CONNECT_TIMEOUT_MILLIS,
            readTimeoutMillis = READ_TIMEOUT_MILLIS,
            allowedTlsProtocols = allowedTlsProtocols,
            requiresFreshPostReloadCertificateProof = true,
            requiresExactCertificateReferenceMatch = true,
            requiresDomainResolutionOnce = true,
            requiresResolvedSetToContainExactIpv4 = true,
            requiresTlsHandshakeOnce = true,
            requiresPlatformTrustValidation = true,
            requiresExactHostnameVerification = true,
            requiresExactPeerDnsNames = true,
            requiresHttpsGetOnce = true,
            requiresHttpStatus200 = true,
            requiresContentLengthMatch = true,
            requiresExactBodySha256 = true,
            remoteMutationAuthorized = false,
            certificateMutationAuthorized = false,
            privateKeyContentReadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            verificationPlanSha256 = "",
        )
        return base.copy(verificationPlanSha256 = planSha256(base)).also(::validatePlan)
    }

    suspend fun executeOnce(
        plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentHttpsTlsServingVerificationResult = withContext(Dispatchers.IO) {
        executeWithAdapters(
            plan = plan,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            resolver = SystemDnsResolver,
            probe = PlatformHttpsTlsProbe,
        )
    }

    internal fun executeWithAdapters(
        plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        resolver: DnsResolver,
        probe: HttpsTlsProbe,
    ): SiteProductionDeploymentHttpsTlsServingVerificationResult {
        validatePlan(plan)
        require(canonicalId.matches(executionAttemptId))
        require(executedAtEpochMillis > 0L)

        val resolvedAddresses = resolver.resolveOnce(plan.domain)
            .map(::canonicalIpAddress)
            .distinct()
            .sorted()
        require(resolvedAddresses.isNotEmpty()) { "Phase 11.97 DNS resolution returned no addresses" }
        require(resolvedAddresses.size <= plan.maxResolvedAddresses) {
            "Phase 11.97 DNS resolution exceeded the bounded address count"
        }
        require(plan.targetIpv4Literal in resolvedAddresses) {
            "Phase 11.97 exact publication IPv4 is absent from the resolved domain address set"
        }

        val observation = probe.probeOnce(
            plan = plan,
            selectedResolvedAddress = plan.targetIpv4Literal,
            executedAtEpochMillis = executedAtEpochMillis,
        )
        require(observation.selectedResolvedAddress == plan.targetIpv4Literal)
        require(observation.sniDomain == plan.domain)
        require(observation.tlsProtocol in plan.allowedTlsProtocols)
        require(observation.platformTrustValidated)
        require(observation.exactHostnameVerified)
        require(observation.peerCertificateDnsNames == plan.expectedCertificateDnsNames) {
            "Phase 11.97 peer certificate DNS SANs differ from the fresh exact server-side reference"
        }
        require(sha256.matches(observation.peerLeafCertificateDerSha256))
        require(observation.httpStatusCode == 200)
        require(observation.contentLength == plan.expectedBodyBytes)
        require(observation.observedBodySha256 == plan.expectedBodySha256)

        val base = SiteProductionDeploymentHttpsTlsServingVerificationResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentHttpsTlsServingVerificationStatus
                .HTTPS_TLS_IDENTITY_AND_EXACT_INDEX_VERIFIED,
            verificationPlanSha256 = plan.verificationPlanSha256,
            preparationSha256 = plan.preparationSha256,
            certificateCompositionSha256 = plan.certificateCompositionSha256,
            servingPolicySelectionSha256 = plan.servingPolicySelectionSha256,
            postCoordinatorNginxReloadExecutionResultSha256 =
                plan.postCoordinatorNginxReloadExecutionResultSha256,
            freshCertificateEligibilityExecutionProofSha256 =
                plan.freshCertificateEligibilityExecutionProofSha256,
            publicationPlanSha256 = plan.publicationPlanSha256,
            remoteHostIdentity = plan.remoteHostIdentity,
            targetIpv4Literal = plan.targetIpv4Literal,
            domain = plan.domain,
            port = plan.port,
            executionAttemptId = executionAttemptId,
            dnsResolutionPerformed = true,
            dnsResolutionInvocationCount = 1,
            resolvedAddresses = resolvedAddresses,
            resolvedSetContainsExactIpv4 = true,
            selectedResolvedAddress = plan.targetIpv4Literal,
            tcpConnectPerformed = true,
            tlsHandshakePerformed = true,
            tlsProtocol = observation.tlsProtocol,
            platformTrustValidated = observation.platformTrustValidated,
            exactHostnameVerified = observation.exactHostnameVerified,
            sniDomain = observation.sniDomain,
            peerLeafCertificateDerSha256 = observation.peerLeafCertificateDerSha256,
            peerCertificateDnsNames = observation.peerCertificateDnsNames,
            expectedCertificateFileSha256 = plan.expectedCertificateFileSha256,
            exactPeerDnsNamesVerified = true,
            httpsGetPerformed = true,
            httpStatusCode = observation.httpStatusCode,
            contentLength = observation.contentLength,
            expectedBodyBytes = plan.expectedBodyBytes,
            expectedBodySha256 = plan.expectedBodySha256,
            observedBodySha256 = observation.observedBodySha256,
            exactBodySha256Verified = true,
            remoteMutationPerformed = false,
            certificateMutationPerformed = false,
            privateKeyContentReadPerformed = false,
            dnsMutationPerformed = false,
            firewallMutationPerformed = false,
            packageInstallPerformed = false,
            automaticRetryPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            executedAtEpochMillis = executedAtEpochMillis,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = resultSha256(base)).also(::validateResult)
    }

    fun validatePlan(plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        listOf(
            plan.preparationSha256,
            plan.certificateCompositionSha256,
            plan.servingPolicySelectionSha256,
            plan.postCoordinatorNginxReloadExecutionResultSha256,
            plan.freshCertificateEligibilityExecutionProofSha256,
            plan.publicationPlanSha256,
            plan.expectedCertificateFileSha256,
            plan.expectedBodySha256,
            plan.verificationPlanSha256,
        ).forEach { require(sha256.matches(it)) }
        require(plan.remoteHostIdentity == plan.targetIpv4Literal)
        require(canonicalIpv4(plan.targetIpv4Literal) == plan.targetIpv4Literal)
        require(plan.domain == normalizeDomainExact(plan.domain))
        require(plan.port in 1..65535)
        require(plan.expectedCertificateDnsNames.isNotEmpty())
        require(plan.expectedCertificateDnsNames == plan.expectedCertificateDnsNames.distinct().sorted())
        require(plan.expectedCertificateDnsNames.all { it == normalizeDomainExact(it) })
        require(plan.domain in plan.expectedCertificateDnsNames)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.expectedCertificatePath) == plan.expectedCertificatePath)
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.expectedPrivateKeyPath) == plan.expectedPrivateKeyPath)
        require(plan.expectedCertificatePath != plan.expectedPrivateKeyPath)
        require(plan.expectedBodyBytes in 1..MAX_INDEX_BODY_BYTES)
        require(plan.requestPath == "/index.html")
        require(plan.maxResolvedAddresses == MAX_RESOLVED_ADDRESSES)
        require(plan.maxHeaderBytes == MAX_HEADER_BYTES)
        require(plan.connectTimeoutMillis == CONNECT_TIMEOUT_MILLIS)
        require(plan.readTimeoutMillis == READ_TIMEOUT_MILLIS)
        require(plan.allowedTlsProtocols == allowedTlsProtocols)
        require(plan.requiresFreshPostReloadCertificateProof)
        require(plan.requiresExactCertificateReferenceMatch)
        require(plan.requiresDomainResolutionOnce)
        require(plan.requiresResolvedSetToContainExactIpv4)
        require(plan.requiresTlsHandshakeOnce)
        require(plan.requiresPlatformTrustValidation)
        require(plan.requiresExactHostnameVerification)
        require(plan.requiresExactPeerDnsNames)
        require(plan.requiresHttpsGetOnce)
        require(plan.requiresHttpStatus200)
        require(plan.requiresContentLengthMatch)
        require(plan.requiresExactBodySha256)
        require(!plan.remoteMutationAuthorized)
        require(!plan.certificateMutationAuthorized)
        require(!plan.privateKeyContentReadAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.automaticRetryAuthorized)
        require(!plan.coordinatorReinvocationAuthorized)
        require(!plan.staticPublicationReplayAuthorized)
        require(plan.verificationPlanSha256 == planSha256(plan.copy(verificationPlanSha256 = "")))
    }

    fun validateResult(result: SiteProductionDeploymentHttpsTlsServingVerificationResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status == SiteProductionDeploymentHttpsTlsServingVerificationStatus
                .HTTPS_TLS_IDENTITY_AND_EXACT_INDEX_VERIFIED,
        )
        listOf(
            result.verificationPlanSha256,
            result.preparationSha256,
            result.certificateCompositionSha256,
            result.servingPolicySelectionSha256,
            result.postCoordinatorNginxReloadExecutionResultSha256,
            result.freshCertificateEligibilityExecutionProofSha256,
            result.publicationPlanSha256,
            result.peerLeafCertificateDerSha256,
            result.expectedCertificateFileSha256,
            result.expectedBodySha256,
            result.observedBodySha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(result.remoteHostIdentity == result.targetIpv4Literal)
        require(canonicalIpv4(result.targetIpv4Literal) == result.targetIpv4Literal)
        require(result.domain == normalizeDomainExact(result.domain))
        require(result.port in 1..65535)
        require(canonicalId.matches(result.executionAttemptId))
        require(result.dnsResolutionPerformed && result.dnsResolutionInvocationCount == 1)
        require(result.resolvedAddresses.isNotEmpty() && result.resolvedAddresses.size <= MAX_RESOLVED_ADDRESSES)
        require(result.resolvedAddresses == result.resolvedAddresses.distinct().sorted())
        require(result.targetIpv4Literal in result.resolvedAddresses)
        require(result.resolvedSetContainsExactIpv4)
        require(result.selectedResolvedAddress == result.targetIpv4Literal)
        require(result.tcpConnectPerformed)
        require(result.tlsHandshakePerformed)
        require(result.tlsProtocol in allowedTlsProtocols)
        require(result.platformTrustValidated)
        require(result.exactHostnameVerified)
        require(result.sniDomain == result.domain)
        require(result.peerCertificateDnsNames.isNotEmpty())
        require(result.domain in result.peerCertificateDnsNames)
        require(result.exactPeerDnsNamesVerified)
        require(result.httpsGetPerformed)
        require(result.httpStatusCode == 200)
        require(result.expectedBodyBytes > 0)
        require(result.contentLength == result.expectedBodyBytes)
        require(result.expectedBodySha256 == result.observedBodySha256)
        require(result.exactBodySha256Verified)
        require(!result.remoteMutationPerformed)
        require(!result.certificateMutationPerformed)
        require(!result.privateKeyContentReadPerformed)
        require(!result.dnsMutationPerformed)
        require(!result.firewallMutationPerformed)
        require(!result.packageInstallPerformed)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(result.executedAtEpochMillis > 0L)
        require(result.executionResultSha256 == resultSha256(result.copy(executionResultSha256 = "")))
    }

    internal fun interface DnsResolver {
        fun resolveOnce(domain: String): List<String>
    }

    internal data class HttpsTlsObservation(
        val selectedResolvedAddress: String,
        val tlsProtocol: String,
        val platformTrustValidated: Boolean,
        val exactHostnameVerified: Boolean,
        val sniDomain: String,
        val peerLeafCertificateDerSha256: String,
        val peerCertificateDnsNames: List<String>,
        val httpStatusCode: Int,
        val contentLength: Int,
        val observedBodySha256: String,
    )

    internal fun interface HttpsTlsProbe {
        fun probeOnce(
            plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
            selectedResolvedAddress: String,
            executedAtEpochMillis: Long,
        ): HttpsTlsObservation
    }

    private object SystemDnsResolver : DnsResolver {
        override fun resolveOnce(domain: String): List<String> {
            val local = InetAddress.getAllByName(domain).map { it.hostAddress.orEmpty() }
            // A VPN "fake-ip" resolver on the phone answers 198.18.x.x for every name. Ask public DNS
            // instead (through the same tunnel); the TLS probe then dials the exact real address.
            if (local.none(com.velumtegra.xuimobile.core.ssh.DnsOverHttpsResolver::isVpnFakeIp)) return local
            return try {
                com.velumtegra.xuimobile.core.ssh.DnsOverHttpsResolver.resolveA(domain)?.takeIf { it.isNotEmpty() } ?: local
            } catch (_: Exception) {
                local
            }
        }
    }

    private object PlatformHttpsTlsProbe : HttpsTlsProbe {
        override fun probeOnce(
            plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
            selectedResolvedAddress: String,
            executedAtEpochMillis: Long,
        ): HttpsTlsObservation {
            val address = InetAddress.getByAddress(
                selectedResolvedAddress,
                ipv4Bytes(selectedResolvedAddress),
            )
            val tcpSocket = Socket()
            try {
                tcpSocket.soTimeout = plan.readTimeoutMillis
                tcpSocket.connect(InetSocketAddress(address, plan.port), plan.connectTimeoutMillis)
                val sslSocket = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(tcpSocket, plan.domain, plan.port, true) as SSLSocket
                sslSocket.use { socket ->
                    socket.soTimeout = plan.readTimeoutMillis
                    val supported = socket.supportedProtocols.toSet()
                    val enabled = plan.allowedTlsProtocols.filter { it in supported }
                    require(enabled.isNotEmpty()) { "Phase 11.97 device TLS stack supports none of the reviewed TLS protocols" }
                    socket.enabledProtocols = enabled.toTypedArray()
                    val parameters = socket.sslParameters
                    parameters.endpointIdentificationAlgorithm = "HTTPS"
                    parameters.serverNames = listOf(SNIHostName(plan.domain))
                    socket.sslParameters = parameters
                    socket.startHandshake()

                    val session = socket.session
                    require(session.protocol in plan.allowedTlsProtocols) {
                        "Phase 11.97 negotiated an unreviewed TLS protocol ${session.protocol}"
                    }
                    val peer = session.peerCertificates.firstOrNull() as? X509Certificate
                        ?: throw IllegalArgumentException("Phase 11.97 peer leaf certificate is unavailable")
                    peer.checkValidity(Date(executedAtEpochMillis))
                    val peerDnsNames = peerDnsNames(peer)
                    require(peerDnsNames == plan.expectedCertificateDnsNames) {
                        "Phase 11.97 peer certificate DNS SANs differ from the fresh server-side certificate metadata"
                    }
                    val peerDerSha = digestBytes(peer.encoded)

                    val request = buildString {
                        append("GET ").append(plan.requestPath).append(" HTTP/1.1\r\n")
                        append("Host: ").append(plan.domain).append("\r\n")
                        append("Accept-Encoding: identity\r\n")
                        append("Connection: close\r\n\r\n")
                    }.toByteArray(StandardCharsets.US_ASCII)
                    socket.outputStream.write(request)
                    socket.outputStream.flush()
                    val response = readExactHttpResponse(socket, plan)
                    return HttpsTlsObservation(
                        selectedResolvedAddress = selectedResolvedAddress,
                        tlsProtocol = session.protocol,
                        platformTrustValidated = true,
                        exactHostnameVerified = true,
                        sniDomain = plan.domain,
                        peerLeafCertificateDerSha256 = peerDerSha,
                        peerCertificateDnsNames = peerDnsNames,
                        httpStatusCode = response.statusCode,
                        contentLength = response.contentLength,
                        observedBodySha256 = response.bodySha256,
                    )
                }
            } finally {
                runCatching { tcpSocket.close() }
            }
        }
    }

    private data class ParsedResponse(val statusCode: Int, val contentLength: Int, val bodySha256: String)

    private fun readExactHttpResponse(
        socket: SSLSocket,
        plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
    ): ParsedResponse {
        val maxTotalBytes = plan.maxHeaderBytes + plan.expectedBodyBytes + 4
        val capture = ByteArrayOutputStream(minOf(maxTotalBytes, 64 * 1024))
        val buffer = ByteArray(8192)
        val input = socket.inputStream
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            require(capture.size() + read <= maxTotalBytes) {
                "Phase 11.97 HTTPS response exceeded the bounded capture"
            }
            capture.write(buffer, 0, read)
        }
        return parseExactHttpResponse(capture.toByteArray(), plan)
    }

    private fun parseExactHttpResponse(
        bytes: ByteArray,
        plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
    ): ParsedResponse {
        val delimiter = byteArrayOf(13, 10, 13, 10)
        val headerEnd = indexOf(bytes, delimiter)
        require(headerEnd >= 0) { "Phase 11.97 HTTPS response headers are incomplete" }
        require(headerEnd + delimiter.size <= plan.maxHeaderBytes) {
            "Phase 11.97 HTTPS response headers exceeded the bound"
        }
        val headerText = String(bytes.copyOfRange(0, headerEnd), StandardCharsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        require(lines.isNotEmpty())
        val statusParts = lines.first().split(' ', limit = 3)
        require(statusParts.size >= 2 && statusParts[0].startsWith("HTTP/")) {
            "Phase 11.97 malformed HTTPS status line"
        }
        val status = statusParts[1].toIntOrNull()
            ?: throw IllegalArgumentException("Phase 11.97 malformed HTTPS status code")
        require(status == 200) { "Phase 11.97 expected HTTP 200 over TLS but received $status" }

        val headers = lines.drop(1).mapNotNull { line ->
            val split = line.indexOf(':')
            if (split <= 0) null else line.substring(0, split).trim().lowercase() to line.substring(split + 1).trim()
        }
        require(headers.none { it.first == "transfer-encoding" }) {
            "Phase 11.97 chunked transfer is outside exact-body verification"
        }
        val encodings = headers.filter { it.first == "content-encoding" }.map { it.second.lowercase() }
        require(encodings.all { it == "identity" }) {
            "Phase 11.97 encoded body is outside exact-body verification"
        }
        val lengths = headers.filter { it.first == "content-length" }.map { it.second }
        require(lengths.size == 1) { "Phase 11.97 requires exactly one Content-Length" }
        val contentLength = lengths.single().toIntOrNull()
            ?: throw IllegalArgumentException("Phase 11.97 invalid Content-Length")
        require(contentLength == plan.expectedBodyBytes) { "Phase 11.97 Content-Length mismatch" }
        val bodyStart = headerEnd + delimiter.size
        require(bytes.size - bodyStart == contentLength) { "Phase 11.97 captured body length mismatch" }
        val bodySha = digestBytes(bytes.copyOfRange(bodyStart, bytes.size))
        require(bodySha == plan.expectedBodySha256) { "Phase 11.97 served index SHA-256 mismatch" }
        return ParsedResponse(status, contentLength, bodySha)
    }

    /**
     * Mirrors the canonical core/site domain normalization rules locally because that helper is
     * internal to the core:site Gradle module and intentionally not part of the app module API.
     */
    private fun normalizeDomainExact(value: String): String {
        require(value.isNotBlank()) { "Certificate domain must not be blank" }
        require(value == value.trim()) { "Certificate domain must not contain surrounding whitespace" }
        require(value.length <= 253) { "Certificate domain is too long" }
        require(value.none(Char::isISOControl)) { "Certificate domain contains control characters" }
        require('*' !in value) { "Wildcard certificate reuse is outside this contract" }
        val ascii = IDN.toASCII(value.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
        require(ascii.length <= 253 && '.' in ascii) { "Certificate domain must be a fully qualified DNS name" }
        require(ascii.split('.').all { label ->
            label.length in 1..63 && label.firstOrNull()?.isLetterOrDigit() == true &&
                label.lastOrNull()?.isLetterOrDigit() == true &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }) { "Certificate domain is not canonical/safe" }
        return ascii
    }

    private fun peerDnsNames(certificate: X509Certificate): List<String> {
        val names = certificate.subjectAlternativeNames.orEmpty().mapNotNull { entry ->
            val type = entry.getOrNull(0) as? Int
            val value = entry.getOrNull(1) as? String
            if (type == 2 && value != null) normalizeDomainExact(value) else null
        }.distinct().sorted()
        require(names.isNotEmpty()) { "Phase 11.97 peer certificate has no exact normalizable DNS SANs" }
        return names
    }

    private fun canonicalIpAddress(value: String): String {
        val withoutScope = value.substringBefore('%')
        canonicalIpv4(withoutScope)?.let { return it }
        val parsed = InetAddress.getByName(withoutScope)
        require(parsed.hostAddress.substringBefore('%') == withoutScope.lowercase() || ':' in withoutScope) {
            "Phase 11.97 DNS resolver returned a non-canonical address"
        }
        return parsed.hostAddress.substringBefore('%').lowercase()
    }

    private fun canonicalIpv4(value: String): String? = runCatching {
        val bytes = ipv4Bytes(value)
        bytes.joinToString(".") { (it.toInt() and 0xff).toString() }.takeIf { it == value }
    }.getOrNull()

    private fun ipv4Bytes(value: String): ByteArray {
        val parts = value.split('.')
        require(parts.size == 4)
        return ByteArray(4) { index ->
            val raw = parts[index]
            require(raw.isNotEmpty() && raw.length <= 3 && raw.all(Char::isDigit))
            require(raw == "0" || !raw.startsWith('0'))
            val number = raw.toInt()
            require(number in 0..255)
            number.toByte()
        }
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        for (start in 0..haystack.size - needle.size) {
            var matched = true
            for (i in needle.indices) {
                if (haystack[start + i] != needle[i]) {
                    matched = false
                    break
                }
            }
            if (matched) return start
        }
        return -1
    }

    private fun planSha256(plan: SiteProductionDeploymentHttpsTlsServingVerificationPlan): String = digest(buildString {
        append("phase=11.97\n")
        append("contractVersion=").append(plan.contractVersion).append('\n')
        append("preparation=").append(plan.preparationSha256).append('\n')
        append("certificateComposition=").append(plan.certificateCompositionSha256).append('\n')
        append("servingPolicySelection=").append(plan.servingPolicySelectionSha256).append('\n')
        append("postCoordinatorNginxReload=").append(plan.postCoordinatorNginxReloadExecutionResultSha256).append('\n')
        append("freshCertificateProof=").append(plan.freshCertificateEligibilityExecutionProofSha256).append('\n')
        append("publicationPlan=").append(plan.publicationPlanSha256).append('\n')
        append("host=").append(plan.remoteHostIdentity).append('\n')
        append("targetIpv4=").append(plan.targetIpv4Literal).append('\n')
        append("domain=").append(plan.domain).append('\n')
        append("port=").append(plan.port).append('\n')
        append("certificateFileSha=").append(plan.expectedCertificateFileSha256).append('\n')
        plan.expectedCertificateDnsNames.forEach { append("certificateDns=").append(it).append('\n') }
        append("certificatePath=").append(plan.expectedCertificatePath).append('\n')
        append("privateKeyPath=").append(plan.expectedPrivateKeyPath).append('\n')
        append("bodySha=").append(plan.expectedBodySha256).append('\n')
        append("bodyBytes=").append(plan.expectedBodyBytes).append('\n')
        append("requestPath=").append(plan.requestPath).append('\n')
        append("maxResolvedAddresses=").append(plan.maxResolvedAddresses).append('\n')
        append("maxHeaderBytes=").append(plan.maxHeaderBytes).append('\n')
        append("connectTimeoutMillis=").append(plan.connectTimeoutMillis).append('\n')
        append("readTimeoutMillis=").append(plan.readTimeoutMillis).append('\n')
        plan.allowedTlsProtocols.forEach { append("tlsProtocol=").append(it).append('\n') }
        append("requiresFreshPostReloadCertificateProof=").append(plan.requiresFreshPostReloadCertificateProof).append('\n')
        append("requiresExactCertificateReferenceMatch=").append(plan.requiresExactCertificateReferenceMatch).append('\n')
        append("requiresDomainResolutionOnce=").append(plan.requiresDomainResolutionOnce).append('\n')
        append("requiresResolvedSetToContainExactIpv4=").append(plan.requiresResolvedSetToContainExactIpv4).append('\n')
        append("requiresTlsHandshakeOnce=").append(plan.requiresTlsHandshakeOnce).append('\n')
        append("requiresPlatformTrustValidation=").append(plan.requiresPlatformTrustValidation).append('\n')
        append("requiresExactHostnameVerification=").append(plan.requiresExactHostnameVerification).append('\n')
        append("requiresExactPeerDnsNames=").append(plan.requiresExactPeerDnsNames).append('\n')
        append("requiresHttpsGetOnce=").append(plan.requiresHttpsGetOnce).append('\n')
        append("requiresHttpStatus200=").append(plan.requiresHttpStatus200).append('\n')
        append("requiresContentLengthMatch=").append(plan.requiresContentLengthMatch).append('\n')
        append("requiresExactBodySha256=").append(plan.requiresExactBodySha256).append('\n')
        append("remoteMutationAuthorized=").append(plan.remoteMutationAuthorized).append('\n')
        append("certificateMutationAuthorized=").append(plan.certificateMutationAuthorized).append('\n')
        append("privateKeyContentReadAuthorized=").append(plan.privateKeyContentReadAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(plan.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(plan.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(plan.packageInstallAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(plan.automaticRetryAuthorized).append('\n')
        append("coordinatorReinvocationAuthorized=").append(plan.coordinatorReinvocationAuthorized).append('\n')
        append("staticPublicationReplayAuthorized=").append(plan.staticPublicationReplayAuthorized).append('\n')
    })

    private fun resultSha256(result: SiteProductionDeploymentHttpsTlsServingVerificationResult): String = digest(buildString {
        append("phase=11.97\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("plan=").append(result.verificationPlanSha256).append('\n')
        append("preparation=").append(result.preparationSha256).append('\n')
        append("certificateComposition=").append(result.certificateCompositionSha256).append('\n')
        append("servingPolicySelection=").append(result.servingPolicySelectionSha256).append('\n')
        append("postCoordinatorNginxReload=").append(result.postCoordinatorNginxReloadExecutionResultSha256).append('\n')
        append("freshCertificateProof=").append(result.freshCertificateEligibilityExecutionProofSha256).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("host=").append(result.remoteHostIdentity).append('\n')
        append("targetIpv4=").append(result.targetIpv4Literal).append('\n')
        append("domain=").append(result.domain).append('\n')
        append("port=").append(result.port).append('\n')
        append("attempt=").append(result.executionAttemptId).append('\n')
        append("dnsResolutionPerformed=").append(result.dnsResolutionPerformed).append('\n')
        append("dnsResolutionInvocationCount=").append(result.dnsResolutionInvocationCount).append('\n')
        result.resolvedAddresses.forEach { append("resolved=").append(it).append('\n') }
        append("resolvedSetContainsExactIpv4=").append(result.resolvedSetContainsExactIpv4).append('\n')
        append("selectedResolvedAddress=").append(result.selectedResolvedAddress).append('\n')
        append("tcpConnectPerformed=").append(result.tcpConnectPerformed).append('\n')
        append("tlsHandshakePerformed=").append(result.tlsHandshakePerformed).append('\n')
        append("tlsProtocol=").append(result.tlsProtocol).append('\n')
        append("platformTrustValidated=").append(result.platformTrustValidated).append('\n')
        append("exactHostnameVerified=").append(result.exactHostnameVerified).append('\n')
        append("sniDomain=").append(result.sniDomain).append('\n')
        append("peerLeafCertificateDerSha=").append(result.peerLeafCertificateDerSha256).append('\n')
        result.peerCertificateDnsNames.forEach { append("peerDns=").append(it).append('\n') }
        append("expectedCertificateFileSha=").append(result.expectedCertificateFileSha256).append('\n')
        append("exactPeerDnsNamesVerified=").append(result.exactPeerDnsNamesVerified).append('\n')
        append("httpsGetPerformed=").append(result.httpsGetPerformed).append('\n')
        append("httpStatusCode=").append(result.httpStatusCode).append('\n')
        append("contentLength=").append(result.contentLength).append('\n')
        append("expectedBodyBytes=").append(result.expectedBodyBytes).append('\n')
        append("expectedBodySha=").append(result.expectedBodySha256).append('\n')
        append("observedBodySha=").append(result.observedBodySha256).append('\n')
        append("exactBodySha256Verified=").append(result.exactBodySha256Verified).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("certificateMutationPerformed=").append(result.certificateMutationPerformed).append('\n')
        append("privateKeyContentReadPerformed=").append(result.privateKeyContentReadPerformed).append('\n')
        append("dnsMutationPerformed=").append(result.dnsMutationPerformed).append('\n')
        append("firewallMutationPerformed=").append(result.firewallMutationPerformed).append('\n')
        append("packageInstallPerformed=").append(result.packageInstallPerformed).append('\n')
        append("automaticRetryPerformed=").append(result.automaticRetryPerformed).append('\n')
        append("coordinatorReinvoked=").append(result.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(result.staticPublicationReplayPerformed).append('\n')
        append("executedAt=").append(result.executedAtEpochMillis).append('\n')
    })

    private fun digest(value: String): String = digestBytes(value.encodeToByteArray())

    private fun digestBytes(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
