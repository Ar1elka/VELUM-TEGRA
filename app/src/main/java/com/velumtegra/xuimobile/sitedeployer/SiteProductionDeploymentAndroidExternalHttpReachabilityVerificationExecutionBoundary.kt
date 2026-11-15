package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingExternalHttpReachabilityVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingExternalHttpReachabilityVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Phase 11.63 performs exactly one bounded external HTTP probe from the Android device. */
internal object SiteProductionDeploymentAndroidExternalHttpReachabilityVerificationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
        loopbackProof: SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof,
        verificationPlan: SiteWebServingExternalHttpReachabilityVerificationPlan,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof = withContext(Dispatchers.IO) {
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingLiveHttpVerificationBoundary.validate(loopbackVerificationPlan)
        SiteWebServingExternalHttpReachabilityVerificationBoundary.validate(verificationPlan)
        SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary.validateProof(loopbackProof)
        require(verificationPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(verificationPlan.loopbackVerificationPlanSha256 == loopbackVerificationPlan.verificationPlanSha256)
        require(verificationPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(verificationPlan.targetIpv4Literal == publicationPlan.remoteHostIdentity)
        require(verificationPlan.domain == publicationPlan.domain)
        require(verificationPlan.port == publicationPlan.port)
        require(verificationPlan.requestPath == loopbackVerificationPlan.requestPath)
        require(verificationPlan.expectedBodySha256 == loopbackVerificationPlan.expectedBodySha256)
        require(verificationPlan.expectedBodyBytes == loopbackVerificationPlan.expectedBodyBytes)
        require(loopbackProof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(loopbackProof.verificationPlanSha256 == loopbackVerificationPlan.verificationPlanSha256)
        require(loopbackProof.status == SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionStatus.LIVE_HTTP_INDEX_VERIFIED_OVER_REMOTE_LOOPBACK)
        require(loopbackProof.httpStatusCode == 200)
        require(loopbackProof.exactBodySha256Verified)
        require(loopbackProof.observedBodySha256 == verificationPlan.expectedBodySha256)
        require(!loopbackProof.externalReachabilityClaimed)
        require(executionAttemptId.matches(canonicalId))
        require(executedAtEpochMillis > 0L)

        val response = performSingleExternalHttpGet(verificationPlan)
        val base = SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionStatus.EXTERNAL_HTTP_INDEX_VERIFIED_FROM_ANDROID_IPV4,
            verificationPlanSha256 = verificationPlan.verificationPlanSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            loopbackVerificationPlanSha256 = loopbackVerificationPlan.verificationPlanSha256,
            loopbackExecutionProofSha256 = loopbackProof.executionProofSha256,
            remoteHostIdentity = verificationPlan.remoteHostIdentity,
            targetIpv4Literal = verificationPlan.targetIpv4Literal,
            port = verificationPlan.port,
            domain = verificationPlan.domain,
            requestPath = verificationPlan.requestPath,
            executionAttemptId = executionAttemptId,
            externalTcpConnectPerformed = true,
            externalHttpGetPerformed = true,
            httpStatusCode = response.statusCode,
            contentLength = response.contentLength,
            expectedBodyBytes = verificationPlan.expectedBodyBytes,
            expectedBodySha256 = verificationPlan.expectedBodySha256,
            observedBodySha256 = response.bodySha256,
            exactBodySha256Verified = response.bodySha256 == verificationPlan.expectedBodySha256,
            externalNetworkPathReachabilityProved = true,
            dnsResolutionPerformed = false,
            dnsResolutionClaimed = false,
            dnsMutationPerformed = false,
            firewallMutationPerformed = false,
            httpsUsed = false,
            httpsClaimed = false,
            configMutationPerformed = false,
            packageInstallPerformed = false,
            automaticRetryPerformed = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            executedAtEpochMillis = executedAtEpochMillis,
            executionProofSha256 = "",
        )
        base.copy(executionProofSha256 = proofSha256(base)).also(::validateProof)
    }

    fun validateProof(proof: SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.status == SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionStatus.EXTERNAL_HTTP_INDEX_VERIFIED_FROM_ANDROID_IPV4)
        listOf(
            proof.verificationPlanSha256,
            proof.publicationPlanSha256,
            proof.loopbackVerificationPlanSha256,
            proof.loopbackExecutionProofSha256,
            proof.expectedBodySha256,
            proof.observedBodySha256,
            proof.executionProofSha256,
        ).forEach { require(sha256.matches(it)) }
        require(proof.remoteHostIdentity == proof.targetIpv4Literal)
        require(proof.port in 1..65535)
        require(proof.domain.isNotBlank())
        require(proof.requestPath == "/index.html")
        require(proof.executionAttemptId.matches(canonicalId))
        require(proof.externalTcpConnectPerformed)
        require(proof.externalHttpGetPerformed)
        require(proof.httpStatusCode == 200)
        require(proof.expectedBodyBytes > 0)
        require(proof.contentLength == proof.expectedBodyBytes)
        require(proof.expectedBodySha256 == proof.observedBodySha256)
        require(proof.exactBodySha256Verified)
        require(proof.externalNetworkPathReachabilityProved)
        require(!proof.dnsResolutionPerformed)
        require(!proof.dnsResolutionClaimed)
        require(!proof.dnsMutationPerformed)
        require(!proof.firewallMutationPerformed)
        require(!proof.httpsUsed)
        require(!proof.httpsClaimed)
        require(!proof.configMutationPerformed)
        require(!proof.packageInstallPerformed)
        require(!proof.automaticRetryPerformed)
        require(!proof.coordinatorInvoked)
        require(!proof.exposesDeployUiAction)
        require(proof.executedAtEpochMillis > 0L)
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = "")))
    }

    private data class ParsedResponse(val statusCode: Int, val contentLength: Int, val bodySha256: String)

    private fun performSingleExternalHttpGet(plan: SiteWebServingExternalHttpReachabilityVerificationPlan): ParsedResponse {
        val address = InetAddress.getByAddress(
            plan.targetIpv4Literal,
            SiteWebServingExternalHttpReachabilityVerificationBoundary.literalIpv4Bytes(plan.targetIpv4Literal),
        )
        val socket = Socket()
        try {
            socket.soTimeout = plan.readTimeoutMillis
            socket.connect(InetSocketAddress(address, plan.port), plan.connectTimeoutMillis)
            val request = buildString {
                append("GET ").append(plan.requestPath).append(" HTTP/1.1\r\n")
                append("Host: ").append(plan.domain).append("\r\n")
                append("Accept-Encoding: identity\r\n")
                append("Connection: close\r\n\r\n")
            }.toByteArray(StandardCharsets.US_ASCII)
            val output = socket.getOutputStream()
            output.write(request)
            output.flush()
            val maxTotalBytes = plan.maxHeaderBytes + plan.expectedBodyBytes + 4
            val capture = ByteArrayOutputStream(minOf(maxTotalBytes, 64 * 1024))
            val buffer = ByteArray(8192)
            val input = socket.getInputStream()
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                require(capture.size() + read <= maxTotalBytes) { "Phase 11.63 external HTTP response exceeded bounded capture" }
                capture.write(buffer, 0, read)
            }
            return parseExactResponse(capture.toByteArray(), plan)
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun parseExactResponse(
        bytes: ByteArray,
        plan: SiteWebServingExternalHttpReachabilityVerificationPlan,
    ): ParsedResponse {
        val delimiter = byteArrayOf(13, 10, 13, 10)
        val headerEnd = indexOf(bytes, delimiter)
        require(headerEnd >= 0) { "Phase 11.63 HTTP response headers are incomplete" }
        require(headerEnd + delimiter.size <= plan.maxHeaderBytes) { "Phase 11.63 HTTP response headers exceeded bound" }
        val headerText = String(bytes.copyOfRange(0, headerEnd), StandardCharsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        require(lines.isNotEmpty())
        val statusParts = lines.first().split(' ', limit = 3)
        require(statusParts.size >= 2 && statusParts[0].startsWith("HTTP/")) { "Phase 11.63 malformed HTTP status line" }
        val status = statusParts[1].toIntOrNull() ?: throw IllegalArgumentException("Phase 11.63 malformed HTTP status code")
        require(status == 200) { "Phase 11.63 expected HTTP 200 but received $status" }

        val headers = lines.drop(1).mapNotNull { line ->
            val split = line.indexOf(':')
            if (split <= 0) null else line.substring(0, split).trim().lowercase() to line.substring(split + 1).trim()
        }
        require(headers.none { it.first == "transfer-encoding" }) { "Phase 11.63 chunked transfer is outside exact-body proof" }
        val encodings = headers.filter { it.first == "content-encoding" }.map { it.second.lowercase() }
        require(encodings.all { it == "identity" }) { "Phase 11.63 encoded body is outside exact-body proof" }
        val lengths = headers.filter { it.first == "content-length" }.map { it.second }
        require(lengths.size == 1) { "Phase 11.63 requires exactly one Content-Length" }
        val contentLength = lengths.single().toIntOrNull() ?: throw IllegalArgumentException("Phase 11.63 invalid Content-Length")
        require(contentLength == plan.expectedBodyBytes) { "Phase 11.63 Content-Length mismatch" }
        val bodyStart = headerEnd + delimiter.size
        require(bytes.size - bodyStart == contentLength) { "Phase 11.63 captured body length mismatch" }
        val body = bytes.copyOfRange(bodyStart, bytes.size)
        val bodySha = digestBytes(body)
        require(bodySha == plan.expectedBodySha256) { "Phase 11.63 served index SHA-256 mismatch" }
        return ParsedResponse(status, contentLength, bodySha)
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        for (start in 0..haystack.size - needle.size) {
            var matched = true
            for (i in needle.indices) {
                if (haystack[start + i] != needle[i]) { matched = false; break }
            }
            if (matched) return start
        }
        return -1
    }

    private fun proofSha256(proof: SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof): String = digest(buildString {
        append("phase=11.63\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("verificationPlan=").append(proof.verificationPlanSha256).append('\n')
        append("publicationPlan=").append(proof.publicationPlanSha256).append('\n')
        append("loopbackVerificationPlan=").append(proof.loopbackVerificationPlanSha256).append('\n')
        append("loopbackExecutionProof=").append(proof.loopbackExecutionProofSha256).append('\n')
        append("remoteHostIdentity=").append(proof.remoteHostIdentity).append('\n')
        append("targetIpv4Literal=").append(proof.targetIpv4Literal).append('\n')
        append("port=").append(proof.port).append('\n')
        append("domain=").append(proof.domain).append('\n')
        append("requestPath=").append(proof.requestPath).append('\n')
        append("executionAttemptId=").append(proof.executionAttemptId).append('\n')
        append("externalTcpConnectPerformed=").append(proof.externalTcpConnectPerformed).append('\n')
        append("externalHttpGetPerformed=").append(proof.externalHttpGetPerformed).append('\n')
        append("httpStatusCode=").append(proof.httpStatusCode).append('\n')
        append("contentLength=").append(proof.contentLength).append('\n')
        append("expectedBodyBytes=").append(proof.expectedBodyBytes).append('\n')
        append("expectedBodySha256=").append(proof.expectedBodySha256).append('\n')
        append("observedBodySha256=").append(proof.observedBodySha256).append('\n')
        append("exactBodySha256Verified=").append(proof.exactBodySha256Verified).append('\n')
        append("externalNetworkPathReachabilityProved=").append(proof.externalNetworkPathReachabilityProved).append('\n')
        append("dnsResolutionPerformed=").append(proof.dnsResolutionPerformed).append('\n')
        append("dnsResolutionClaimed=").append(proof.dnsResolutionClaimed).append('\n')
        append("dnsMutationPerformed=").append(proof.dnsMutationPerformed).append('\n')
        append("firewallMutationPerformed=").append(proof.firewallMutationPerformed).append('\n')
        append("httpsUsed=").append(proof.httpsUsed).append('\n')
        append("httpsClaimed=").append(proof.httpsClaimed).append('\n')
        append("configMutationPerformed=").append(proof.configMutationPerformed).append('\n')
        append("packageInstallPerformed=").append(proof.packageInstallPerformed).append('\n')
        append("automaticRetryPerformed=").append(proof.automaticRetryPerformed).append('\n')
        append("coordinatorInvoked=").append(proof.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
        append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
    })

    private fun digest(value: String): String = digestBytes(value.encodeToByteArray())

    private fun digestBytes(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
