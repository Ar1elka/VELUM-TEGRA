package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration

/** Phase 11.62 read-only SSH adapter. Callers cannot supply shell text or request paths. */
class SiteWebServingLiveHttpVerificationSshAdapter {
    suspend fun verifyOnce(
        verificationPlan: SiteWebServingLiveHttpVerificationPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): SiteWebServingLiveHttpVerificationObservation {
        validateInputs(verificationPlan, publicationPlan, access, session)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.62 SSH session does not expose verified host-key evidence")
        val result = session.execute(
            RemoteCommand.create(guardedLoopbackHttpCommand(verificationPlan), "site-web-live-http-verify-once"),
            SshTransportConfig(
                channelOpenTimeout = Duration.ofSeconds(5),
                commandExecutionTimeout = Duration.ofSeconds(12),
                stdoutCaptureLimitBytes = verificationPlan.expectedBodyBytes + verificationPlan.maxHeaderBytes + 4096,
                stderrCaptureLimitBytes = 32 * 1024,
            ),
        )
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Phase 11.62 command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Phase 11.62 HTTP response exceeded bounded capture" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Phase 11.62 live HTTP verification command failed" }
        val response = result.stdout.copyBytes()
        val parsed = parseExactResponse(response, verificationPlan)
        return SiteWebServingLiveHttpVerificationObservation(
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            exactConfigSha256Verified = true,
            nginxMasterRunning = true,
            expectedListenerLive = true,
            loopbackHttpGetPerformed = true,
            httpStatusCode = parsed.statusCode,
            contentLength = parsed.contentLength,
            observedBodySha256 = parsed.bodySha256,
            exactBodySha256Verified = true,
            remoteCommandCount = 1,
            arbitraryCommandAccepted = false,
            configMutationPerformed = false,
            dnsMutationPerformed = false,
            firewallMutationPerformed = false,
            packageInstallPerformed = false,
            automaticRetryPerformed = false,
        )
    }

    private fun validateInputs(
        verificationPlan: SiteWebServingLiveHttpVerificationPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ) {
        SiteWebServingLiveHttpVerificationBoundary.validate(verificationPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(verificationPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(verificationPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(verificationPlan.configPath == publicationPlan.configPath)
        require(verificationPlan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(verificationPlan.domain == publicationPlan.domain)
        require(verificationPlan.port == publicationPlan.port)
        require(access.endpoint.host == verificationPlan.remoteHostIdentity)
        require(session.binding.serverAccessId == access.id)
        require(session.binding.owner is SessionOwner.Operation)
        require(session.isOpen)
    }

    private fun guardedLoopbackHttpCommand(plan: SiteWebServingLiveHttpVerificationPlan): String {
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        val filter = quote("sport = :${plan.port}")
        val script = buildString {
            append("exec 3<>/dev/tcp/127.0.0.1/").append(plan.port).append(" || exit 31; ")
            append("printf \"GET ").append(plan.requestPath)
                .append(" HTTP/1.1\\r\\nHost: ").append(plan.domain)
                .append("\\r\\nAccept-Encoding: identity\\r\\nConnection: close\\r\\n\\r\\n\" >&3; ")
            append("cat <&3")
        }
        val qScript = quote(script)
        return "test -f $config; test ! -L $config; " +
            "test \"\$(sha256sum -- $config | cut -d' ' -f1)\" = $desiredSha; " +
            "test -s /run/nginx.pid; kill -0 \"\$(cat /run/nginx.pid)\" 2>/dev/null; " +
            "out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; test \$code -eq 0; test -n \"\$out\"; " +
            "command -v bash >/dev/null 2>&1; bash -c $qScript"
    }

    private data class ParsedResponse(val statusCode: Int, val contentLength: Int, val bodySha256: String)

    private fun parseExactResponse(bytes: ByteArray, plan: SiteWebServingLiveHttpVerificationPlan): ParsedResponse {
        val delimiter = byteArrayOf(13, 10, 13, 10)
        val headerEnd = indexOf(bytes, delimiter)
        require(headerEnd >= 0) { "Phase 11.62 HTTP response headers are incomplete" }
        require(headerEnd + delimiter.size <= plan.maxHeaderBytes) { "Phase 11.62 HTTP response headers exceeded bound" }
        val headerBytes = bytes.copyOfRange(0, headerEnd)
        val headerText = String(headerBytes, StandardCharsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        require(lines.isNotEmpty())
        val statusParts = lines.first().split(' ', limit = 3)
        require(statusParts.size >= 2 && statusParts[0].startsWith("HTTP/")) { "Phase 11.62 malformed HTTP status line" }
        val status = statusParts[1].toIntOrNull() ?: throw IllegalArgumentException("Phase 11.62 malformed HTTP status code")
        require(status == 200) { "Phase 11.62 expected HTTP 200 but received $status" }

        val headers = lines.drop(1).mapNotNull { line ->
            val split = line.indexOf(':')
            if (split <= 0) null else line.substring(0, split).trim().lowercase() to line.substring(split + 1).trim()
        }
        require(headers.none { it.first == "transfer-encoding" }) { "Phase 11.62 chunked/transfer encoding is outside exact-body proof" }
        val contentEncodings = headers.filter { it.first == "content-encoding" }.map { it.second.lowercase() }
        require(contentEncodings.all { it == "identity" }) { "Phase 11.62 encoded HTTP body is outside exact-body proof" }
        val lengths = headers.filter { it.first == "content-length" }.map { it.second }
        require(lengths.size == 1) { "Phase 11.62 requires exactly one Content-Length" }
        val contentLength = lengths.single().toIntOrNull()
            ?: throw IllegalArgumentException("Phase 11.62 invalid Content-Length")
        require(contentLength == plan.expectedBodyBytes) { "Phase 11.62 Content-Length mismatch" }

        val bodyStart = headerEnd + delimiter.size
        require(bytes.size - bodyStart == contentLength) { "Phase 11.62 captured body length mismatch" }
        val body = bytes.copyOfRange(bodyStart, bytes.size)
        val bodySha = MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        require(bodySha == plan.expectedBodySha256) { "Phase 11.62 served index SHA-256 mismatch" }
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

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }
}
