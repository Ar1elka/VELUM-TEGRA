package com.velumtegra.xuimobile.core.webpanel

import com.velumtegra.xuimobile.core.domain.*
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient

/** Explicit previously accepted leaf identity, scoped to one exact resolved SSH target/revision.
 * No first-use learning, system trust bypass for other routes, wildcard, or global TLS changes.
 */
data class PinnedSshPanelCertificate(val target: ResolvedWebPanelTarget, val sha256: String) {
    init { require(Regex("[0-9A-F]{64}").matches(sha256)) }
    fun permits(request: WebPanelAuthenticationRequest): Boolean {
        val route = request.target.routeTarget as? ResolvedWebPanelRouteTarget.SshTunnel ?: return false
        val transport = request.transport as? WebPanelAuthenticationTransport.SshTunnel ?: return false
        return request.target == target && route.scheme == WebPanelScheme.HTTPS &&
            transport.authorityHost.value == "127.0.0.1" && transport.pinnedCertificate == this
    }
    override fun toString() = "PinnedSshPanelCertificate([scoped public fingerprint])"
}

internal class PinnedPanelTrustManager(private val pin: String) : X509TrustManager {
    init { require(Regex("[0-9A-F]{64}").matches(pin)) }
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
        throw CertificateException("Client certificates are unsupported")
    }
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        val certificates = chain ?: throw CertificateException("Missing chain")
        val leaf = certificates.firstOrNull() ?: throw CertificateException("Missing leaf")
        if (authType.isNullOrBlank() || certificates.size > 8) throw CertificateException("Invalid chain")
        leaf.checkValidity()
        if (leaf.basicConstraints >= 0) throw CertificateException("Expected leaf certificate")
        val usage = leaf.extendedKeyUsage
        if (usage != null && "1.3.6.1.5.5.7.3.1" !in usage && "2.5.29.37.0" !in usage)
            throw CertificateException("Wrong certificate purpose")
        val actual = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
            .joinToString("") { "%02X".format(it) }
        if (!MessageDigest.isEqual(pin.toByteArray(Charsets.US_ASCII), actual.toByteArray(Charsets.US_ASCII)))
            throw CertificateException("Saved leaf identity changed")
    }
}

internal fun OkHttpClient.Builder.scopedPanelPin(pin: PinnedSshPanelCertificate?): OkHttpClient.Builder {
    if (pin == null) return this
    val trust = PinnedPanelTrustManager(pin.sha256)
    val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
    return sslSocketFactory(tls.socketFactory, trust).hostnameVerifier { host, session ->
        // The remote identity is the saved leaf plus the exact app-owned SSH target, not a DNS fallback.
        host == "127.0.0.1" && runCatching {
            trust.checkServerTrusted(arrayOf(session.peerCertificates.first() as X509Certificate), "TLS")
            true
        }.getOrDefault(false)
    }
}
