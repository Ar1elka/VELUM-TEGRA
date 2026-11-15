package com.velumtegra.xuimobile.inventory

import android.content.Context
import android.net.http.SslCertificate
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Scoped to an SSH profile + exact server target, not to the ephemeral phone port. The panel sign-in id is
 * kept as a readable prefix (`<accessId>#<sha>`) so a pin can be dropped together with its profile.
 */
internal fun panelCertificateTrustScope(
    accessId: String, sshAccessId: String, host: String, port: Int,
    webBasePath: String, protocol: String,
): String = accessId + PIN_OWNER_SEPARATOR + sha256Upper(("VELUM_PRIVATE_PANEL_PIN_V1\u0000$accessId\u0000$sshAccessId\u0000" +
    "$host\u0000$port\u0000$webBasePath\u0000$protocol").toByteArray(StandardCharsets.UTF_8))

internal const val PIN_OWNER_SEPARATOR = '#'

internal fun sha256Upper(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes).joinToString("") { "%02X".format(it) }

internal enum class CertificatePinDecision { FIRST_USE, MATCH, CHANGED, INVALID }

internal fun certificatePinDecision(known: String?, presented: String?): CertificatePinDecision = when {
    presented == null || !Regex("[0-9A-F]{64}").matches(presented) -> CertificatePinDecision.INVALID
    known == null -> CertificatePinDecision.FIRST_USE
    !Regex("[0-9A-F]{64}").matches(known) -> CertificatePinDecision.INVALID
    known == presented -> CertificatePinDecision.MATCH
    else -> CertificatePinDecision.CHANGED
}

internal data class ObservedPanelCertificate(
    val fingerprint: String,
    val subject: String,
    val notAfter: String,
)

/** Read DER from WebView's reported leaf; reject unparseable and time-invalid certificates. */
internal fun observedPanelCertificate(cert: SslCertificate?): ObservedPanelCertificate? {
    if (cert == null) return null
    return try {
    val der = SslCertificate.saveState(cert).getByteArray("x509-certificate") ?: return null
    val parsed = CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    parsed.checkValidity()
    val fingerprint = sha256Upper(parsed.encoded)
    ObservedPanelCertificate(
        fingerprint = fingerprint,
        subject = parsed.subjectX500Principal.name.take(180),
        notAfter = java.text.DateFormat.getDateInstance().format(parsed.notAfter),
    )
} catch (_: Exception) { null }
}

/** Certificate fingerprints are public identifiers, not login secrets. Store no credentials. */
internal class PrivatePanelCertificatePins(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(
        "velum_private_panel_cert_pins_v1", Context.MODE_PRIVATE)
    /** Pins saved before the owner prefix existed are still honoured under their bare hash key. */
    fun read(scope: String): String? = prefs.getString(scope, null)
        ?: prefs.getString(scope.substringAfter(PIN_OWNER_SEPARATOR), null)
    fun save(scope: String, fingerprint: String): Boolean {
        if (scope.isBlank() || certificatePinDecision(null, fingerprint) == CertificatePinDecision.INVALID) return false
        return prefs.edit().putString(scope, fingerprint).remove(scope.substringAfter(PIN_OWNER_SEPARATOR)).commit()
    }

    /** Drops pins whose panel sign-in no longer exists. Legacy bare-hash pins have no owner and are kept. */
    fun retainOnly(existingPanelAccessIds: Set<String>): Int {
        val stale = prefs.all.keys.filter { key ->
            PIN_OWNER_SEPARATOR in key && key.substringBefore(PIN_OWNER_SEPARATOR) !in existingPanelAccessIds
        }
        if (stale.isNotEmpty()) prefs.edit().apply { stale.forEach(::remove) }.commit()
        return stale.size
    }
}
