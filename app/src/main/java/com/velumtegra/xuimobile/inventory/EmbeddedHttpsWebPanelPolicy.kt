package com.velumtegra.xuimobile.inventory

import java.net.URI

/** A WebView may navigate only within the exact explicitly authorized HTTPS origin.
 * Subresources remain subject to WebView's TLS and mixed-content checks. No implicit
 * cross-origin browser handoff, HTTP downgrade, host aliasing or redirect trust.
 */
internal fun isSameAuthorizedHttpsPanelOrigin(initialUrl: String, candidateUrl: String): Boolean {
    if (exactHttpsPanelUrl(initialUrl) == null) return false
    val initial = parseHttpsOrigin(initialUrl) ?: return false
    val next = parseHttpsOrigin(candidateUrl) ?: return false
    return initial == next
}

private data class HttpsOrigin(val host: String, val port: Int)

private fun parseHttpsOrigin(url: String): HttpsOrigin? {
    if (url.isBlank() || url != url.trim() || url.any { it.isWhitespace() || Character.isISOControl(it) || it == '\\' }) {
        return null
    }
    val uri = try { URI(url) } catch (_: Exception) { return null }
    if (!uri.isAbsolute || !uri.scheme.equals("https", ignoreCase = true) ||
        uri.rawUserInfo != null || uri.rawAuthority?.contains('@') == true ||
        uri.host.isNullOrBlank() || uri.port > 65535 || uri.port == 0 || uri.port < -1
    ) return null
    return HttpsOrigin(requireNotNull(uri.host).lowercase(java.util.Locale.ROOT), if (uri.port == -1) 443 else uri.port)
}
