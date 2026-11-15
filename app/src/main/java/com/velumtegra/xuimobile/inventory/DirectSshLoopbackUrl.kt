package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import java.net.URI

/** App-local OS-assigned SSH-forward endpoint. Never build a public VPS URL. */
internal fun directSshLoopbackUrl(scheme: WebPanelScheme, localPort: Int, privateBasePath: String): String? {
    if (localPort !in 1..65535 || !privateBasePath.startsWith('/')) return null
    val protocol = if (scheme == WebPanelScheme.HTTPS) "https" else "http"
    val url = "$protocol://127.0.0.1:$localPort$privateBasePath"
    return url.takeIf { isExactDirectSshLoopbackUrl(it) }
}

/** Strict direct-route URL: numeric loopback, explicit nondefault port, no credentials or query secrets. */
internal fun isExactDirectSshLoopbackUrl(url: String): Boolean {
    val uri = runCatching { URI(url) }.getOrNull() ?: return false
    if (uri.host != "127.0.0.1" || uri.port !in 1..65535 ||
        uri.scheme?.lowercase(java.util.Locale.ROOT) !in setOf("http", "https")) return false
    return exactPrivateSshPanelUrl(url, uri.scheme.equals("http", true)) != null
}

/** Allows relative 3x-ui navigation/resources only on the same loopback port and scheme. */
internal fun isSameDirectSshLoopbackOrigin(initialUrl: String, candidateUrl: String): Boolean {
    if (!isExactDirectSshLoopbackUrl(initialUrl)) return false
    val start = runCatching { URI(initialUrl) }.getOrNull() ?: return false
    val next = runCatching { URI(candidateUrl) }.getOrNull() ?: return false
    return next.host == "127.0.0.1" && next.port == start.port &&
        next.scheme.equals(start.scheme, true) && next.rawUserInfo == null &&
        next.rawAuthority?.contains('@') != true &&
        candidateUrl == candidateUrl.trim() &&
        candidateUrl.none { Character.isISOControl(it) || it == '\\' || it.isWhitespace() }
}
