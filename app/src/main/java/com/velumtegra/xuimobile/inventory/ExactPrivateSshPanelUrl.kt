package com.velumtegra.xuimobile.inventory

import java.net.URI

/** HTTP is never accepted by direct WebView opening; it is restricted to a verified private tunnel. */
internal fun exactPrivateSshPanelUrl(url: String, allowHttp: Boolean): String? {
    if (exactHttpsPanelUrl(url) != null) return url
    if (!allowHttp || url.isBlank() || url != url.trim() ||
        url.any { it.isWhitespace() || Character.isISOControl(it) || it == '\\' }) return null
    val uri = runCatching { URI(url) }.getOrNull() ?: return null
    if (!uri.scheme.equals("http", true) || uri.host !in setOf("127.0.0.1", "localhost") ||
        uri.port !in 1..65535 || uri.rawUserInfo != null || uri.rawQuery != null ||
        uri.rawFragment != null || uri.rawPath.orEmpty().split('/').any { it == "." || it == ".." } ||
        uri.rawPath.orEmpty().contains("%2f", true) || uri.rawPath.orEmpty().contains("%5c", true)) return null
    return url
}

internal fun isSamePrivateSshOrigin(initial: String, current: String, allowHttp: Boolean): Boolean {
    if (exactPrivateSshPanelUrl(initial, allowHttp) == null) return false
    val start = runCatching { URI(initial) }.getOrNull() ?: return false
    val next = runCatching { URI(current) }.getOrNull() ?: return false
    return start.scheme.equals(next.scheme, true) && start.host.equals(next.host, true) &&
        start.port == next.port && next.rawUserInfo == null &&
        next.scheme in setOf("http", "https")
}
