package com.velumtegra.xuimobile.core.ssh

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Minimal public DNS-over-HTTPS A-record lookup (Cloudflare JSON API). Used only as a second
 * opinion when the device resolver is known to lie (VPN fake-ip). Sends nothing but the host name.
 */
object DnsOverHttpsResolver {
    /** RFC 2544 range used by Clash/sing-box/v2rayNG "fake-ip" DNS (198.18.0.0/15); never a real public host. */
    fun isVpnFakeIp(address: String): Boolean = SiteExternalReachabilityProbe.isVpnFakeIp(address)

    private const val ENDPOINT = "https://cloudflare-dns.com/dns-query"
    private val hostName = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+") // braces are quantifiers here, ICU-safe
    private val ipv4 = Regex("(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}")
    private val answerA = Regex("\\{[^{}]*\"type\"\\s*:\\s*1\\b[^{}]*\"data\"\\s*:\\s*\"([^\"]+)\"[^{}]*\\}") // ICU (Android) requires the escaped '}'

    fun resolveA(host: String): List<String>? {
        if (ipv4.matches(host)) return listOf(host)
        if (host.length > 253 || !hostName.matches(host)) return null
        val connection = try {
            URL("$ENDPOINT?name=${URLEncoder.encode(host, "UTF-8")}&type=A").openConnection() as HttpURLConnection
        } catch (_: IOException) {
            return null
        }
        return try {
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/dns-json")
            if (connection.responseCode != 200) return null
            val body = connection.inputStream.use { input ->
                val bytes = input.readBytes()
                if (bytes.size > 64 * 1024) return null
                bytes.decodeToString()
            }
            parse(body)
        } catch (_: Exception) {
            null
        } finally {
            connection.disconnect()
        }
    }

    internal fun parse(json: String): List<String>? {
        if (!Regex("\"Status\"\\s*:\\s*0\\b").containsMatchIn(json)) return null
        return answerA.findAll(json).map { it.groupValues[1] }.filter(ipv4::matches).distinct().toList()
    }
}
