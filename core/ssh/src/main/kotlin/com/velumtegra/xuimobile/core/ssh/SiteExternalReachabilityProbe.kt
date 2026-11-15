package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.cert.CertificateException
import javax.net.ssl.SSLException

/** DNS lookup seam (the device resolver in production, a fixed table in tests). */
fun interface SiteHostResolver {
    fun resolve(host: String): List<InetAddress>
}

data class SiteDnsCheck(
    val domainAddresses: List<String>,
    val serverAddresses: List<String>,
    val pointsToServer: Boolean,
    val failureMessage: String?,
)

data class SiteExternalFetchResult(
    val reachable: Boolean,
    val httpStatus: Int?,
    val bodySha256: String?,
    val failureCategory: SiteServingFailureCategory?,
    val failureMessage: String?,
)

/**
 * Read-only checks performed from the operator's device, i.e. from outside the VPS: does the
 * domain resolve to the selected server, and does the public URL return exactly the published
 * index.html (with normal certificate validation for HTTPS). Nothing is ever changed.
 */
class SiteExternalReachabilityProbe(
    private val resolver: SiteHostResolver = SiteHostResolver { InetAddress.getAllByName(it).toList() },
    private val connectTimeoutMillis: Int = 8_000,
    private val readTimeoutMillis: Int = 10_000,
    /**
     * Second opinion used only when the device resolver returns VPN "fake-ip" answers
     * (198.18.0.0/15). Production asks public DNS-over-HTTPS; it goes through the same VPN tunnel and
     * therefore sees the real public A records. Returns null when that lookup is unavailable.
     */
    private val publicResolver: (String) -> List<String>? = { DnsOverHttpsResolver.resolveA(it) },
) {
    fun checkDns(domain: String, serverHost: String): SiteDnsCheck {
        var fakeIpSeen = false
        fun resolveReal(host: String): List<String> {
            val local = resolver.resolve(host).map { it.hostAddress }.distinct()
            if (local.isEmpty() || local.none(::isVpnFakeIp)) return local
            fakeIpSeen = true
            val public = try { publicResolver(host) } catch (_: Throwable) { null }
            return public?.takeIf { it.isNotEmpty() } ?: local
        }
        val serverAddresses = try {
            resolveReal(serverHost)
        } catch (_: UnknownHostException) {
            return SiteDnsCheck(emptyList(), emptyList(), false, "Не удалось определить IP-адрес сервера $serverHost")
        }
        val domainAddresses = try {
            resolveReal(domain)
        } catch (_: UnknownHostException) {
            return SiteDnsCheck(
                emptyList(),
                serverAddresses,
                false,
                "Домен $domain не найден в DNS. Добавьте A-запись на ${serverAddresses.firstOrNull() ?: serverHost}",
            )
        }
        val matches = domainAddresses.any { it in serverAddresses }
        return SiteDnsCheck(
            domainAddresses = domainAddresses,
            serverAddresses = serverAddresses,
            pointsToServer = matches,
            failureMessage = when {
                matches -> null
                domainAddresses.any(::isVpnFakeIp) || serverAddresses.any(::isVpnFakeIp) ->
                    "VPN на телефоне подменяет ответы DNS (адрес ${domainAddresses.joinToString()}), " +
                        "поэтому настоящий адрес домена $domain узнать не удалось. Выключите VPN и повторите проверку"
                else -> "Домен $domain указывает на ${domainAddresses.joinToString()}, а сервер — " +
                    "${serverAddresses.joinToString()}. Исправьте A-запись" +
                    if (fakeIpSeen) " (адреса проверены через публичный DNS, потому что VPN подменяет ответы)" else ""
            },
        )
    }

    internal companion object {
        /** RFC 2544 benchmarking range, used by Clash/sing-box/v2rayNG "fake-ip" DNS. Never a real public host. */
        fun isVpnFakeIp(address: String): Boolean {
            val parts = address.split('.')
            if (parts.size != 4) return false
            val a = parts[0].toIntOrNull() ?: return false
            val b = parts[1].toIntOrNull() ?: return false
            return a == 198 && (b == 18 || b == 19)
        }
    }

    fun fetch(url: String, expectedSha256: String, maxBytes: Int = 4 * 1024 * 1024): SiteExternalFetchResult {
        if (url.startsWith("http://")) return fetchPlainHttp(url, expectedSha256, maxBytes)
        val connection = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (error: IOException) {
            return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Некорректный адрес $url: ${error.message}")
        }
        return try {
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Cache-Control", "no-cache")
            val status = connection.responseCode
            if (status != 200) {
                return SiteExternalFetchResult(
                    false,
                    status,
                    null,
                    SiteServingFailureCategory.SERVING_VERIFICATION,
                    "Адрес $url ответил кодом $status вместо страницы сайта",
                )
            }
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0
            connection.inputStream.use { input ->
                val buffer = ByteArray(16 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > maxBytes) {
                        return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Ответ $url слишком большой")
                    }
                    digest.update(buffer, 0, read)
                }
            }
            val sha = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
            if (sha == expectedSha256) {
                SiteExternalFetchResult(true, status, sha, null, null)
            } else {
                SiteExternalFetchResult(
                    false,
                    status,
                    sha,
                    SiteServingFailureCategory.SERVING_VERIFICATION,
                    "По адресу $url открывается другая страница, а не опубликованный сайт",
                )
            }
        } catch (error: UnknownHostException) {
            failure(SiteServingFailureCategory.DNS, "Домен не найден в DNS: ${error.message}")
        } catch (error: SSLException) {
            failure(SiteServingFailureCategory.CERTIFICATE, "Ошибка HTTPS-сертификата: ${error.message}")
        } catch (error: CertificateException) {
            failure(SiteServingFailureCategory.CERTIFICATE, "Ошибка HTTPS-сертификата: ${error.message}")
        } catch (error: SocketTimeoutException) {
            failure(
                SiteServingFailureCategory.EXTERNAL_UNREACHABLE,
                "Сервер не ответил снаружи — порт, вероятно, закрыт файрволом сервера или хостинга",
            )
        } catch (error: ConnectException) {
            failure(
                SiteServingFailureCategory.EXTERNAL_UNREACHABLE,
                "Соединение отклонено — порт закрыт файрволом или на нём ничего не слушает",
            )
        } catch (error: NoRouteToHostException) {
            failure(SiteServingFailureCategory.EXTERNAL_UNREACHABLE, "Нет маршрута до сервера: ${error.message}")
        } catch (error: IOException) {
            val cause = error.cause
            if (cause is CertificateException || cause is SSLException) {
                failure(SiteServingFailureCategory.CERTIFICATE, "Ошибка HTTPS-сертификата: ${cause.message}")
            } else {
                failure(SiteServingFailureCategory.EXTERNAL_UNREACHABLE, "Сайт недоступен снаружи: ${error.message}")
            }
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Plain-HTTP verification GET over a raw socket. The app's network security config forbids
     * cleartext for its own HTTP stack (that protects panel credentials); this request carries no
     * credentials or cookies and only reads the public page that was just published.
     */
    private fun fetchPlainHttp(url: String, expectedSha256: String, maxBytes: Int): SiteExternalFetchResult {
        val parsed = try {
            URL(url)
        } catch (error: IOException) {
            return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Некорректный адрес $url")
        }
        val host = parsed.host
        val port = if (parsed.port == -1) 80 else parsed.port
        val path = parsed.file.ifEmpty { "/" }
        require(host.none { it == '\r' || it == '\n' } && path.none { it == '\r' || it == '\n' })
        return try {
            val address = resolver.resolve(host).firstOrNull() ?: throw UnknownHostException(host)
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(address, port), connectTimeoutMillis)
                socket.soTimeout = readTimeoutMillis
                val hostHeader = if (port == 80) host else "$host:$port"
                socket.getOutputStream().apply {
                    write("GET $path HTTP/1.1\r\nHost: $hostHeader\r\nUser-Agent: VELUM-TEGRA-site-check\r\nAccept: */*\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    flush()
                }
                val raw = socket.getInputStream().readNBytesBounded(maxBytes + 64 * 1024)
                    ?: return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Ответ $url слишком большой")
                parsePlainHttpResponse(raw, url, expectedSha256)
            }
        } catch (error: UnknownHostException) {
            failure(SiteServingFailureCategory.DNS, "Домен не найден в DNS: ${error.message}")
        } catch (error: SocketTimeoutException) {
            failure(
                SiteServingFailureCategory.EXTERNAL_UNREACHABLE,
                "Сервер не ответил снаружи — порт, вероятно, закрыт файрволом сервера или хостинга",
            )
        } catch (error: ConnectException) {
            failure(
                SiteServingFailureCategory.EXTERNAL_UNREACHABLE,
                "Соединение отклонено — порт закрыт файрволом или на нём ничего не слушает",
            )
        } catch (error: IOException) {
            failure(SiteServingFailureCategory.EXTERNAL_UNREACHABLE, "Сайт недоступен снаружи: ${error.message}")
        }
    }

    internal fun parsePlainHttpResponse(raw: ByteArray, url: String, expectedSha256: String): SiteExternalFetchResult {
        val headerEnd = indexOf(raw, "\r\n\r\n".toByteArray(Charsets.US_ASCII))
        if (headerEnd < 0) return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Некорректный HTTP-ответ от $url")
        val head = String(raw, 0, headerEnd, Charsets.ISO_8859_1).split("\r\n")
        val status = head.first().split(' ').getOrNull(1)?.toIntOrNull()
        if (status != 200) {
            return SiteExternalFetchResult(
                false,
                status,
                null,
                SiteServingFailureCategory.SERVING_VERIFICATION,
                "Адрес $url ответил кодом ${status ?: "?"} вместо страницы сайта",
            )
        }
        val headers = head.drop(1).associate { it.substringBefore(':').trim().lowercase() to it.substringAfter(':', "").trim() }
        var body = raw.copyOfRange(headerEnd + 4, raw.size)
        if (headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true) {
            body = dechunk(body) ?: return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Некорректный HTTP-ответ от $url")
        } else {
            headers["content-length"]?.toIntOrNull()?.let { length ->
                if (length > body.size) {
                    return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Ответ $url оборвался")
                }
                body = body.copyOfRange(0, length)
            }
        }
        if (headers["content-encoding"]?.isNotBlank() == true && headers["content-encoding"] != "identity") {
            return failure(SiteServingFailureCategory.SERVING_VERIFICATION, "Сервер вернул сжатый ответ, который нельзя сверить")
        }
        val sha = MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return if (sha == expectedSha256) {
            SiteExternalFetchResult(true, status, sha, null, null)
        } else {
            SiteExternalFetchResult(
                false,
                status,
                sha,
                SiteServingFailureCategory.SERVING_VERIFICATION,
                "По адресу $url открывается другая страница, а не опубликованный сайт",
            )
        }
    }

    private fun java.io.InputStream.readNBytesBounded(limit: Int): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(16 * 1024)
        while (true) {
            val read = read(buffer)
            if (read < 0) return out.toByteArray()
            out.write(buffer, 0, read)
            if (out.size() > limit) return null
        }
    }

    private fun dechunk(data: ByteArray): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (true) {
            val lineEnd = indexOf(data, "\r\n".toByteArray(Charsets.US_ASCII), i)
            if (lineEnd < 0) return null
            val size = String(data, i, lineEnd - i, Charsets.US_ASCII).substringBefore(';').trim().toIntOrNull(16) ?: return null
            i = lineEnd + 2
            if (size == 0) return out.toByteArray()
            if (i + size > data.size) return null
            out.write(data, i, size)
            i += size + 2
        }
    }

    private fun indexOf(data: ByteArray, pattern: ByteArray, from: Int = 0): Int {
        outer@ for (i in from..data.size - pattern.size) {
            for (j in pattern.indices) if (data[i + j] != pattern[j]) continue@outer
            return i
        }
        return -1
    }

    private fun failure(category: SiteServingFailureCategory, message: String) =
        SiteExternalFetchResult(false, null, null, category, message)
}
