package com.velumtegra.xuimobile.core.scanner.android

import android.os.Build
import com.velumtegra.xuimobile.core.scanner.NearbyIpInfiniteTargetProducer
import com.velumtegra.xuimobile.core.scanner.RealityScanProgress
import com.velumtegra.xuimobile.core.scanner.RealityScanResult
import com.velumtegra.xuimobile.core.scanner.RealityScanTarget
import com.velumtegra.xuimobile.core.scanner.RealityScannerTlsPolicy
import com.velumtegra.xuimobile.core.scanner.RealitySniCandidatePolicy
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Smallest executable migration of the approved Reality Scanner engine.
 *
 * Single-IP infinite target production is deliberately delegated to
 * [NearbyIpInfiniteTargetProducer]. This file contains no alternate nearby-IP stepping algorithm.
 * Service/UI ownership is migrated in later slices.
 */
class RealityScannerEngine {
    private val trustManager =
        object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        }

    private val sslFactory: SSLSocketFactory by lazy {
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustManager), null)
        }.socketFactory
    }

    suspend fun scan(
        input: String,
        port: Int,
        timeoutSeconds: Int,
        threadCount: Int,
        enableIpv6: Boolean,
        enableTls12: Boolean = false,
        geoDatabase: File? = null,
        onProgress: (RealityScanProgress) -> Unit,
        awaitIfPaused: suspend () -> Unit = {},
        awaitNetworkOnline: suspend () -> Unit = {},
        /** Returns false when the result was already known, so it is not counted twice. */
        onResult: (RealityScanResult) -> Boolean = { true },
        /** True while the device is offline: a probe that failed then is repeated, not lost. */
        isOffline: () -> Boolean = { false },
        /** Targets already checked by an interrupted run of the same plan; they are skipped. */
        resumeCompleted: Int = 0,
        resumeFeasible: Int = 0,
    ): List<RealityScanResult> {
        require(port in 1..65535) { "Порт должен быть от 1 до 65535." }
        require(timeoutSeconds in 1..120) { "Timeout должен быть от 1 до 120 секунд." }
        require(threadCount in 1..32) { "Количество потоков должно быть от 1 до 32." }

        val plan = planTargets(input, enableIpv6)
        val skip = resumeCompleted.coerceAtLeast(0)
        val handshakeTimeoutMillis = timeoutSeconds * 1000
        // A node whose TCP handshake needs more than a few seconds is useless as a Reality target, while
        // most neighbour IPs are simply silent: waiting the full TLS timeout on each one made the scan crawl.
        val connectTimeoutMillis = minOf(handshakeTimeoutMillis, MAX_CONNECT_TIMEOUT_MILLIS)
        val scannedResults = java.util.Collections.synchronizedList(mutableListOf<RealityScanResult>())
        val completed = AtomicInteger(skip)
        val feasible = AtomicInteger(resumeFeasible.coerceAtLeast(0))

        val geoResolver =
            geoDatabase
                ?.takeIf { it.exists() && it.length() > 0 }
                ?.let { runCatching { GeoIpResolver(it) }.getOrNull() }

        try {
            coroutineScope {
                val channel = Channel<RealityScanTarget>(capacity = threadCount * 2)
                val producer =
                    async(Dispatchers.Default) {
                        try {
                            for (target in plan.targets.drop(skip)) {
                                if (!isActive) return@async
                                channel.send(target)
                            }
                        } finally {
                            channel.close()
                        }
                    }

                val workers =
                    List(threadCount) {
                        async(Dispatchers.IO) {
                            for (target in channel) {
                                suspend fun attempt(): RealityScanResult {
                                    awaitIfPaused()
                                    awaitNetworkOnline()
                                    return scanTarget(
                                        target = target,
                                        port = port,
                                        connectTimeoutMillis = connectTimeoutMillis,
                                        handshakeTimeoutMillis = handshakeTimeoutMillis,
                                        enableTls12 = enableTls12,
                                        geoResolver = geoResolver,
                                    )
                                }
                                var result = attempt()
                                var retries = 0
                                // The network dropped under this probe: it says nothing about the target.
                                while (result.error != null && retries++ < MAX_OFFLINE_RETRIES && isOffline()) {
                                    result = attempt()
                                }

                                // An endless neighbour scan must not keep every dead IP in memory.
                                if (!plan.infinite || result.feasible) scannedResults.add(result)
                                if (result.feasible && onResult(result)) feasible.incrementAndGet()

                                onProgress(
                                    RealityScanProgress(
                                        total = plan.total,
                                        completed = completed.incrementAndGet(),
                                        feasible = feasible.get(),
                                    ),
                                )
                            }
                        }
                    }

                workers.awaitAll()
                producer.await()
            }
        } finally {
            geoResolver?.close()
        }

        return scannedResults
    }

    /** Human-readable reason why [input] cannot be scanned, or null when at least one target is usable. */
    fun inputProblem(input: String, enableIpv6: Boolean): String? {
        if (input.isBlank()) return "Укажи IP, домен или CIDR."
        if (parseInput(input, enableIpv6).isNotEmpty()) return null
        val tokens = tokens(input)
        return when {
            !enableIpv6 && tokens.any { it.substringBefore('/').count { c -> c == ':' } >= 2 } ->
                "Это IPv6-адрес. Включи переключатель IPv6 или укажи IPv4."
            tokens.any { it.contains('/') } ->
                "Диапазон не распознан. Поддерживается IPv4 CIDR от /12 до /32, например 203.0.113.0/24."
            else -> "Не найдено ни одной корректной цели. Укажи IP, домен или CIDR."
        }
    }

    /** What a scan of [input] would cover, without any network access; null when nothing is usable. */
    fun summarizeInput(input: String, enableIpv6: Boolean): RealityScanInputSummary? =
        runCatching {
            planTargets(input, enableIpv6).let { RealityScanInputSummary(infinite = it.infinite, total = it.total) }
        }.getOrNull()

    internal fun planTargets(input: String, enableIpv6: Boolean): RealityTargetPlan {
        val parsed = parseInput(input, enableIpv6)
        require(parsed.isNotEmpty()) { "Не найдено ни одной корректной цели." }

        val infiniteMode =
            parsed.size == 1 &&
                parsed[0].isIpTarget &&
                !parsed[0].isCidr &&
                !parsed[0].target.isDomain

        if (infiniteMode) {
            val seed = InetAddress.getByName(parsed[0].target.host)
            return RealityTargetPlan(
                infinite = true,
                total = 0,
                targets = NearbyIpInfiniteTargetProducer.sequence(seed, enableIpv6),
            )
        }

        return RealityTargetPlan(
            infinite = false,
            total = parsed.sumOf { it.count.toLong() }.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            targets = parsed.asSequence().flatMap { it.targets },
        )
    }

    private class ParsedInput(
        val target: RealityScanTarget,
        val isIpTarget: Boolean,
        val isCidr: Boolean,
        val count: Int,
        /** Lazy: a /12 range is a million targets and must not be materialized as a list. */
        val targets: Sequence<RealityScanTarget>,
    )

    /** Splits pasted text into targets and strips what people usually paste around a host. */
    private fun tokens(input: String): List<String> =
        input.split('\n', '\r', ',', ';', ' ', '\t')
            .map { normalizeToken(it) }
            .filter { it.isNotEmpty() }

    private fun normalizeToken(raw: String): String {
        var value = raw.trim()
        if (value.contains("://")) value = value.substringAfter("://")
        value = value.substringBefore('?').substringBefore('#')
        if (!CIDR_SHAPE.matches(value)) value = value.substringBefore('/')
        if (value.startsWith("[")) {
            value = value.substringAfter('[').substringBefore(']') // [2001:db8::1]:443
        } else if (value.count { it == ':' } == 1) {
            value = value.substringBefore(':') // host:443
        }
        value = value.trimEnd('.')
        return if (value.contains(':')) value else value.lowercase()
    }

    private fun parseInput(input: String, enableIpv6: Boolean): List<ParsedInput> {
        val result = mutableListOf<ParsedInput>()

        tokens(input)
            .forEach { line ->
                when {
                    isValidIp(line) -> {
                        val ipv6 = line.contains(":")
                        if (ipv6 && !enableIpv6) return@forEach

                        val target = RealityScanTarget(origin = line, host = line, isDomain = false)
                        result +=
                            ParsedInput(
                                target = target,
                                isIpTarget = true,
                                isCidr = false,
                                count = 1,
                                targets = sequenceOf(target),
                            )
                    }

                    line.contains("/") -> expandCidr(line)?.let { result += it }

                    isValidDomain(line) -> {
                        val target = RealityScanTarget(origin = line, host = line, isDomain = true)
                        result +=
                            ParsedInput(
                                target = target,
                                isIpTarget = false,
                                isCidr = false,
                                count = 1,
                                targets = sequenceOf(target),
                            )
                    }
                }
            }

        return result.distinctBy { "${it.target.origin}|${it.target.host}|${it.isCidr}" }
    }

    /** IPv4 only, as in the approved v1 behavior: exact IPv6 targets are supported, IPv6 CIDR is not. */
    private fun expandCidr(cidr: String): ParsedInput? {
        val parts = cidr.split("/")
        if (parts.size != 2 || !isValidIp(parts[0]) || parts[0].contains(':')) return null

        val address = runCatching { InetAddress.getByName(parts[0]) }.getOrNull() as? Inet4Address ?: return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val hostBits = 32 - prefix
        if (hostBits > MAX_CIDR_HOST_BITS) return null

        var base = 0L
        for (byte in address.address) {
            base = (base shl 8) or (byte.toInt() and 0xff).toLong()
        }
        val mask = if (prefix == 0) 0L else (0xffffffffL shl hostBits) and 0xffffffffL
        val network = base and mask
        val count = 1 shl hostBits

        fun target(offset: Int): RealityScanTarget {
            val value = network + offset
            val ip = "${(value shr 24) and 0xff}.${(value shr 16) and 0xff}.${(value shr 8) and 0xff}.${value and 0xff}"
            return RealityScanTarget(origin = cidr, host = ip, isDomain = false)
        }
        return ParsedInput(
            target = target(0),
            isIpTarget = false,
            isCidr = true,
            count = count,
            targets = (0 until count).asSequence().map(::target),
        )
    }

    /**
     * Blocking socket calls ignore coroutine cancellation, so STOP used to leave every worker hanging until
     * its timeout and then publishing into the next session. The socket is closed as soon as the scan is
     * cancelled; leaving the scope then rethrows the cancellation, so nothing is reported afterwards.
     */
    private suspend fun scanTarget(
        target: RealityScanTarget,
        port: Int,
        connectTimeoutMillis: Int,
        handshakeTimeoutMillis: Int,
        enableTls12: Boolean,
        geoResolver: GeoIpResolver?,
    ): RealityScanResult =
        coroutineScope {
            val socket = Socket()
            val closer =
                launch(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        awaitCancellation()
                    } finally {
                        runCatching { socket.close() }
                    }
                }
            try {
                probe(socket, target, port, connectTimeoutMillis, handshakeTimeoutMillis, enableTls12, geoResolver)
            } finally {
                closer.cancel()
            }
        }

    private fun probe(
        socket: Socket,
        target: RealityScanTarget,
        port: Int,
        connectTimeoutMillis: Int,
        handshakeTimeoutMillis: Int,
        enableTls12: Boolean,
        geoResolver: GeoIpResolver?,
    ): RealityScanResult {
        var address = target.host

        return try {
            if (target.isDomain) {
                val all = InetAddress.getAllByName(target.host)
                val resolved = all.firstOrNull { it is Inet4Address } ?: all.firstOrNull()
                if (resolved == null) return failure(target, port, "DNS: IP не найден")
                address = resolved.hostAddress ?: target.host
            }

            socket.soTimeout = handshakeTimeoutMillis
            val connectStartedNs = System.nanoTime()
            socket.connect(InetSocketAddress(address, port), connectTimeoutMillis)
            val latencyMs: Long? =
                ((System.nanoTime() - connectStartedNs) / 1_000_000L).coerceAtLeast(0L)

            run {
                val sslSocket = sslFactory.createSocket(socket, target.host, port, true) as SSLSocket
                sslSocket.use { tlsSocket ->
                    configureTls(tlsSocket, target, enableTls12)
                    tlsSocket.soTimeout = handshakeTimeoutMillis
                    tlsSocket.startHandshake()

                    val session = tlsSocket.session
                    val certificates = session.peerCertificates.filterIsInstance<X509Certificate>()
                    if (certificates.isEmpty()) {
                        return failure(target, port, "Сертификат сервера не получен")
                    }

                    val serverCertificate = certificates.first()
                    val detailCertificate =
                        certificates.firstOrNull { !it.subjectAlternativeNames.isNullOrEmpty() }
                            ?: serverCertificate
                    val cn = extractCommonName(serverCertificate.subjectX500Principal.name)
                    val dnsSubjectAltNames = extractDnsSubjectAltNames(detailCertificate)
                    val sniCandidates =
                        RealitySniCandidatePolicy.selectableCandidates(
                            commonName = cn,
                            dnsSubjectAltNames = dnsSubjectAltNames,
                        )
                    val selectedSni =
                        RealitySniCandidatePolicy.defaultSelection(
                            requestedDomain = target.origin.takeIf { target.isDomain },
                            candidates = sniCandidates,
                        )
                    val issuerOrganization =
                        extractIssuerOrganization(serverCertificate.issuerX500Principal.name)
                    val alpn = readNegotiatedProtocol(tlsSocket)
                    val tls = session.protocol
                    val geo = geoResolver?.lookup(address) ?: "N/A"
                    val feasible =
                        RealityScannerTlsPolicy.isAcceptedProtocol(tls, enableTls12) &&
                            alpn == "h2" &&
                            cn.isNotBlank() &&
                            issuerOrganization.isNotBlank()

                    RealityScanResult(
                        origin = target.origin,
                        ip = address,
                        port = port,
                        feasible = feasible,
                        tls = tls,
                        alpn = alpn,
                        certificateDomain = cn,
                        certificateIssuer = issuerOrganization,
                        certificateSignature = detailCertificate.sigAlgName,
                        certificatePublicKey = detailCertificate.publicKey.algorithm,
                        certificateLength = certificates.sumOf { it.encoded.size },
                        certificateCount = certificates.size,
                        cipherSuite = session.cipherSuite,
                        curve = null,
                        geo = geo,
                        latencyMs = latencyMs,
                        sniCandidates = sniCandidates,
                        selectedSni = selectedSni,
                    )
                }
            }
        } catch (error: Exception) {
            failure(target, port, error.message?.take(180) ?: error.javaClass.simpleName)
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun configureTls(
        socket: SSLSocket,
        target: RealityScanTarget,
        enableTls12: Boolean,
    ) {
        val enabledProtocols =
            RealityScannerTlsPolicy.enabledProtocols(
                supportedProtocols = socket.supportedProtocols.asList(),
                enableTls12 = enableTls12,
            )
        if (enabledProtocols.isNotEmpty()) {
            socket.enabledProtocols = enabledProtocols.toTypedArray()
        }

        if (target.isDomain && Build.VERSION.SDK_INT >= 24) {
            runCatching {
                val parameters = socket.sslParameters
                val setServerNames = parameters.javaClass.getMethod("setServerNames", List::class.java)
                val serverNameClass = Class.forName("javax.net.ssl.SNIHostName")
                val sni = serverNameClass.getConstructor(String::class.java).newInstance(target.origin)
                setServerNames.invoke(parameters, listOf(sni))
                socket.sslParameters = parameters
            }
        }

        if (Build.VERSION.SDK_INT >= 29) {
            runCatching {
                val parameters = socket.sslParameters
                val method =
                    parameters.javaClass.getMethod("setApplicationProtocols", Array<String>::class.java)
                method.invoke(parameters, arrayOf("h2", "http/1.1"))
                socket.sslParameters = parameters
            }
        }
    }

    private fun readNegotiatedProtocol(socket: SSLSocket): String {
        if (Build.VERSION.SDK_INT < 29) return ""
        return runCatching {
            val method = socket.javaClass.getMethod("getApplicationProtocol")
            method.invoke(socket) as? String ?: ""
        }.getOrDefault("")
    }

    private fun extractCommonName(distinguishedName: String): String =
        runCatching {
            distinguishedName
                .split(',')
                .map { it.trim() }
                .firstOrNull { it.startsWith("CN=") }
                ?.substringAfter("CN=")
                ?.trim()
                ?: ""
        }.getOrDefault("")

    private fun extractDnsSubjectAltNames(certificate: X509Certificate): List<String> =
        runCatching {
            certificate.subjectAlternativeNames
                ?.mapNotNull { entry ->
                    val type = entry.getOrNull(0) as? Int
                    val value = entry.getOrNull(1) as? String
                    value?.takeIf { type == 2 }
                }
                .orEmpty()
        }.getOrDefault(emptyList())

    private fun extractIssuerOrganization(distinguishedName: String): String =
        runCatching {
            distinguishedName
                .split(',')
                .map { it.trim() }
                .filter { it.startsWith("O=") }
                .map { it.substringAfter("O=").trim() }
                .filter { it.isNotBlank() }
                .joinToString(" | ")
        }.getOrDefault("")

    private fun failure(target: RealityScanTarget, port: Int, error: String): RealityScanResult =
        RealityScanResult(
            origin = target.origin,
            ip = target.host,
            port = port,
            feasible = false,
            tls = "",
            alpn = "",
            certificateDomain = "",
            certificateIssuer = "",
            certificateSignature = "",
            certificatePublicKey = "",
            certificateLength = 0,
            certificateCount = 0,
            cipherSuite = "",
            curve = null,
            geo = "N/A",
            error = error,
        )

    private fun isValidIp(value: String): Boolean {
        val ipv4 = Regex("""^(?:\d{1,3}\.){3}\d{1,3}$""")
        if (ipv4.matches(value)) {
            return value.split(".").all { it.toIntOrNull() in 0..255 }
        }
        if (!value.contains(":")) return false
        if (!Regex("^[0-9A-Fa-f:.]+$").matches(value)) return false // never reach a DNS lookup
        return runCatching {
            InetAddress.getByName(value)
            true
        }.getOrDefault(false)
    }

    private fun isValidDomain(value: String): Boolean {
        if (value.length > 253) return false
        if (!Regex("^[A-Za-z0-9.-]+$").matches(value)) return false
        if (Regex("""^[\d.]+$""").matches(value)) return false // a mistyped IPv4, not a host name
        return value.split('.').all { it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-') }
    }

    private companion object {
        const val MAX_CONNECT_TIMEOUT_MILLIS = 4_000
        const val MAX_OFFLINE_RETRIES = 3
        const val MAX_CIDR_HOST_BITS = 20
        val CIDR_SHAPE = Regex("""^[0-9A-Fa-f:.]+/\d{1,3}$""")
    }
}

/** [infinite]: a single IP is scanned outwards through its neighbours until stopped; [total] is then 0. */
data class RealityScanInputSummary(
    val infinite: Boolean,
    val total: Int,
)

internal data class RealityTargetPlan(
    val infinite: Boolean,
    val total: Int,
    val targets: Sequence<RealityScanTarget>,
)
