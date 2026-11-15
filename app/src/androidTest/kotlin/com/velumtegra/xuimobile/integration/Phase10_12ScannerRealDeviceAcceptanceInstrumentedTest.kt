package com.velumtegra.xuimobile.integration

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.scanner.NearbyIpInfiniteTargetProducer
import com.velumtegra.xuimobile.core.scanner.RealityScanResult
import com.velumtegra.xuimobile.core.scanner.RealityScanResultGrouping
import com.velumtegra.xuimobile.core.scanner.RealityScannerTlsPolicy
import com.velumtegra.xuimobile.core.scanner.RealitySniAnalysis
import com.velumtegra.xuimobile.core.scanner.RealitySniRatingProjection
import com.velumtegra.xuimobile.core.scanner.RealitySniVerdict
import com.velumtegra.xuimobile.core.scanner.android.CheburcheckSniAnalyzer
import com.velumtegra.xuimobile.core.scanner.android.RealityScanSession
import com.velumtegra.xuimobile.core.scanner.android.RealityScanSessionStore
import com.velumtegra.xuimobile.core.scanner.android.RealityScannerEngine
import com.velumtegra.xuimobile.core.scanner.android.RealityScannerForegroundService
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.Principal
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ServerSocketFactory
import javax.security.auth.x500.X500Principal
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Final Phase 10 Scanner acceptance on one real Android device.
 *
 * All network evidence is device-local. TLS and CheburCheck-compatible witnesses listen only on
 * 127.0.0.1; no external target, credential or mutation is used. The acceptance deliberately does
 * not toggle Wi-Fi/mobile data. Network-loss state-machine semantics stay frozen by the JVM strict
 * gate while this test proves the real FGS/session/UI-facing persistence boundaries.
 */
@RunWith(AndroidJUnit4::class)
class Phase10_12ScannerRealDeviceAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Test
    fun finalScannerAcceptance(): Unit = runBlocking {
        require(Build.VERSION.SDK_INT >= 29) {
            "Phase 10.12 requires API 29+ so the device-local TLS witness can negotiate ALPN h2."
        }

        cleanupScannerState()
        assertServiceManifestContract()
        assertCanonicalNearbyIpOrderOnDevice()

        val tls13Result = proveTls13DefaultAndProductionEngine()
        val tls12Result = proveTls12IsOptIn()
        proveSplitTlsProjection(tls13Result, tls12Result)
        proveForegroundOwnershipPauseResumeTaskRemovalAndRestore()
        proveAnalyzerPersistenceExportsAndTwoColumnRating(tls13Result)

        cleanupScannerState()
    }

    private suspend fun proveTls13DefaultAndProductionEngine(): RealityScanResult {
        LocalTlsFixture(RealityScannerTlsPolicy.TLS_13).use { fixture ->
            val results =
                RealityScannerEngine().scan(
                    input = "localhost",
                    port = fixture.port,
                    timeoutSeconds = 4,
                    threadCount = 1,
                    enableIpv6 = false,
                    enableTls12 = false,
                    onProgress = {},
                )
            val result = results.single()
            assertTrue(
                "TLS 1.3 fixture must be feasible; error=${result.error}; tls=${result.tls}; alpn=${result.alpn}; issuer=${result.certificateIssuer}; fixtureFailure=${fixture.failureSummary()}",
                result.feasible,
            )
            assertEquals(RealityScannerTlsPolicy.TLS_13, result.tls)
            assertEquals("h2", result.alpn)
            assertTrue((result.latencyMs ?: -1L) >= 0L)
            assertTrue("clean.scanner.test" in result.sniCandidates)
            assertEquals("clean.scanner.test", result.selectedSni)
            return result
        }
    }

    private suspend fun proveTls12IsOptIn(): RealityScanResult {
        LocalTlsFixture(RealityScannerTlsPolicy.TLS_12).use { fixture ->
            val defaultResults =
                RealityScannerEngine().scan(
                    input = "localhost",
                    port = fixture.port,
                    timeoutSeconds = 4,
                    threadCount = 1,
                    enableIpv6 = false,
                    enableTls12 = false,
                    onProgress = {},
                )
            assertFalse("TLS 1.2-only endpoint must not be feasible by default", defaultResults.single().feasible)

            val optInResults =
                RealityScannerEngine().scan(
                    input = "localhost",
                    port = fixture.port,
                    timeoutSeconds = 4,
                    threadCount = 1,
                    enableIpv6 = false,
                    enableTls12 = true,
                    onProgress = {},
                )
            val result = optInResults.single()
            assertTrue("TLS 1.2-only endpoint must become feasible after explicit opt-in", result.feasible)
            assertEquals(RealityScannerTlsPolicy.TLS_12, result.tls)
            assertEquals("h2", result.alpn)
            return result
        }
    }

    private fun proveSplitTlsProjection(tls13Result: RealityScanResult, tls12Result: RealityScanResult) {
        val groups = RealityScanResultGrouping.split(listOf(tls12Result, tls13Result))
        assertEquals(listOf(RealityScannerTlsPolicy.TLS_13), groups.tls13.map { it.tls })
        assertEquals(listOf(RealityScannerTlsPolicy.TLS_12), groups.tls12.map { it.tls })
        assertTrue(groups.other.isEmpty())
        assertEquals(2, groups.total)
    }

    private fun proveForegroundOwnershipPauseResumeTaskRemovalAndRestore() {
        LocalTlsFixture(RealityScannerTlsPolicy.TLS_13).use { fixture ->
            val activity = launchMainActivity()
            try {
                RealityScannerForegroundService.start(
                    context = context,
                    input = "127.0.0.1",
                    port = fixture.port,
                    threadCount = 1,
                    enableIpv6 = false,
                    enableTls12 = false,
                )

                val started = awaitServiceState(8_000) { it.running && it.completed >= 1 }
                assertFalse("Acceptance device must have an internet-capable active network", started.networkLost)
                assertEquals("127.0.0.1", started.input)
                assertEquals(fixture.port, started.port)
                assertEquals(1, started.threads)
                assertFalse(started.tls12)
                awaitCondition(8_000) { RealityScanSessionStore.loadCurrent(context).isNotEmpty() }

                RealityScannerForegroundService.pause(context)
                val paused = awaitServiceState(4_000) { it.running && it.paused && !it.networkLost }
                val completedAtPause = paused.completed
                Thread.sleep(700)
                val afterPause = RealityScannerForegroundService.state(context)
                assertTrue(
                    "At most one already-in-flight target may finish after user pause",
                    afterPause.completed <= completedAtPause + 1,
                )

                RealityScannerForegroundService.resume(context)
                val resumed = awaitServiceState(4_000) { it.running && !it.paused && !it.networkLost }
                assertTrue(resumed.running)
                // Production Scanner uses a 10 s per-target socket timeout. After resume, the next
                // nearby-IP witness may legitimately consume that full timeout before progress advances.
                awaitServiceState(15_000) { it.completed > completedAtPause + 1 }

                instrumentation.runOnMainSync { activity.finishAndRemoveTask() }
                Thread.sleep(900)
                val afterTaskRemoval = RealityScannerForegroundService.state(context)
                assertTrue("Scanner FGS must survive removal of the app task", afterTaskRemoval.running)
                assertEquals("127.0.0.1", afterTaskRemoval.input)
                assertEquals(fixture.port, afterTaskRemoval.port)

                val restoredActivity = launchMainActivity()
                try {
                    RealityScannerForegroundService.ensureRunning(context)
                    val restored = awaitServiceState(4_000) { it.running }
                    assertEquals("127.0.0.1", restored.input)
                    assertEquals(1, restored.threads)
                    assertTrue(RealityScanSessionStore.loadCurrent(context).isNotEmpty())
                } finally {
                    instrumentation.runOnMainSync { restoredActivity.finish() }
                }
            } finally {
                RealityScannerForegroundService.stop(context)
                awaitServiceState(5_000) { !it.running }
                if (!activity.isFinishing) {
                    instrumentation.runOnMainSync { activity.finish() }
                }
            }
        }
    }

    private suspend fun proveAnalyzerPersistenceExportsAndTwoColumnRating(seed: RealityScanResult) {
        context.getSharedPreferences("velum_reality_sni_analyzer", Context.MODE_PRIVATE).edit().clear().commit()
        LocalCheburcheckFixture().use { fixture ->
            val analyzer = CheburcheckSniAnalyzer(context, fixture.baseUrl)
            val clean = analyzer.analyze("clean.scanner.test")
            val whitelist = analyzer.analyze("whitelist.scanner.test")
            val candidate = analyzer.analyze("child.parent.scanner.test")
            val blocked = analyzer.analyze("blocked.scanner.test")

            assertEquals(RealitySniVerdict.CLEAN, clean.verdict)
            assertEquals(RealitySniVerdict.WHITELIST_CONFIRMED, whitelist.verdict)
            assertEquals(RealitySniVerdict.WHITELIST_CANDIDATE, candidate.verdict)
            assertEquals(RealitySniVerdict.BLOCKED, blocked.verdict)
            assertTrue(clean.source.contains("check"))
            assertTrue(whitelist.source.contains("whitelist"))

            val stored =
                seed.copy(
                    id = "phase10-12-${UUID.randomUUID()}",
                    selectedSni = "clean.scanner.test",
                    sniAnalysis = clean,
                )
            RealityScanSessionStore.saveCurrent(context, listOf(stored))
            RealityScanSessionStore.saveFavorites(context, listOf(stored))
            RealityScanSessionStore.saveHistory(
                context,
                listOf(RealityScanSession(createdAt = System.currentTimeMillis(), results = listOf(stored))),
            )

            val selectedChanged = stored.copy(selectedSni = "whitelist.scanner.test", sniAnalysis = null)
            RealityScanSessionStore.updateResultEverywhere(context, selectedChanged)
            assertNull(RealityScanSessionStore.loadCurrent(context).single().sniAnalysis)
            assertNull(RealityScanSessionStore.loadFavorites(context).single().sniAnalysis)
            assertNull(RealityScanSessionStore.loadHistory(context).single().results.single().sniAnalysis)

            val analyzed = selectedChanged.copy(sniAnalysis = whitelist)
            RealityScanSessionStore.updateResultEverywhere(context, analyzed)
            assertPersistedEverywhere(analyzed)
            assertProductionExportsContainSniEvidence(analyzed)

            val cleanSlow = ratingResult(analyzed, "clean-slow", 44, "clean.scanner.test", clean)
            val cleanFast = ratingResult(analyzed, "clean-fast", 8, "clean.scanner.test", clean)
            val whiteSlow = ratingResult(analyzed, "white-slow", 31, "whitelist.scanner.test", whitelist)
            val whiteFast = ratingResult(analyzed, "white-fast", 6, "whitelist.scanner.test", whitelist)
            val candidateRow = ratingResult(analyzed, "candidate", 1, "child.parent.scanner.test", candidate)
            val blockedRow = ratingResult(analyzed, "blocked", 2, "blocked.scanner.test", blocked)
            val unknownRow =
                ratingResult(
                    analyzed,
                    "unknown",
                    3,
                    "unknown.scanner.test",
                    RealitySniAnalysis(
                        sni = "unknown.scanner.test",
                        verdict = RealitySniVerdict.UNKNOWN,
                        source = "acceptance",
                        checkedAt = System.currentTimeMillis(),
                    ),
                )
            val unanalyzed = analyzed.copy(id = "unanalyzed", latencyMs = 0, selectedSni = "clean.scanner.test", sniAnalysis = null)

            val rating =
                RealitySniRatingProjection.project(
                    listOf(cleanSlow, whiteSlow, cleanFast, whiteFast, candidateRow, blockedRow, unknownRow, unanalyzed),
                )
            assertEquals(listOf("clean-fast", "clean-slow"), rating.clean.map { it.id })
            assertEquals(listOf("white-fast", "white-slow"), rating.whitelist.map { it.id })
            assertEquals(
                listOf("candidate", "blocked", "unknown", "unanalyzed"),
                rating.remainder.map { it.id },
            )
        }
    }

    private fun assertPersistedEverywhere(expected: RealityScanResult) {
        val current = RealityScanSessionStore.loadCurrent(context).single()
        val favorite = RealityScanSessionStore.loadFavorites(context).single()
        val historical = RealityScanSessionStore.loadHistory(context).single().results.single()
        for (actual in listOf(current, favorite, historical)) {
            assertEquals(expected.id, actual.id)
            assertEquals("whitelist.scanner.test", actual.selectedSni)
            assertEquals(RealitySniVerdict.WHITELIST_CONFIRMED, actual.sniAnalysis?.verdict)
            assertEquals("whitelist.scanner.test", actual.sniAnalysis?.sni)
            assertTrue(actual.sniAnalysis?.source?.contains("whitelist") == true)
        }
    }

    private fun assertProductionExportsContainSniEvidence(result: RealityScanResult) {
        val screenKt = Class.forName("com.velumtegra.xuimobile.scanner.RealityScannerScreenKt")

        val csvMethod = screenKt.getDeclaredMethod("buildCsv", List::class.java).apply { isAccessible = true }
        val csv = csvMethod.invoke(null, listOf(result)) as String
        assertTrue(csv.contains("SELECTED_SNI"))
        assertTrue(csv.contains("SNI_VERDICT"))
        assertTrue(csv.contains("whitelist.scanner.test"))
        assertTrue(csv.contains("WHITELIST_CONFIRMED"))

        val jsonMethod = screenKt.getDeclaredMethod("buildJson", List::class.java).apply { isAccessible = true }
        val json = JSONObject(jsonMethod.invoke(null, listOf(result)) as String)
        val row = json.getJSONArray("results").getJSONObject(0)
        assertEquals("whitelist.scanner.test", row.getString("selectedSni"))
        assertEquals("WHITELIST_CONFIRMED", row.getJSONObject("sniAnalysis").getString("verdict"))
        assertTrue(row.has("latencyMs"))

        val copyMethod = screenKt.getDeclaredMethod("asCopyText", RealityScanResult::class.java).apply { isAccessible = true }
        val copy = copyMethod.invoke(null, result) as String
        assertTrue(copy.contains("SNI: whitelist.scanner.test"))
        assertTrue(copy.contains("SNI-анализ: Белый список — подтверждено"))
    }

    private fun ratingResult(
        base: RealityScanResult,
        id: String,
        latencyMs: Long,
        selectedSni: String,
        analysis: RealitySniAnalysis,
    ): RealityScanResult =
        base.copy(
            id = id,
            latencyMs = latencyMs,
            selectedSni = selectedSni,
            sniAnalysis = analysis,
        )

    private fun assertCanonicalNearbyIpOrderOnDevice() {
        val seed = InetAddress.getByName("198.51.100.10")
        val first = NearbyIpInfiniteTargetProducer.sequence(seed, enableIpv6 = false).take(7).map { it.host }.toList()
        assertEquals(
            listOf(
                "198.51.100.10",
                "198.51.100.9",
                "198.51.100.11",
                "198.51.100.8",
                "198.51.100.12",
                "198.51.100.7",
                "198.51.100.13",
            ),
            first,
        )
    }

    @Suppress("DEPRECATION")
    private fun assertServiceManifestContract() {
        val info =
            context.packageManager.getServiceInfo(
                ComponentName(context, RealityScannerForegroundService::class.java),
                0,
            )
        assertEquals(0, info.flags and ServiceInfo.FLAG_STOP_WITH_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            assertTrue(
                "Reality Scanner must declare specialUse foreground ownership",
                info.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE != 0,
            )
        }
    }

    private fun launchMainActivity(): Activity {
        val intent =
            requireNotNull(context.packageManager.getLaunchIntentForPackage(context.packageName)) {
                "Debug launch intent is unavailable."
            }.apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
        return instrumentation.startActivitySync(intent)
    }

    private fun cleanupScannerState() {
        runCatching { RealityScannerForegroundService.stop(context) }
        runCatching { awaitServiceState(2_500) { !it.running } }
        RealityScanSessionStore.clearCurrent(context)
        RealityScanSessionStore.saveHistory(context, emptyList())
        RealityScanSessionStore.saveFavorites(context, emptyList())
    }

    private fun awaitServiceState(
        timeoutMs: Long,
        predicate: (com.velumtegra.xuimobile.core.scanner.android.ScannerServiceState) -> Boolean,
    ): com.velumtegra.xuimobile.core.scanner.android.ScannerServiceState {
        val deadline = System.currentTimeMillis() + timeoutMs
        var last = RealityScannerForegroundService.state(context)
        while (System.currentTimeMillis() < deadline) {
            last = RealityScannerForegroundService.state(context)
            if (predicate(last)) return last
            Thread.sleep(50)
        }
        throw AssertionError("Timed out waiting for Scanner service state. Last=$last")
    }

    private fun awaitCondition(timeoutMs: Long, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return
            Thread.sleep(50)
        }
        throw AssertionError("Timed out waiting for Scanner acceptance condition.")
    }

    @SuppressLint("NewApi")
    private class LocalTlsFixture(
        private val protocol: String,
    ) : AutoCloseable {
        private val running = AtomicBoolean(true)
        private val lastFailure = AtomicReference<String?>(null)
        private val server: SSLServerSocket
        private val thread: Thread
        val port: Int

        private val keyAlias = "phase10_12_scanner_ephemeral"

        init {
            val now = System.currentTimeMillis()
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val keyPair = generator.generateKeyPair()
            val privateKey = keyPair.private
            val certificateChain =
                arrayOf(
                    selfSignedEcCertificate(
                        publicKeyEncoded = keyPair.public.encoded,
                        privateKey = privateKey,
                        subject = X500Principal("CN=clean.scanner.test,O=VELUM Test"),
                        serial = BigInteger.valueOf(now.coerceAtLeast(1L)),
                        notBefore = Date(now - 60_000L),
                        notAfter = Date(now + 24L * 60L * 60L * 1000L),
                    ),
                )
            val keyManager =
                object : X509ExtendedKeyManager() {
                    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

                    override fun chooseClientAlias(
                        keyType: Array<out String>?,
                        issuers: Array<out Principal>?,
                        socket: Socket?,
                    ): String? = null

                    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
                        arrayOf(keyAlias).takeIf { isEcKeyType(keyType) }

                    override fun chooseServerAlias(
                        keyType: String?,
                        issuers: Array<out Principal>?,
                        socket: Socket?,
                    ): String? = keyAlias.takeIf { isEcKeyType(keyType) }

                    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
                        certificateChain.takeIf { alias == keyAlias }

                    override fun getPrivateKey(alias: String?): PrivateKey? =
                        privateKey.takeIf { alias == keyAlias }

                    override fun chooseEngineClientAlias(
                        keyType: Array<out String>?,
                        issuers: Array<out Principal>?,
                        engine: SSLEngine?,
                    ): String? = null

                    override fun chooseEngineServerAlias(
                        keyType: String?,
                        issuers: Array<out Principal>?,
                        engine: SSLEngine?,
                    ): String? = keyAlias.takeIf { isEcKeyType(keyType) }

                    private fun isEcKeyType(keyType: String?): Boolean =
                        keyType?.contains("EC", ignoreCase = true) == true
                }
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(arrayOf(keyManager), null, null)

            server =
                sslContext.serverSocketFactory.createServerSocket(
                    0,
                    16,
                    InetAddress.getByName("127.0.0.1"),
                ) as SSLServerSocket
            require(protocol in server.supportedProtocols) {
                "Acceptance device does not support required server protocol $protocol: ${server.supportedProtocols.joinToString()}"
            }
            server.enabledProtocols = arrayOf(protocol)
            server.needClientAuth = false
            val parameters = server.sslParameters
            parameters.applicationProtocols = arrayOf("h2")
            server.sslParameters = parameters
            port = server.localPort

            thread =
                Thread({ acceptLoop() }, "phase10-12-tls-$protocol-$port").apply {
                    isDaemon = true
                    start()
                }
        }

        private fun acceptLoop() {
            while (running.get()) {
                val socket =
                    try {
                        server.accept() as SSLSocket
                    } catch (_: Exception) {
                        if (!running.get()) return
                        continue
                    }
                try {
                    socket.soTimeout = 5_000
                    socket.useClientMode = false
                    socket.enabledProtocols = arrayOf(protocol)
                    val socketParameters = socket.sslParameters
                    socketParameters.applicationProtocols = arrayOf("h2")
                    socket.sslParameters = socketParameters
                    socket.use { it.startHandshake() }
                } catch (error: SSLException) {
                    lastFailure.compareAndSet(null, "${error.javaClass.simpleName}: ${error.message.orEmpty()}")
                    runCatching { socket.close() }
                } catch (error: Exception) {
                    lastFailure.compareAndSet(null, "${error.javaClass.simpleName}: ${error.message.orEmpty()}")
                    runCatching { socket.close() }
                }
            }
        }

        private fun selfSignedEcCertificate(
            publicKeyEncoded: ByteArray,
            privateKey: PrivateKey,
            subject: X500Principal,
            serial: BigInteger,
            notBefore: Date,
            notAfter: Date,
        ): X509Certificate {
            val signatureAlgorithm = derSequence(derOid("1.2.840.10045.4.3.2"))
            val validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter))
            val tbsCertificate =
                derSequence(
                    derExplicit(0, derInteger(BigInteger.valueOf(2L))),
                    derInteger(serial),
                    signatureAlgorithm,
                    subject.encoded,
                    validity,
                    subject.encoded,
                    publicKeyEncoded,
                )
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(tbsCertificate)
            val certificateBytes =
                derSequence(
                    tbsCertificate,
                    signatureAlgorithm,
                    derBitString(signer.sign()),
                )
            return CertificateFactory.getInstance("X.509")
                .generateCertificate(certificateBytes.inputStream()) as X509Certificate
        }

        private fun derSequence(vararg values: ByteArray): ByteArray =
            derTagged(0x30, values.fold(ByteArray(0)) { acc, value -> acc + value })

        private fun derExplicit(tagNumber: Int, value: ByteArray): ByteArray =
            derTagged(0xA0 + tagNumber, value)

        private fun derInteger(value: BigInteger): ByteArray = derTagged(0x02, value.toByteArray())

        private fun derBitString(value: ByteArray): ByteArray = derTagged(0x03, byteArrayOf(0) + value)

        private fun derUtcTime(value: Date): ByteArray {
            val formatter = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }
            return derTagged(0x17, formatter.format(value).toByteArray(StandardCharsets.US_ASCII))
        }

        private fun derOid(oid: String): ByteArray {
            val parts = oid.split('.').map { it.toLong() }
            require(parts.size >= 2)
            val body = ByteArrayOutputStream()
            body.write((parts[0] * 40L + parts[1]).toInt())
            for (part in parts.drop(2)) {
                var value = part
                val encoded = ArrayDeque<Int>()
                encoded.addFirst((value and 0x7f).toInt())
                value = value ushr 7
                while (value > 0) {
                    encoded.addFirst(((value and 0x7f).toInt()) or 0x80)
                    value = value ushr 7
                }
                encoded.forEach { body.write(it) }
            }
            return derTagged(0x06, body.toByteArray())
        }

        private fun derTagged(tag: Int, body: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(tag)
            if (body.size < 0x80) {
                out.write(body.size)
            } else {
                var size = body.size
                val lengthBytes = ArrayDeque<Int>()
                while (size > 0) {
                    lengthBytes.addFirst(size and 0xff)
                    size = size ushr 8
                }
                out.write(0x80 or lengthBytes.size)
                lengthBytes.forEach { out.write(it) }
            }
            out.write(body)
            return out.toByteArray()
        }

        fun failureSummary(): String = lastFailure.get().orEmpty()

        override fun close() {
            running.set(false)
            runCatching { server.close() }
            runCatching { thread.join(1_000) }
        }
    }

    private class LocalCheburcheckFixture : AutoCloseable {
        private val running = AtomicBoolean(true)
        private val server: ServerSocket =
            ServerSocketFactory.getDefault().createServerSocket(
                0,
                16,
                InetAddress.getByName("127.0.0.1"),
            )
        private val thread: Thread
        val baseUrl: String = "http://127.0.0.1:${server.localPort}"

        init {
            thread =
                Thread({ acceptLoop() }, "phase10-12-chebur-${server.localPort}").apply {
                    isDaemon = true
                    start()
                }
        }

        private fun acceptLoop() {
            while (running.get()) {
                val socket =
                    try {
                        server.accept()
                    } catch (_: Exception) {
                        if (!running.get()) return
                        continue
                    }
                runCatching { handle(socket) }
                runCatching { socket.close() }
            }
        }

        private fun handle(socket: Socket) {
            socket.soTimeout = 4_000
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))
            val requestLine = reader.readLine().orEmpty()
            while (true) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) break
            }
            val path = requestLine.split(' ').getOrNull(1).orEmpty()
            val body = responseBody(path)
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            val header =
                "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/plain; charset=utf-8\r\n" +
                    "Content-Length: ${bytes.size}\r\n" +
                    "Connection: close\r\n\r\n"
            socket.getOutputStream().use { output ->
                output.write(header.toByteArray(StandardCharsets.US_ASCII))
                output.write(bytes)
                output.flush()
            }
        }

        private fun responseBody(path: String): String {
            if (path.startsWith("/whitelist/domains.csv")) {
                return "domain\nwhitelist.scanner.test\nparent.scanner.test\n"
            }
            if (path.startsWith("/api/v1/check")) {
                val rawTarget = path.substringAfter("target=", "")
                val target = URLDecoder.decode(rawTarget.substringBefore('&'), StandardCharsets.UTF_8.name())
                return if (target == "blocked.scanner.test") {
                    "{\"status\":\"blocked\",\"reasons\":[\"acceptance-block\"]}"
                } else {
                    "{\"status\":\"clear\",\"reasons\":[]}"
                }
            }
            return "{}"
        }

        override fun close() {
            running.set(false)
            runCatching { server.close() }
            runCatching { thread.join(1_000) }
        }
    }
}
