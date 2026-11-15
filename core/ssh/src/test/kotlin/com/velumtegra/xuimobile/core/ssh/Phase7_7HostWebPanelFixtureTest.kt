package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyPairGenerator
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.forward.AcceptAllForwardingFilter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Host-only deterministic witness for Phase 7.7 integrated WebPanel acceptance.
 *
 * It exposes one exact synthetic SSH credential and one loopback-only 3X-UI-like HTTP target.
 * Apache MINA permits local forwarding, but no shell/exec command is installed. The HTTP target
 * accepts only the exact Phase 7.4 preflight/login sequence and one exact synthetic panel credential.
 * After successful login it deliberately closes the owning SSH server to force real transport loss.
 */
class Phase7_7HostWebPanelFixtureTest {
    @Test
    fun `host fixture witnesses one tunneled panel authentication then transport loss`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 7.7 host fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val panel = PanelHttpFixture(fixtureDir)
        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 7.7 fixture host fingerprint is not canonical SHA-256" }

        val exactAuthAttempts = AtomicInteger(0)
        val unexpectedAuthAttempts = AtomicInteger(0)
        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                if (username == SSH_USERNAME && password == SSH_PASSWORD) {
                    exactAuthAttempts.incrementAndGet()
                    true
                } else {
                    unexpectedAuthAttempts.incrementAndGet()
                    writeAtomic(fixtureDir.resolve(UNEXPECTED_AUTH_FILE), "unexpected-auth\n")
                    false
                }
            }
            forwardingFilter = AcceptAllForwardingFilter.INSTANCE
        }

        var sshStoppedForLoss = false
        try {
            panel.start()
            server.start()
            check(server.port in 1..65535) { "Phase 7.7 SSH fixture did not bind a TCP port" }
            check(panel.port in 1..65535) { "Phase 7.7 HTTP fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "sshPort=${server.port}\n" +
                    "fingerprint=$fingerprint\n" +
                    "panelPort=${panel.port}\n" +
                    "expectedAuth=1\n" +
                    "expectedHttp=3\n" +
                    "expectedLogin=1\n",
            )

            waitForMarker(fixtureDir.resolve(LOGIN_COMPLETED_FILE), LOGIN_TIMEOUT_MILLIS)
            // Let the successful login response fully reach the device before inducing loss.
            Thread.sleep(2_000)
            server.stop()
            sshStoppedForLoss = true
            writeAtomic(fixtureDir.resolve(TRANSPORT_CLOSED_FILE), "closed=true\n")

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals("Exactly one SSH authentication is allowed", 1, exactAuthAttempts.get())
            assertEquals("No fallback SSH credential may be attempted", 0, unexpectedAuthAttempts.get())
            assertEquals("Exactly three HTTP requests are allowed", 3, panel.requests.size)
            assertEquals("Exactly one /login submission is allowed", 1, panel.loginSubmissions.get())
            assertFalse("No unexpected HTTP request may reach the target", Files.exists(fixtureDir.resolve(UNEXPECTED_HTTP_FILE)))
            assertFalse("No unexpected SSH authentication may reach the target", Files.exists(fixtureDir.resolve(UNEXPECTED_AUTH_FILE)))
        } finally {
            if (!sshStoppedForLoss) runCatching { server.stop() }
            panel.close()
        }
    }

    private inner class PanelHttpFixture(
        private val fixtureDir: Path,
    ) : AutoCloseable {
        private val server = ServerSocket(0, 50, InetAddress.getByName(LOOPBACK_HOST))
        private val running = AtomicBoolean(false)
        private var worker: Thread? = null
        val requests = CopyOnWriteArrayList<RecordedRequest>()
        val loginSubmissions = AtomicInteger(0)
        val port: Int get() = server.localPort

        fun start() {
            check(running.compareAndSet(false, true))
            worker = thread(name = "phase7-7-panel-fixture", isDaemon = true) {
                while (running.get()) {
                    val socket = try {
                        server.accept()
                    } catch (_: Exception) {
                        break
                    }
                    socket.use { client ->
                        runCatching { serve(client) }
                            .onFailure {
                                writeAtomic(fixtureDir.resolve(UNEXPECTED_HTTP_FILE), "fixture-http-failure\n")
                            }
                    }
                }
            }
        }

        private fun serve(socket: Socket) {
            val request = readRequest(socket)
            requests += request
            val index = requests.size
            when (index) {
                1 -> {
                    require(request.requestLine == "GET /base/csrf-token HTTP/1.1")
                    writeResponse(
                        socket,
                        body = "{\"success\":true,\"obj\":\"$CSRF_TOKEN\"}",
                        headers = mapOf("Set-Cookie" to "$AUTH_COOKIE=phase77-preflight; Path=/base/; HttpOnly; SameSite=Lax"),
                    )
                }
                2 -> {
                    require(request.requestLine == "POST /base/getTwoFactorEnable HTTP/1.1")
                    require(request.headers["x-csrf-token"] == CSRF_TOKEN)
                    require(request.headers["cookie"].orEmpty().contains("$AUTH_COOKIE=phase77-preflight"))
                    writeResponse(socket, body = "{\"success\":true,\"obj\":false}")
                }
                3 -> {
                    require(request.requestLine == "POST /base/login HTTP/1.1")
                    require(request.headers["x-csrf-token"] == CSRF_TOKEN)
                    require(request.headers["cookie"].orEmpty().contains("$AUTH_COOKIE=phase77-preflight"))
                    require(request.headers["host"] == "$LOOPBACK_HOST:$port")
                    require(
                        String(request.body, StandardCharsets.UTF_8) ==
                            "username=$PANEL_USERNAME&password=$PANEL_PASSWORD",
                    )
                    loginSubmissions.incrementAndGet()
                    writeResponse(
                        socket,
                        body = "{\"success\":true,\"obj\":null}",
                        headers = mapOf("Set-Cookie" to "$AUTH_COOKIE=phase77-session; Path=/base/; HttpOnly; SameSite=Lax"),
                    )
                    writeAtomic(fixtureDir.resolve(LOGIN_COMPLETED_FILE), "requests=3\nlogin=1\n")
                }
                else -> {
                    writeAtomic(fixtureDir.resolve(UNEXPECTED_HTTP_FILE), "over-dispatch\n")
                    writeResponse(socket, status = 409, body = "{\"success\":false}")
                }
            }
        }

        override fun close() {
            running.set(false)
            runCatching { server.close() }
            worker?.join(1_000)
        }

        private fun readRequest(socket: Socket): RecordedRequest {
            socket.soTimeout = 5_000
            val input = BufferedInputStream(socket.getInputStream())
            val requestLine = readAsciiLine(input)
            val headers = linkedMapOf<String, String>()
            while (true) {
                val line = readAsciiLine(input)
                if (line.isEmpty()) break
                val split = line.indexOf(':')
                require(split > 0)
                headers[line.substring(0, split).trim().lowercase()] = line.substring(split + 1).trim()
            }
            val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
            require(contentLength in 0..8192)
            val body = ByteArray(contentLength)
            var offset = 0
            while (offset < body.size) {
                val read = input.read(body, offset, body.size - offset)
                require(read > 0)
                offset += read
            }
            return RecordedRequest(requestLine, headers, body)
        }

        private fun writeResponse(
            socket: Socket,
            status: Int = 200,
            body: String,
            headers: Map<String, String> = emptyMap(),
        ) {
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            val output = BufferedOutputStream(socket.getOutputStream())
            output.write("HTTP/1.1 $status ${if (status in 200..299) "OK" else "FAIL"}\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.write("Content-Type: application/json; charset=utf-8\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.write("Content-Length: ${bytes.size}\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.write("Connection: close\r\n".toByteArray(StandardCharsets.US_ASCII))
            headers.forEach { (name, value) ->
                output.write("$name: $value\r\n".toByteArray(StandardCharsets.US_ASCII))
            }
            output.write("\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.write(bytes)
            output.flush()
        }

        private fun readAsciiLine(input: BufferedInputStream): String {
            val bytes = ArrayList<Byte>()
            while (true) {
                val value = input.read()
                require(value >= 0) { "Unexpected EOF" }
                if (value == '\n'.code) break
                if (value != '\r'.code) bytes += value.toByte()
                require(bytes.size <= 8192)
            }
            return ByteArray(bytes.size) { bytes[it] }.toString(StandardCharsets.US_ASCII)
        }
    }

    private data class RecordedRequest(
        val requestLine: String,
        val headers: Map<String, String>,
        val body: ByteArray,
    )

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(
            READY_FILE,
            LOGIN_COMPLETED_FILE,
            TRANSPORT_CLOSED_FILE,
            UNEXPECTED_AUTH_FILE,
            UNEXPECTED_HTTP_FILE,
            RELEASE_FILE,
        ).forEach { Files.deleteIfExists(fixtureDir.resolve(it)) }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(50)
        }
        error("Timed out waiting for fixture marker: ${path.fileName}")
    }

    private fun writeAtomic(path: Path, text: String) {
        Files.createDirectories(path.parent)
        val temp = path.resolveSibling("${path.fileName}.tmp-${System.nanoTime()}")
        Files.writeString(temp, text, StandardCharsets.UTF_8)
        try {
            Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: Exception) {
            Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE77_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val SSH_USERNAME = "phase77ssh"
        const val SSH_PASSWORD = "P77SshPasswordOnly"
        const val PANEL_USERNAME = "phase77panel"
        const val PANEL_PASSWORD = "P77PanelPasswordOnly"
        const val CSRF_TOKEN = "phase77-csrf-token"
        const val AUTH_COOKIE = "3x-ui"
        const val READY_FILE = "ready.properties"
        const val LOGIN_COMPLETED_FILE = "webpanel.login.completed"
        const val TRANSPORT_CLOSED_FILE = "transport.closed"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_HTTP_FILE = "unexpected.http"
        const val RELEASE_FILE = "release.marker"
        const val LOGIN_TIMEOUT_MILLIS = 120_000L
        const val RELEASE_TIMEOUT_MILLIS = 120_000L
    }
}
