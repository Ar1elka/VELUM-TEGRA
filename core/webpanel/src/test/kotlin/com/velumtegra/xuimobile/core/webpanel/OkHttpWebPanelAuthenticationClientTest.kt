package com.velumtegra.xuimobile.core.webpanel

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.StandaloneWebPanelTargetDetails
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLoopbackEndpoint
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.time.Instant
import java.security.KeyStore
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OkHttpWebPanelAuthenticationClientTest {
    @Test
    fun `direct current protocol authenticates once with csrf cookie and closes process local session`() = runBlocking {
        ScriptedHttpServer(successScripts(twoFactor = false)).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request())

            assertTrue(result is WebPanelAuthenticationResult.Authenticated)
            val session = (result as WebPanelAuthenticationResult.Authenticated).session
            assertTrue(session.isOpen)
            assertFalse(session.toString().contains(PASSWORD))
            assertFalse(session.toString().contains("session-cookie-value"))
            session.close()
            session.close()
            assertFalse(session.isOpen)

            val requests = server.awaitRequests(3)
            assertEquals("GET /base/csrf-token HTTP/1.1", requests[0].requestLine)
            assertEquals("POST /base/getTwoFactorEnable HTTP/1.1", requests[1].requestLine)
            assertEquals("csrf-token-value", requests[1].headers["x-csrf-token"])
            assertTrue(requests[1].headers["cookie"].orEmpty().contains("3x-ui=preflight-cookie"))
            assertEquals("POST /base/login HTTP/1.1", requests[2].requestLine)
            assertEquals(1, requests.count { it.requestLine.contains(" /base/login ") })
            assertTrue(requests[2].bodyText.contains("username=admin"))
            assertTrue(requests[2].bodyText.contains("password=$PASSWORD"))
            assertFalse(requests[2].bodyText.contains("twoFactorCode="))
            assertEquals(1, fixture.secretStore.readCalls.get())
            assertEquals(PANEL_SECRET_ID, fixture.secretStore.lastReadId)
        }
    }

    @Test
    fun `two factor required returns before password secret read or credential submission`() = runBlocking {
        ScriptedHttpServer(successScripts(twoFactor = true).take(2)).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.SECOND_FACTOR_REQUIRED, result.evidence.failure)
            assertEquals(CredentialSubmissionState.NOT_STARTED, result.evidence.credentialSubmission)
            assertEquals(0, fixture.secretStore.readCalls.get())
            assertEquals(2, server.awaitRequests(2).size)
            assertEquals(0, server.requests.count { it.requestLine.contains(" /base/login ") })
        }
    }

    @Test
    fun `explicit second factor is sent only in the single login submission`() = runBlocking {
        ScriptedHttpServer(successScripts(twoFactor = true)).use { server ->
            val fixture = AuthFixture.direct(server.port)
            WebPanelSecondFactor.fromBytes(OTP.encodeToByteArray()).use { otp ->
                val result = fixture.client.authenticate(fixture.request(secondFactor = otp))
                assertTrue(result is WebPanelAuthenticationResult.Authenticated)
                (result as WebPanelAuthenticationResult.Authenticated).session.close()
            }

            val requests = server.awaitRequests(3)
            val login = requests.single { it.requestLine.contains(" /base/login ") }
            assertTrue(login.bodyText.contains("password=$PASSWORD"))
            assertTrue(login.bodyText.contains("twoFactorCode=$OTP"))
            assertEquals(1, requests.count { it.bodyText.contains("password=$PASSWORD") })
            assertEquals(1, requests.count { it.bodyText.contains("twoFactorCode=$OTP") })
        }
    }

    @Test
    fun `authentication rejection reports one rejected credential submission and never retries`() = runBlocking {
        val scripts = successScripts(twoFactor = false).dropLast(1) + response("{\"success\":false,\"msg\":\"wrong\"}")
        ScriptedHttpServer(scripts).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.AUTHENTICATION_REJECTED, result.evidence.failure)
            assertEquals(CredentialSubmissionState.REJECTED, result.evidence.credentialSubmission)
            val requests = server.awaitRequests(3)
            assertEquals(1, requests.count { it.requestLine.contains(" /base/login ") })
        }
    }

    @Test
    fun `revision changed during preflight fails before password read and login`() = runBlocking {
        ScriptedHttpServer(successScripts(twoFactor = false).take(2)).use { server ->
            val fixture = AuthFixture.direct(server.port)
            fixture.webPanelRepository.authReads = ArrayDeque(
                listOf(
                    RepositoryResult.Success(VersionedRecord(fixture.access, REVISION)),
                    RepositoryResult.Success(VersionedRecord(fixture.access, RecordRevision(REVISION.value + 1))),
                ),
            )
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_REVISION_CHANGED, result.evidence.failure)
            assertEquals(0, fixture.secretStore.readCalls.get())
            assertEquals(0, server.awaitRequests(2).count { it.requestLine.contains(" /base/login ") })
        }
    }

    @Test
    fun `exact missing password secret fails without fallback or login`() = runBlocking {
        ScriptedHttpServer(successScripts(twoFactor = false).take(2)).use { server ->
            val fixture = AuthFixture.direct(server.port)
            fixture.secretStore.readResult = SecretReadResult.NotFound
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.PASSWORD_SECRET_NOT_FOUND, result.evidence.failure)
            assertEquals(1, fixture.secretStore.readCalls.get())
            assertEquals(PANEL_SECRET_ID, fixture.secretStore.lastReadId)
            assertEquals(0, fixture.secretStore.listCalls.get())
            assertEquals(0, server.awaitRequests(2).count { it.requestLine.contains(" /base/login ") })
        }
    }

    @Test
    fun `malformed csrf is protocol incompatible and never reaches secret or login`() = runBlocking {
        ScriptedHttpServer(listOf(response("{\"success\":true,\"obj\":7}"))).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationStage.PREFLIGHT_CSRF, result.evidence.stage)
            assertEquals(WebPanelAuthenticationFailure.PROTOCOL_INCOMPATIBLE, result.evidence.failure)
            assertEquals(0, fixture.secretStore.readCalls.get())
            assertEquals(1, server.awaitRequests(1).size)
        }
    }

    @Test
    fun `oversized response is bounded and fails before credential material`() = runBlocking {
        ScriptedHttpServer(listOf(response("{\"success\":true,\"obj\":\"${"x".repeat(2048)}\"}"))).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(
                fixture.request(config = WebPanelAuthenticationConfig(maxResponseBytes = 512)),
            ) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.RESPONSE_TOO_LARGE, result.evidence.failure)
            assertEquals(0, fixture.secretStore.readCalls.get())
            assertEquals(1, server.awaitRequests(1).size)
        }
    }

    @Test
    fun `redirect is not followed and remains typed http failure`() = runBlocking {
        ScriptedHttpServer(listOf(httpResponse(302, "", mapOf("Location" to "/base/csrf-token")))).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.HTTP_STATUS_FAILURE, result.evidence.failure)
            assertEquals(1, server.awaitRequests(1).size)
            assertEquals(0, fixture.secretStore.readCalls.get())
        }
    }

    @Test
    fun `ssh transport resolves logical authority only to exact loopback forward and preserves origin host header`() = runBlocking {
        ScriptedHttpServer(successScripts(twoFactor = false)).use { server ->
            val fixture = AuthFixture.ssh(server.port, REMOTE_PANEL_PORT)
            val result = fixture.client.authenticate(
                fixture.request(
                    transport = WebPanelAuthenticationTransport.SshTunnel(
                        forward = fixture.forward!!,
                        authorityHost = WebPanelHost("panel.example.test"),
                    ),
                ),
            )
            assertTrue(result is WebPanelAuthenticationResult.Authenticated)
            (result as WebPanelAuthenticationResult.Authenticated).session.close()

            val requests = server.awaitRequests(3)
            assertEquals(3, requests.size)
            assertTrue(requests.all { it.headers["host"] == "panel.example.test:$REMOTE_PANEL_PORT" })
            assertEquals(1, requests.count { it.requestLine.contains(" /base/login ") })
        }
    }

    @Test
    fun `closed or mismatched ssh forward fails before any network or secret read`() = runBlocking {
        ScriptedHttpServer(emptyList()).use { server ->
            val fixture = AuthFixture.ssh(server.port, REMOTE_PANEL_PORT)
            fixture.forward!!.open.set(false)
            val closed = fixture.client.authenticate(
                fixture.request(
                    transport = WebPanelAuthenticationTransport.SshTunnel(
                        fixture.forward,
                        WebPanelHost("panel.example.test"),
                    ),
                ),
            ) as WebPanelAuthenticationResult.Failed
            assertEquals(WebPanelAuthenticationFailure.FORWARD_NOT_OPEN, closed.evidence.failure)
            assertEquals(0, fixture.secretStore.readCalls.get())
            assertEquals(0, server.requests.size)
        }
    }

    @Test
    fun `https transport never bypasses tls verification for loopback`() = runBlocking {
        UntrustedTlsServer().use { server ->
            val fixture = AuthFixture.direct(server.port, WebPanelScheme.HTTPS)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationStage.PREFLIGHT_CSRF, result.evidence.stage)
            assertEquals(WebPanelAuthenticationFailure.TLS_FAILURE, result.evidence.failure)
            assertEquals(0, fixture.secretStore.readCalls.get())
            assertTrue(server.accepted.get() >= 1)
        }
    }

    @Test
    fun `login connection loss after body write is ambiguous and is never retried`() = runBlocking {
        val scripts = successScripts(twoFactor = false).take(2) + closeWithoutResponse()
        ScriptedHttpServer(scripts).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.LOGIN_OUTCOME_UNKNOWN, result.evidence.failure)
            assertEquals(CredentialSubmissionState.OUTCOME_UNKNOWN, result.evidence.credentialSubmission)
            val requests = server.awaitRequests(3)
            assertEquals(1, requests.count { it.requestLine.contains(" /base/login ") })
            assertEquals(1, requests.count { it.bodyText.contains("password=$PASSWORD") })
        }
    }

    @Test
    fun `preflight session cookie alone never satisfies authenticated login cookie gate`() = runBlocking {
        val scripts = successScripts(twoFactor = false).dropLast(1) + response("{\"success\":true,\"obj\":null}")
        ScriptedHttpServer(scripts).use { server ->
            val fixture = AuthFixture.direct(server.port)
            val result = fixture.client.authenticate(fixture.request()) as WebPanelAuthenticationResult.Failed

            assertEquals(WebPanelAuthenticationFailure.AUTHENTICATED_SESSION_COOKIE_MISSING, result.evidence.failure)
            assertEquals(CredentialSubmissionState.OUTCOME_UNKNOWN, result.evidence.credentialSubmission)
            val requests = server.awaitRequests(3)
            assertTrue(requests[2].headers["cookie"].orEmpty().contains("3x-ui=preflight-cookie"))
            assertEquals(1, requests.count { it.requestLine.contains(" /base/login ") })
        }
    }

    @Test
    fun `credential body owns one wipeable buffer and clears it on close`() {
        val password = "sensitive pass+%".encodeToByteArray()
        val secondFactor = "654321".encodeToByteArray()
        val body = OneShotFormBody.create("user name", password, secondFactor)
        val bytesField = OneShotFormBody::class.java.getDeclaredField("bytes").apply { isAccessible = true }
        val backing = bytesField.get(body) as ByteArray

        assertTrue(backing.toString(Charsets.UTF_8).contains("username=user+name"))
        assertTrue(backing.toString(Charsets.UTF_8).contains("password=sensitive+pass%2B%25"))
        assertTrue(backing.toString(Charsets.UTF_8).contains("twoFactorCode=654321"))
        assertFalse(backing === password)
        assertFalse(backing === secondFactor)
        assertFalse(body.toString().contains("sensitive"))

        body.close()
        body.close()
        assertTrue(backing.all { it == 0.toByte() })
        assertEquals(null, bytesField.get(body))
        java.util.Arrays.fill(password, 0)
        java.util.Arrays.fill(secondFactor, 0)
    }

    @Test
    fun `coroutine cancellation cancels exact in flight preflight call and never reaches secrets or next request`() = runBlocking {
        val createdPaths = CopyOnWriteArrayList<String>()
        val heldCall = AtomicReference<HoldingCall?>(null)
        val fixture = AuthFixture.direct(
            port = 1,
            callFactory = { client, request ->
                createdPaths += request.url.encodedPath
                HoldingCall(client.newCall(request)).also { heldCall.set(it) }
            },
        )
        val attempt = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { fixture.client.authenticate(fixture.request()) }
        val call = awaitHoldingCall(heldCall)
        call.awaitEnqueued()

        attempt.cancelAndJoin()

        assertTrue(attempt.isCancelled)
        assertEquals(1, call.cancelCalls.get())
        assertTrue(call.isCanceled())
        assertEquals(listOf("/base/csrf-token"), createdPaths.toList())
        assertEquals(0, fixture.secretStore.readCalls.get())
        assertEquals(0, fixture.secretStore.listCalls.get())
    }

    @Test
    fun `strict json parser rejects duplicate security fields and trailing injection`() {
        assertEquals(null, BoundedJson.parseObject("{\"success\":false,\"success\":true}"))
        assertEquals(null, BoundedJson.parseObject("{\"success\":true}{}"))
        val parsed = BoundedJson.parseObject("{\"success\":true,\"obj\":\"csrf\\u002dtoken\"}")
        assertNotNull(parsed)
    }

    private class AuthFixture private constructor(
        val access: WebPanelAccess,
        val target: com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget,
        val webPanelRepository: MutableWebPanelRepository,
        val secretStore: FakeSecretStore,
        val forward: FakeForward?,
        callFactory: ((okhttp3.OkHttpClient, okhttp3.Request) -> okhttp3.Call)? = null,
    ) {
        val client = if (callFactory == null) {
            OkHttpWebPanelAuthenticationClient(webPanelRepository, secretStore)
        } else {
            OkHttpWebPanelAuthenticationClient(webPanelRepository, secretStore, callFactory)
        }

        fun request(
            transport: WebPanelAuthenticationTransport = WebPanelAuthenticationTransport.Direct,
            secondFactor: WebPanelSecondFactor? = null,
            config: WebPanelAuthenticationConfig = TEST_CONFIG,
        ) = WebPanelAuthenticationRequest(target, transport, secondFactor, config)

        companion object {
            fun direct(
                port: Int,
                scheme: WebPanelScheme = WebPanelScheme.HTTP,
                callFactory: ((okhttp3.OkHttpClient, okhttp3.Request) -> okhttp3.Call)? = null,
            ): AuthFixture {
                val access = WebPanelAccess(
                    PANEL_ID,
                    WebPanelInstallationLink.Standalone,
                    "admin",
                    PANEL_SECRET_ID,
                    WebPanelRoute.Direct("127.0.0.1"),
                )
                val repository = MutableWebPanelRepository(access)
                val target = resolveTarget(
                    access,
                    repository,
                    scheme,
                    StandaloneWebPanelTargetDetails.Direct(port, "/base/"),
                )
                repository.resetForAuth()
                return AuthFixture(access, target, repository, FakeSecretStore(), null, callFactory)
            }

            fun ssh(localPort: Int, remotePort: Int): AuthFixture {
                val access = WebPanelAccess(
                    PANEL_ID,
                    WebPanelInstallationLink.Standalone,
                    "admin",
                    PANEL_SECRET_ID,
                    WebPanelRoute.SshTunnel(SERVER_ACCESS_ID),
                )
                val repository = MutableWebPanelRepository(access)
                val server = Server(SERVER_ID, "test", Instant.EPOCH)
                val serverAccess = ServerAccess(
                    SERVER_ACCESS_ID,
                    SERVER_ID,
                    SshEndpoint("ssh.example.test", 22),
                    "root",
                    SshAuthRef.Password(SecretId("ssh-secret")),
                    HostKeyFingerprint("SHA256:test"),
                )
                val target = resolveTarget(
                    access,
                    repository,
                    WebPanelScheme.HTTP,
                    StandaloneWebPanelTargetDetails.SshTunnel("127.0.0.1", remotePort, "/base/"),
                    server,
                    serverAccess,
                )
                repository.resetForAuth()
                val forward = FakeForward(
                    target,
                    SessionBinding(SessionId("session-web"), SERVER_ACCESS_ID, SessionOwner.WebPanel(PANEL_ID)),
                    loopbackEndpoint(localPort),
                )
                return AuthFixture(access, target, repository, FakeSecretStore(), forward)
            }
        }
    }

    private class MutableWebPanelRepository(private val access: WebPanelAccess) : WebPanelAccessRepository {
        var authReads: ArrayDeque<RepositoryResult<VersionedRecord<WebPanelAccess>>> = ArrayDeque()
        private var resolverMode = true

        fun resetForAuth() {
            resolverMode = false
            authReads = ArrayDeque()
        }

        override suspend fun get(webPanelAccessId: WebPanelAccessId): RepositoryResult<VersionedRecord<WebPanelAccess>> {
            if (resolverMode) return RepositoryResult.Success(VersionedRecord(access, REVISION))
            return if (authReads.isEmpty()) RepositoryResult.Success(VersionedRecord(access, REVISION)) else authReads.removeFirst()
        }

        override suspend fun list(): RepositoryResult<List<VersionedRecord<WebPanelAccess>>> = error("No fallback list")
        override suspend fun updateMetadata(access: WebPanelAccess, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("No writes")
        override suspend fun delete(webPanelAccessId: WebPanelAccessId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("No writes")
    }

    private class FakeSecretStore : SecretStore {
        val readCalls = AtomicInteger(0)
        val listCalls = AtomicInteger(0)
        var lastReadId: SecretId? = null
        var readResult: SecretReadResult? = null

        override suspend fun read(secretId: SecretId): SecretReadResult {
            readCalls.incrementAndGet()
            lastReadId = secretId
            return readResult ?: SecretReadResult.Found(SecretMaterial.fromBytes(PASSWORD.encodeToByteArray()))
        }

        override suspend fun listIds(): SecretListResult {
            listCalls.incrementAndGet()
            error("Secret fallback list forbidden")
        }

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult = error("No writes")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult = error("No writes")
    }

    private class FakeForward(
        override val target: com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget,
        override val sessionBinding: SessionBinding,
        override val localEndpoint: WebPanelLoopbackEndpoint,
    ) : WebPanelLocalForwardHandle {
        val open = AtomicBoolean(true)
        override val isOpen: Boolean get() = open.get()
        override fun close() { open.set(false) }
        override fun toString(): String = "FakeForward([REDACTED])"
    }

    private class HoldingCall(private val delegate: okhttp3.Call) : okhttp3.Call by delegate {
        val cancelCalls = AtomicInteger(0)
        private val executed = AtomicBoolean(false)
        private val cancelled = AtomicBoolean(false)
        private val enqueued = java.util.concurrent.CountDownLatch(1)

        override fun enqueue(responseCallback: okhttp3.Callback) {
            check(executed.compareAndSet(false, true)) { "Already Executed" }
            enqueued.countDown()
        }

        override fun cancel() {
            cancelCalls.incrementAndGet()
            cancelled.set(true)
        }

        override fun isExecuted(): Boolean = executed.get()
        override fun isCanceled(): Boolean = cancelled.get()

        fun awaitEnqueued() {
            check(enqueued.await(2, java.util.concurrent.TimeUnit.SECONDS)) { "Expected preflight Call.enqueue" }
        }
    }

    private fun awaitHoldingCall(reference: AtomicReference<HoldingCall?>): HoldingCall {
        repeat(400) {
            reference.get()?.let { return it }
            Thread.sleep(5)
        }
        error("Expected preflight call to be created")
    }

    private data class RecordedRequest(
        val requestLine: String,
        val headers: Map<String, String>,
        val body: ByteArray,
    ) {
        val bodyText: String get() = body.toString(Charsets.UTF_8)
    }

    private sealed interface ScriptReply {
        data class Http(val status: Int, val body: String, val headers: Map<String, String>) : ScriptReply
        data object Close : ScriptReply
        data object HoldUntilDisconnect : ScriptReply
    }

    private class ScriptedHttpServer(private val scripts: List<(RecordedRequest) -> ScriptReply>) : AutoCloseable {
        private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val running = AtomicBoolean(true)
        val requests: MutableList<RecordedRequest> = CopyOnWriteArrayList()
        private val disconnects = AtomicInteger(0)
        private val activeClient = AtomicReference<Socket?>(null)
        val port: Int get() = server.localPort
        private val worker = thread(name = "phase7-4-http-fixture", isDaemon = true) {
            var index = 0
            while (running.get() && index < scripts.size) {
                val socket = try { server.accept() } catch (_: Exception) { break }
                activeClient.set(socket)
                socket.use { client ->
                    val request = readRequest(client)
                    requests += request
                    when (val reply = scripts[index++](request)) {
                        ScriptReply.Close -> Unit
                        ScriptReply.HoldUntilDisconnect -> {
                            // readRequest() uses a bounded 3s fixture timeout. Once the request has
                            // been fully recorded, disable that timeout so this branch observes only
                            // the peer closing/resetting the socket as a consequence of Call.cancel().
                            client.soTimeout = 0
                            try {
                                while (client.getInputStream().read() >= 0) Unit
                                disconnects.incrementAndGet()
                            } catch (_: java.net.SocketException) {
                                disconnects.incrementAndGet()
                            }
                        }
                        is ScriptReply.Http -> writeResponse(client, reply)
                    }
                }
                activeClient.compareAndSet(socket, null)
            }
        }

        fun awaitRequests(count: Int): List<RecordedRequest> {
            repeat(200) {
                if (requests.size >= count) return requests.toList()
                Thread.sleep(5)
            }
            error("Expected $count requests, got ${requests.size}")
        }

        fun awaitDisconnects(count: Int): Int {
            repeat(600) {
                if (disconnects.get() >= count) return disconnects.get()
                Thread.sleep(5)
            }
            error("Expected $count real disconnects, got ${disconnects.get()}")
        }

        override fun close() {
            running.set(false)
            runCatching { activeClient.getAndSet(null)?.close() }
            runCatching { server.close() }
            worker.join(1000)
        }

        private fun readRequest(socket: Socket): RecordedRequest {
            socket.soTimeout = 3000
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
            val length = headers["content-length"]?.toIntOrNull() ?: 0
            val body = ByteArray(length)
            var offset = 0
            while (offset < length) {
                val read = input.read(body, offset, length - offset)
                require(read > 0)
                offset += read
            }
            return RecordedRequest(requestLine, headers, body)
        }

        private fun writeResponse(socket: Socket, reply: ScriptReply.Http) {
            val bytes = reply.body.encodeToByteArray()
            val output = BufferedOutputStream(socket.getOutputStream())
            output.write("HTTP/1.1 ${reply.status} ${if (reply.status in 200..299) "OK" else "FAIL"}\r\n".encodeToByteArray())
            output.write("Content-Type: application/json; charset=utf-8\r\n".encodeToByteArray())
            output.write("Content-Length: ${bytes.size}\r\n".encodeToByteArray())
            output.write("Connection: close\r\n".encodeToByteArray())
            reply.headers.forEach { (name, value) -> output.write("$name: $value\r\n".encodeToByteArray()) }
            output.write("\r\n".encodeToByteArray())
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
            return ByteArray(bytes.size) { bytes[it] }.toString(Charsets.US_ASCII)
        }
    }

    private class UntrustedTlsServer : AutoCloseable {
        private val running = AtomicBoolean(true)
        val accepted = AtomicInteger(0)
        private val keyStoreBytes = Base64.getDecoder().decode(TLS_FIXTURE_PKCS12)
        private val keyStorePassword = TLS_FIXTURE_PASSWORD.toCharArray()
        private val context = SSLContext.getInstance("TLS").apply {
            val keyStore = KeyStore.getInstance("PKCS12")
            ByteArrayInputStream(keyStoreBytes).use { keyStore.load(it, keyStorePassword) }
            val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
                init(keyStore, keyStorePassword)
            }
            init(keyManagers.keyManagers, null, null)
        }
        private val server = context.serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = server.localPort
        private val worker = thread(name = "phase7-4-tls-negative-fixture", isDaemon = true) {
            while (running.get()) {
                val socket = try { server.accept() } catch (_: Exception) { break }
                accepted.incrementAndGet()
                socket.use { client ->
                    runCatching { (client as SSLSocket).startHandshake() }
                }
                break
            }
        }

        override fun close() {
            running.set(false)
            runCatching { server.close() }
            worker.join(1000)
            java.util.Arrays.fill(keyStoreBytes, 0)
            java.util.Arrays.fill(keyStorePassword, '\u0000')
        }
    }

    companion object {
        private val PANEL_ID = WebPanelAccessId("panel-1")
        private val PANEL_SECRET_ID = SecretId("panel-secret")
        private val SERVER_ID = ServerId("server-1")
        private val SERVER_ACCESS_ID = ServerAccessId("access-1")
        private val REVISION = RecordRevision(7)
        private const val PASSWORD = "phase74-pass"
        private const val OTP = "123456"
        private const val REMOTE_PANEL_PORT = 18443
        private const val TLS_FIXTURE_PASSWORD = "phase74fixture"
        private val TLS_FIXTURE_PKCS12 =
                "MIIJ/wIBAzCCCbUGCSqGSIb3DQEHAaCCCaYEggmiMIIJnjCCBAoGCSqGSIb3DQEHBqCCA/swggP3AgEAMIID8AYJKoZIhvcNAQcB" +
                "MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDsUgjlZwLY028/idwifFfsAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFl" +
                "AwQBKgQQLg/S106rLNuvYdqE48XSmoCCA4CmX7A8+746S/wqdsBPtOneePw1Vq2Er1i5kadu3G03ApGikuD6TNN9dc+QWMFDYLvF" +
                "6+eD1Mmvd1S6PAOb2UzzUAyxClAuoCKWRk64vhDh3+z+5YYRww8FlOFfspY1G/cc7G0TWZbW8gKlQgQDMHt/l0o4k7aKkFBSbFJv" +
                "0UbqEnM4GWY4Wxhl5N732vlhtsecy5WzvvLwwsJDgnxYseTiG25j3SbHSWa0ZSwBngrrdSTEhIzOSjGQq8+/doc7ZykWAnjLQeBS" +
                "84Y8W0vnrxcm6dYXdbqRLB/OFh5BLJTRGBd5QcPezO0PinjWU8cG2nAny/DSgyd5zcfXRruR1hY+h434c6uAuV4PBb9dNivlWMKY" +
                "omnxLeo/kbYoZIRYcRqh25po+e+v0UUzZi4Boh7cYhyHKNdYGWp3tZSwcAnDs578S19QzF7dCJIqR00DFefNg/67ptPT6JNvOcIq" +
                "+WEs9IQBqk3sNdJzj1bALJdYbyHy7+ocmBsAQIjevtorR0ucvzZMrmvdjOjgxXa88PGeSPwYYhJ9l4bDsGXdOMv5jK0aoh3S7J4x" +
                "XwspF4IpfVOQxOEd2vscyL/JYuj2cahW3gOjAThdZ9bufryARXcuyCBrriSY9t0QI8gzQ9kNhoN9quFog7MYUJrcYQNWgdxCsIgD" +
                "SaJYi8xBvjEN5rU/v3QXTnshyvS2NXVnLZXNbEPa1N4T5twJx7eIvM4LsOKJ7THegKFssTivX/FB+88yiWhkG9JdRPar8TGWap5R" +
                "njRn28ebEG3XndADofVvCTk8Y8ai98Is1gpV/1+Od4Dva3SQDnrvhTH8+ah9psXCkKV5aoSQ3E+vTwPZ97xvDSsbRamCOziZG8g7" +
                "2APQSv5/cOBmopXlYMtOwJmQQIMP4pCKFMVyEdvIbcvILsNrjelM0PxtXKfjCyPiNJvLv3DOvmyxKh+WGfkArhQT8hl/k2tdH2Qs" +
                "SLHvlk67DdBYVLen4NYXPLFFIUujEpuaYdkRogORQiybliXd3BSN9mFIwjer5V3sxO1sFcrScQiNrQD7f/AGZUk+fPcPzbcydYZc" +
                "5DnQs0htob/NcGOTWwKl0T3OozXgGKlTRRo9MwrE2EZqQJHSe8J6KB3FrmNPy7qyqHI5+y+bqgt1cuA72YK4HQ9QeNAdX8Qy3ogH" +
                "NXeTycwUQd4JneEJB9Zc3eaTVWqASzCCBYwGCSqGSIb3DQEHAaCCBX0EggV5MIIFdTCCBXEGCyqGSIb3DQEMCgECoIIFOTCCBTUw" +
                "XwYJKoZIhvcNAQUNMFIwMQYJKoZIhvcNAQUMMCQEECacMptf3X/HAhXKKY0v5JUCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUD" +
                "BAEqBBDFOKdcne0ERlUd9iolHqENBIIE0BYghXWlPc76ExEU+GMbntTESTRi613hVozsyLm5z/RFZ1Hydos/fqs8iPpPT3oMilHH" +
                "SZBuBHBfx+dGYdIkgHRtgayrpCY5l008s9wPXIuPX9ptVJloDXCwcSWv4cTGvLTtyiBLKNttsTUhfB1XzZGAJZEJwFtAJAARVKMa" +
                "z7dJ5NuufGrUklQ1dxORs994NwfjXNFwwmYzd/rR6vPdWASyYZlz3szxxnT+6YRz19PeU4PBakoaamzqU2X+mL+sfU8q34cW8zgJ" +
                "ctKqvJb1jmJhze2+BMpKPTXvNMzcxFUZ7V1XNrBrHjy7nShqaaEcAnG0SaplAz/KR14H5cFW0n+JD6R/cfmNt/zG0KIH1f29VPPT" +
                "46niiiRW/PoGvZKe+AjKbwMc92crIQjC3clviOV5WBjBQ/Q69k2jVkYbHwTlqQpVw74tM+6jMo4rkuuj63miCXyOkkPTlb+nzk0q" +
                "624RWRSa/6CiTr+Nv+3La+aiMFG/eWvodj2AZpYw899JhLTxFuwJLlUitftWEF5fzUnEapwfxiw5/ROo5XgoheY9NxvhziGgI29z" +
                "njbSMapihYl9tThDSMrqWzIuPNNhBN/2cRGMcsZBlF5bXswlf4XirfNdnnv9GkhZGCGj+GIHOEzD6uCG34TcJQ1RPhFbc4pApgvO" +
                "JAY/icfsLUENPX7HPuhdhHTwLlQlXzOI+crgi2DZXm+mXO/HgCNiPSYo55E3csRzqxaobaC1O7EvVJy7lCGGHSm3zUgjK2/V/Ddv" +
                "XxmDjFAIJvDF7kNZH6f3Pw6OyR7yzJOwNuaw+TIJW/8rcDDQLkrPYmHXXAKpR0DXDbEuDmpaJ0uZNKDPj27M/KNwU1kEf8VhIlrV" +
                "rZUfffHWB1sLn5b1AEeyXXXGunQ7aAy1vljp2TBFhXr+baXuVzxI93LSC8P8nyFCcLmMaBVb4CGewe86Wr95BAjplJQ2rysESTsb" +
                "ZW5Jzn/scnj1IPsxoCbIYBea/dFEQDHu4GYehgb2MFa5KJemH3BKW6UnurbdZVJUuzYxVs6ILFHF/ZAGbRZTasq6GbUfZq9+dFGA" +
                "EOzYSoWK+Rwj90ikGuSFSmFpFAC9C4CMh2lwlRKa1p3ivNhNjwoQZedGxnJc0fd6X9ne3qeWjuSgFCA9xo1IM4z43fHeuiLPJR7G" +
                "dJSTt9esINnLIFe4De+FtDZXiW8rmnFh3JGEtbbADQYr2/LZ3sseNu+MDOrcNd3wSqyU3BLhX+wVO/XdOTk6pYr8YNnmShDs2HHK" +
                "wDY9PvH+OI147IpzvXQGyBs1EFt2Nb0UoDh/lXDuASWP2e/yTIan0+CPekGCmMcV5roDxR3Xh+MVksAiMvUFxpcdqnMMhm8lkJLe" +
                "AdW3EnPlbC0Dm5x+tfOInvGV1mUFFl1FTc/1UKmiYZ5e90n4mv60qvCW8d0BR++N6aUJuBVbljL/KzhVQcYy4RlgdPcP+ZdlLicg" +
                "J6UaqNZFPaYtDnRdK8XW4um7Fi1bZ19xElMtFoRafDnj6FQCSLzOvJOKLqje92we4nLh8k9859RKGKcX8ARz6v5YpTaWD5De9ChV" +
                "RWGSLZwfc3ITY60nxA1tcReR1zuA5yvMpOsRAzFH+4frjfrTi/9ihGxQ/K5qGRPQ8iBS7adHRNOOMSUwIwYJKoZIhvcNAQkVMRYE" +
                "FFfSsU97kgz1I6elnp3cbpG9KqV4MEEwMTANBglghkgBZQMEAgEFAAQgM/R+bzxmyHrXQqA1ylP4go2VfVEd/k5PhfxUYTjwDNIE" +
                "CPyYEWLPls30AgIIAA=="
        private val TEST_CONFIG = WebPanelAuthenticationConfig(
            connectTimeout = java.time.Duration.ofSeconds(2),
            readTimeout = java.time.Duration.ofSeconds(2),
            writeTimeout = java.time.Duration.ofSeconds(2),
            callTimeout = java.time.Duration.ofSeconds(4),
        )

        private fun successScripts(twoFactor: Boolean): List<(RecordedRequest) -> ScriptReply> = listOf(
            { request ->
                assertEquals("GET /base/csrf-token HTTP/1.1", request.requestLine)
                ScriptReply.Http(
                    200,
                    "{\"success\":true,\"obj\":\"csrf-token-value\"}",
                    mapOf("Set-Cookie" to "3x-ui=preflight-cookie; Path=/base/; HttpOnly; SameSite=Lax"),
                )
            },
            { request ->
                assertEquals("POST /base/getTwoFactorEnable HTTP/1.1", request.requestLine)
                assertEquals("csrf-token-value", request.headers["x-csrf-token"])
                ScriptReply.Http(200, "{\"success\":true,\"obj\":$twoFactor}", emptyMap())
            },
            { request ->
                assertEquals("POST /base/login HTTP/1.1", request.requestLine)
                assertEquals("csrf-token-value", request.headers["x-csrf-token"])
                ScriptReply.Http(
                    200,
                    "{\"success\":true,\"obj\":null}",
                    mapOf("Set-Cookie" to "3x-ui=session-cookie-value; Path=/base/; HttpOnly; SameSite=Lax"),
                )
            },
        )

        private fun response(body: String): (RecordedRequest) -> ScriptReply = { ScriptReply.Http(200, body, emptyMap()) }
        private fun httpResponse(status: Int, body: String, headers: Map<String, String>): (RecordedRequest) -> ScriptReply =
            { ScriptReply.Http(status, body, headers) }
        private fun closeWithoutResponse(): (RecordedRequest) -> ScriptReply = { ScriptReply.Close }
        private fun holdUntilDisconnect(): (RecordedRequest) -> ScriptReply = { ScriptReply.HoldUntilDisconnect }

        private fun resolveTarget(
            access: WebPanelAccess,
            repository: WebPanelAccessRepository,
            scheme: WebPanelScheme,
            details: StandaloneWebPanelTargetDetails,
            server: Server? = null,
            serverAccess: ServerAccess? = null,
        ): com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget = runBlocking {
            val resolver = ExactWebPanelTargetResolver(
                repository,
                NoopInstallationRepository,
                FixedServerRepository(server),
                FixedServerAccessRepository(serverAccess),
            )
            val result = resolver.resolve(WebPanelTargetResolutionRequest(access.id, scheme, details))
            (result as WebPanelTargetResolutionResult.Resolved).target
        }

        private fun loopbackEndpoint(port: Int): WebPanelLoopbackEndpoint {
            val constructor = WebPanelLoopbackEndpoint::class.java.declaredConstructors.single { it.parameterCount == 1 }
            constructor.isAccessible = true
            return constructor.newInstance(port) as WebPanelLoopbackEndpoint
        }

        private object NoopInstallationRepository : XuiInstallationRepository {
            override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> = error("Not used")
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = error("No fallback")
            override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("No writes")
        }

        private class FixedServerRepository(private val server: Server?) : ServerRepository {
            override suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>> =
                server?.let { RepositoryResult.Success(VersionedRecord(it, RecordRevision(2))) } ?: error("Not used")
            override suspend fun list(): RepositoryResult<List<VersionedRecord<Server>>> = error("No fallback")
            override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("No writes")
        }

        private class FixedServerAccessRepository(private val access: ServerAccess?) : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> = access?.let { RepositoryResult.Success(it) } ?: error("Not used")
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = error("No fallback")
            override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("No writes")
        }
    }
}
