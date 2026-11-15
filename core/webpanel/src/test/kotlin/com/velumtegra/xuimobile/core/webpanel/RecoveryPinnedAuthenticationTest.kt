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
import org.junit.Assert.assertNull
import org.junit.Test

class RecoveryPinnedAuthenticationTest {
    private fun transport(f: AuthFixture, pin: String = pin(), host: String = "127.0.0.1") =
        WebPanelAuthenticationTransport.SshTunnel(requireNotNull(f.forward), WebPanelHost(host), PinnedSshPanelCertificate(f.target,pin))
    @Test fun pinnedPrivateTlsAuthenticatesOnceReadsApiAndCloses() = runBlocking {
        val scripts=successScripts(false)+listOf(response("{\"success\":true,\"obj\":{\"cpu\":10}}"))
        ScriptedHttpServer(scripts,tls=true).use { server ->
            val f=AuthFixture.ssh(server.port,REMOTE_PANEL_PORT,WebPanelScheme.HTTPS)
            val result=f.client.authenticate(f.request(transport(f))) as WebPanelAuthenticationResult.Authenticated
            val reader=result.session as WebPanelServerStatusSession
            assertTrue(reader.readServerStatusOnce() is WebPanelServerStatusResult.Success)
            result.session.close();assertFalse(result.session.isOpen)
            assertEquals(1,server.awaitRequests(4).count{it.requestLine.contains("/login ")})
            assertEquals(1,f.secretStore.readCalls.get())
        }
    }
    @Test fun changedSavedLeafFailsBeforeCredentials() = runBlocking {
        ScriptedHttpServer(successScripts(false),tls=true).use { server ->
            val f=AuthFixture.ssh(server.port,REMOTE_PANEL_PORT,WebPanelScheme.HTTPS)
            assertTrue(f.client.authenticate(f.request(transport(f,"0".repeat(64)))) is WebPanelAuthenticationResult.Failed)
            assertEquals(0,f.secretStore.readCalls.get())
        }
    }
    @Test fun ordinaryTlsStillRejectsSelfSignedCertificate() = runBlocking {
        ScriptedHttpServer(successScripts(false),tls=true).use { server ->
            val f=AuthFixture.direct(server.port,WebPanelScheme.HTTPS)
            assertTrue(f.client.authenticate(f.request()) is WebPanelAuthenticationResult.Failed)
            assertEquals(0,f.secretStore.readCalls.get())
        }
    }
    @Test fun pinCannotAuthorizePlainHttp() = runBlocking {
        val f=AuthFixture.ssh(1,REMOTE_PANEL_PORT)
        assertTrue(f.client.authenticate(f.request(transport(f))) is WebPanelAuthenticationResult.Failed)
        assertEquals(0,f.secretStore.readCalls.get())
    }
    @Test fun pinCannotAuthorizeAnotherLogicalAuthority() = runBlocking {
        val f=AuthFixture.ssh(1,REMOTE_PANEL_PORT,WebPanelScheme.HTTPS)
        assertTrue(f.client.authenticate(f.request(transport(f,host="elsewhere.invalid"))) is WebPanelAuthenticationResult.Failed)
        assertEquals(0,f.secretStore.readCalls.get())
    }
    @Test fun finalSourceFenceRejectsAfterPreflightBeforeSecret() = runBlocking {
        ScriptedHttpServer(successScripts(false).take(2)).use { server ->
            val f=AuthFixture.direct(server.port)
            val result=f.client.authenticate(WebPanelAuthenticationRequest(f.target,WebPanelAuthenticationTransport.Direct,config=TEST_CONFIG,credentialAuthority={false}))
            assertTrue(result is WebPanelAuthenticationResult.Failed);assertEquals(0,f.secretStore.readCalls.get())
            assertEquals(0,server.awaitRequests(2).count{it.requestLine.contains("/login ")})
        }
    }
    @Test fun pinnedTwoFactorDoesNotSendPassword() = runBlocking {
        ScriptedHttpServer(successScripts(true).take(2),tls=true).use { server ->
            val f=AuthFixture.ssh(server.port,REMOTE_PANEL_PORT,WebPanelScheme.HTTPS)
            val result=f.client.authenticate(f.request(transport(f))) as WebPanelAuthenticationResult.Failed
            assertEquals(WebPanelAuthenticationFailure.SECOND_FACTOR_REQUIRED,result.evidence.failure)
            assertEquals(0,f.secretStore.readCalls.get())
        }
    }
    @Test fun pinRejectsMalformedFingerprint() {
        val f=AuthFixture.ssh(1,REMOTE_PANEL_PORT,WebPanelScheme.HTTPS)
        assertTrue(runCatching{PinnedSshPanelCertificate(f.target,"wrong")}.isFailure)
    }
    @Test fun pinCannotCrossExactRemoteTarget() = runBlocking {
        val f=AuthFixture.ssh(1,REMOTE_PANEL_PORT,WebPanelScheme.HTTPS)
        val other=AuthFixture.ssh(1,REMOTE_PANEL_PORT+1,WebPanelScheme.HTTPS)
        val transport=WebPanelAuthenticationTransport.SshTunnel(requireNotNull(f.forward),WebPanelHost("127.0.0.1"),PinnedSshPanelCertificate(other.target,pin()))
        assertTrue(f.client.authenticate(f.request(transport)) is WebPanelAuthenticationResult.Failed)
        assertEquals(0,f.secretStore.readCalls.get())
    }
    @Test fun exactPinDoesNotAcceptExpiredLeaf() {
        val cert=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode("MIICvzCCAaegAwIBAgIBAzANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9maXh0dXJlLmludmFsaWQwHhcNMDAwMTAxMDAwMDAwWhcNMDEwMTAxMDAwMDAwWjAaMRgwFgYDVQQDDA9maXh0dXJlLmludmFsaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkRxHUarqAO5P4wzLQlmnswPuCCM62jzy//GOTu1xqKiHfBpVcHmHG9PPZ37T9vgp2IQKX3sXPUuc5gibVSNeKkGJtB3uL805eGR39wupWTU/BEQdlcinm/piMtiw6X+Vtwa6PW4vf2hHRCDbLQJOcB6BGrPyCJLwnlzSzwZ9Q2vZUzKJLmc+/uNl8Vo0v8ETOREFxSeFlUsVwmx239+wjYT41wuKXoRC5cqP+NOv45IQQthLqysXuE3TSOgdF/xpDBHb7c0Fl4MnOct9vyCAz+LltmUV5XKxIXj/SthQBAsa4+WkPob9UghXNo0h+f9P91iKK9ZHCenfIw3r4PF+NAgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBADBH6+xJ+PNfoQWQ4cBO16AzSv+RpU3NPF3BoUgTnCSM2fAv0Xu0TcWELHVut+LFzh7CpJPngvkOudParbw2z+dZGKekKruymb2cGFAJkyJ8YYzCnVE1eqmUw2kfTDpunq1D92nA2wJJPe89IjDI9/7cCxoAycVjFv5lPKNyqolL0ibS79ckqhs9032AUsY3qOvqCzGMFLOrJ9tSn0dOiXVgMpqB2ra6Q6VPG65Atfv0s0Kx9A2D1vW0tRqbbQIuQkud4ZNb7V1erRJAFJnlC4JNW8X8t5rZe49n9zP/NW+M8IRbdOCEbC47AP+4Y4crShHzos0bH+s1Ox14hP9hUA8="))) as java.security.cert.X509Certificate
        assertTrue(runCatching{PinnedPanelTrustManager("712FCD504459B87552D4CAA7F24FD8E93400BB414B69C174F155373997684244").checkServerTrusted(arrayOf(cert),"RSA")}.exceptionOrNull() is java.security.cert.CertificateExpiredException)
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

            fun ssh(localPort: Int, remotePort: Int, scheme: WebPanelScheme = WebPanelScheme.HTTP): AuthFixture {
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
                    scheme,
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
        val forwardOpen = AtomicBoolean(true)
        override val isOpen: Boolean get() = forwardOpen.get()
        override fun close() { forwardOpen.set(false) }
        override fun toString(): String = "FakeForward([REDACTED])"
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

    private class ScriptedHttpServer(private val scripts: List<(RecordedRequest) -> ScriptReply>, tls: Boolean = false) : AutoCloseable {
        private val server = if(tls) fixtureTls().serverSocketFactory.createServerSocket(0,50,InetAddress.getByName("127.0.0.1")) else ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
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
                    val request = runCatching { readRequest(client) }.getOrNull() ?: return@thread
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

    companion object {
        private fun keyStore(): KeyStore = KeyStore.getInstance("PKCS12").apply {
            load(ByteArrayInputStream(Base64.getDecoder().decode(TLS_FIXTURE_PKCS12)), TLS_FIXTURE_PASSWORD.toCharArray())
        }
        private fun fixtureTls(): SSLContext = SSLContext.getInstance("TLS").apply {
            val km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keyStore(), TLS_FIXTURE_PASSWORD.toCharArray()) }
            init(km.keyManagers, null, null)
        }
        private fun pin(): String = java.security.MessageDigest.getInstance("SHA-256").digest(keyStore().getCertificate("fixture").encoded).joinToString(""){"%02X".format(it)}

        private val PANEL_ID = WebPanelAccessId("panel-1")
        private val PANEL_SECRET_ID = SecretId("panel-secret")
        private val SERVER_ID = ServerId("server-1")
        private val SERVER_ACCESS_ID = ServerAccessId("access-1")
        private val REVISION = RecordRevision(7)
        private const val PASSWORD = "phase74-pass"
        private const val OTP = "123456"
        private const val REMOTE_PANEL_PORT = 18443
        private const val TLS_FIXTURE_PASSWORD = "phase74fixture"
        private val TLS_FIXTURE_PKCS12 = "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"
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
