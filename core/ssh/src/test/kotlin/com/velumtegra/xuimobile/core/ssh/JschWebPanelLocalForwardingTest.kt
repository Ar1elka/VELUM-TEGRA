package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
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
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.CommandCompletion
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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.forward.AcceptAllForwardingFilter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JschWebPanelLocalForwardingTest {
    @Test
    fun `real jsch forward binds ephemeral loopback and reaches only resolved remote target`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val access = ssh.access(SERVER_ACCESS_ID)
                val panelTarget = resolveStandaloneSshTarget(
                    webPanelAccessId = WEB_PANEL_ID,
                    access = access,
                    remoteHost = LOOPBACK_HOST,
                    remotePort = targetServer.port,
                )
                val handle = ssh.connectHandle(access, SessionOwner.WebPanel(WEB_PANEL_ID))

                val opened = handle.openWebPanelLocalForward(panelTarget, FORWARD_CONFIG)
                assertTrue(opened is WebPanelLocalForwardOpenResult.Opened)
                val forward = (opened as WebPanelLocalForwardOpenResult.Opened).handle

                assertEquals(LOOPBACK_HOST, forward.localEndpoint.host)
                assertTrue(forward.localEndpoint.port in 1..65535)
                assertNotEquals(targetServer.port, forward.localEndpoint.port)
                assertEquals(handle.binding, forward.sessionBinding)
                assertEquals(panelTarget, forward.target)
                assertTrue(forward.isOpen)

                val payload = "phase-7-3-exact-target".encodeToByteArray()
                assertArrayEquals(payload, roundTrip(forward.localEndpoint, payload))
                assertEquals(1, targetServer.acceptedConnections.get())

                forward.close()
                forward.close() // exact forward cleanup is idempotent.
                assertFalse(forward.isOpen)
                assertTrue(handle.isOpen)
                assertEventuallyClosed(forward.localEndpoint)

                val reopened = handle.openWebPanelLocalForward(panelTarget, FORWARD_CONFIG)
                    as WebPanelLocalForwardOpenResult.Opened
                assertTrue(reopened.handle.isOpen)
                assertArrayEquals(
                    "reopened".encodeToByteArray(),
                    roundTrip(reopened.handle.localEndpoint, "reopened".encodeToByteArray()),
                )
                reopened.handle.close()
                handle.close()
            }
        }
    }

    @Test
    fun `same exact resolved target reuses same forward without second listener`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val access = ssh.access(SERVER_ACCESS_ID)
                val target = resolveStandaloneSshTarget(WEB_PANEL_ID, access, LOOPBACK_HOST, targetServer.port)
                val handle = ssh.connectHandle(access, SessionOwner.WebPanel(WEB_PANEL_ID))

                val first = handle.openWebPanelLocalForward(target, FORWARD_CONFIG)
                    as WebPanelLocalForwardOpenResult.Opened
                val second = handle.openWebPanelLocalForward(target, FORWARD_CONFIG)
                    as WebPanelLocalForwardOpenResult.AlreadyOpen

                assertSame(first.handle, second.handle)
                assertEquals(first.handle.localEndpoint.port, second.handle.localEndpoint.port)
                assertEquals(1, ssh.passwordAttempts.get())
                assertArrayEquals(
                    "same-target".encodeToByteArray(),
                    roundTrip(first.handle.localEndpoint, "same-target".encodeToByteArray()),
                )
                first.handle.close()
                handle.close()
            }
        }
    }

    @Test
    fun `different resolved target cannot replace live forward inside same ssh session`() = runBlocking {
        TcpEchoFixture().use { firstTargetServer ->
            TcpEchoFixture().use { secondTargetServer ->
                LocalForwardingSshFixture().use { ssh ->
                    val access = ssh.access(SERVER_ACCESS_ID)
                    val firstTarget = resolveStandaloneSshTarget(
                        WEB_PANEL_ID,
                        access,
                        LOOPBACK_HOST,
                        firstTargetServer.port,
                    )
                    val secondTarget = resolveStandaloneSshTarget(
                        WEB_PANEL_ID,
                        access,
                        LOOPBACK_HOST,
                        secondTargetServer.port,
                    )
                    val handle = ssh.connectHandle(access, SessionOwner.WebPanel(WEB_PANEL_ID))
                    val first = handle.openWebPanelLocalForward(firstTarget, FORWARD_CONFIG)
                        as WebPanelLocalForwardOpenResult.Opened

                    val rejected = handle.openWebPanelLocalForward(secondTarget, FORWARD_CONFIG)

                    assertEquals(
                        WebPanelLocalForwardOpenResult.Rejected(
                            WebPanelLocalForwardFailure.DIFFERENT_TARGET_ALREADY_FORWARDED,
                        ),
                        rejected,
                    )
                    assertTrue(first.handle.isOpen)
                    assertArrayEquals(
                        "first-stays-owner".encodeToByteArray(),
                        roundTrip(first.handle.localEndpoint, "first-stays-owner".encodeToByteArray()),
                    )
                    assertEquals(1, firstTargetServer.acceptedConnections.get())
                    assertEquals(0, secondTargetServer.acceptedConnections.get())
                    handle.close()
                }
            }
        }
    }

    @Test
    fun `direct route cannot enter ssh forwarding capability`() = runBlocking {
        LocalForwardingSshFixture().use { ssh ->
            val access = ssh.access(SERVER_ACCESS_ID)
            val directTarget = resolveStandaloneDirectTarget(WEB_PANEL_ID, "panel.example.test", 8443)
            val handle = ssh.connectHandle(access, SessionOwner.WebPanel(WEB_PANEL_ID))

            assertEquals(
                WebPanelLocalForwardOpenResult.Rejected(WebPanelLocalForwardFailure.ROUTE_NOT_SSH_TUNNEL),
                handle.openWebPanelLocalForward(directTarget, FORWARD_CONFIG),
            )
            assertTrue(handle.isOpen)
            handle.close()
        }
    }

    @Test
    fun `forward requires exact webpanel owner`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val access = ssh.access(SERVER_ACCESS_ID)
                val target = resolveStandaloneSshTarget(WEB_PANEL_ID, access, LOOPBACK_HOST, targetServer.port)
                val wrongOwner = SessionOwner.WebPanel(WebPanelAccessId("another-panel"))
                val handle = ssh.connectHandle(access, wrongOwner)

                assertEquals(
                    WebPanelLocalForwardOpenResult.Rejected(WebPanelLocalForwardFailure.SESSION_OWNER_MISMATCH),
                    handle.openWebPanelLocalForward(target, FORWARD_CONFIG),
                )
                assertEquals(0, targetServer.acceptedConnections.get())
                handle.close()
            }
        }
    }

    @Test
    fun `forward requires exact server access id and never matches by host`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val actualAccess = ssh.access(SERVER_ACCESS_ID)
                val otherAccess = ssh.access(ServerAccessId("other-access-same-host"))
                val target = resolveStandaloneSshTarget(WEB_PANEL_ID, otherAccess, LOOPBACK_HOST, targetServer.port)
                val handle = ssh.connectHandle(actualAccess, SessionOwner.WebPanel(WEB_PANEL_ID))

                assertEquals(
                    WebPanelLocalForwardOpenResult.Rejected(WebPanelLocalForwardFailure.SERVER_ACCESS_MISMATCH),
                    handle.openWebPanelLocalForward(target, FORWARD_CONFIG),
                )
                assertEquals(actualAccess.endpoint, otherAccess.endpoint)
                assertEquals(0, targetServer.acceptedConnections.get())
                handle.close()
            }
        }
    }

    @Test
    fun `owning ssh close deterministically closes forward and local listener`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val access = ssh.access(SERVER_ACCESS_ID)
                val target = resolveStandaloneSshTarget(WEB_PANEL_ID, access, LOOPBACK_HOST, targetServer.port)
                val handle = ssh.connectHandle(access, SessionOwner.WebPanel(WEB_PANEL_ID))
                val forward = (handle.openWebPanelLocalForward(target, FORWARD_CONFIG)
                    as WebPanelLocalForwardOpenResult.Opened).handle
                val endpoint = forward.localEndpoint

                handle.close()
                handle.close()

                assertFalse(handle.isOpen)
                assertFalse(forward.isOpen)
                assertEventuallyClosed(endpoint)
            }
        }
    }

    @Test
    fun `registry replacement closes prior session forward and stale cleanup cannot close replacement`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val access = ssh.access(SERVER_ACCESS_ID)
                val target = resolveStandaloneSshTarget(WEB_PANEL_ID, access, LOOPBACK_HOST, targetServer.port)
                val owner = SessionOwner.WebPanel(WEB_PANEL_ID)
                val first = ssh.connectHandle(access, owner)
                val second = ssh.connectHandle(access, owner)
                val registry = ExactSessionRegistry()
                assertEquals(SessionInstallResult.Installed, registry.install(first))
                val firstForward = (first.openWebPanelLocalForward(target, FORWARD_CONFIG)
                    as WebPanelLocalForwardOpenResult.Opened).handle
                val firstEndpoint = firstForward.localEndpoint

                val replacement = registry.install(second)
                assertTrue(replacement is SessionInstallResult.Replaced)
                assertFalse(first.isOpen)
                assertFalse(firstForward.isOpen)
                assertEventuallyClosed(firstEndpoint)

                val secondForward = (second.openWebPanelLocalForward(target, FORWARD_CONFIG)
                    as WebPanelLocalForwardOpenResult.Opened).handle
                assertFalse(
                    registry.remove(
                        owner = owner,
                        accessId = access.id,
                        sessionId = first.binding.sessionId,
                        close = true,
                    ),
                )
                assertTrue(second.isOpen)
                assertTrue(secondForward.isOpen)
                assertArrayEquals(
                    "replacement".encodeToByteArray(),
                    roundTrip(secondForward.localEndpoint, "replacement".encodeToByteArray()),
                )

                assertTrue(
                    registry.remove(
                        owner = owner,
                        accessId = access.id,
                        sessionId = second.binding.sessionId,
                        close = true,
                    ),
                )
                assertFalse(secondForward.isOpen)
                assertEventuallyClosed(secondForward.localEndpoint)
                registry.close()
            }
        }
    }

    @Test
    fun `closed session cannot create forward`() = runBlocking {
        TcpEchoFixture().use { targetServer ->
            LocalForwardingSshFixture().use { ssh ->
                val access = ssh.access(SERVER_ACCESS_ID)
                val target = resolveStandaloneSshTarget(WEB_PANEL_ID, access, LOOPBACK_HOST, targetServer.port)
                val handle = ssh.connectHandle(access, SessionOwner.WebPanel(WEB_PANEL_ID))
                handle.close()

                assertEquals(
                    WebPanelLocalForwardOpenResult.Rejected(WebPanelLocalForwardFailure.SESSION_NOT_OPEN),
                    handle.openWebPanelLocalForward(target, FORWARD_CONFIG),
                )
                assertEquals(0, targetServer.acceptedConnections.get())
            }
        }
    }

    @Test
    fun `non forwarding ssh handle fails typed instead of opening another connection`() = runBlocking {
        val fake = NonForwardingHandle(
            SessionBinding(
                sessionId = SessionId("fake-session"),
                serverAccessId = SERVER_ACCESS_ID,
                owner = SessionOwner.WebPanel(WEB_PANEL_ID),
            ),
        )
        val access = ServerAccess(
            id = SERVER_ACCESS_ID,
            serverId = SERVER_ID,
            endpoint = SshEndpoint("ssh.example.test", 22),
            username = "fixture",
            auth = SshAuthRef.Password(FIXTURE_SECRET_ID),
            pinnedHostKey = HostKeyFingerprint("SHA256:not-used"),
        )
        val target = resolveStandaloneSshTarget(WEB_PANEL_ID, access, LOOPBACK_HOST, 8080)

        assertEquals(
            WebPanelLocalForwardOpenResult.Rejected(
                WebPanelLocalForwardFailure.UNSUPPORTED_SESSION_CAPABILITY,
            ),
            fake.openWebPanelLocalForward(target, FORWARD_CONFIG),
        )
        assertTrue(fake.isOpen)
    }

    @Test
    fun `bracketed ipv6 host is normalized only at ssh transport boundary`() {
        assertEquals("2001:db8::1", WebPanelHost("[2001:db8::1]").toSshForwardDestinationHost())
        assertEquals("2001:db8::1", WebPanelHost("2001:db8::1").toSshForwardDestinationHost())
        assertEquals("panel.example.test", WebPanelHost("panel.example.test").toSshForwardDestinationHost())
    }

    @Test
    fun `forward timeout policy is bounded and has no local bind controls`() {
        assertThrows(IllegalArgumentException::class.java) {
            WebPanelLocalForwardConfig(remoteConnectTimeout = Duration.ZERO)
        }
        assertThrows(IllegalArgumentException::class.java) {
            WebPanelLocalForwardConfig(remoteConnectTimeout = Duration.ofMinutes(31))
        }
        assertEquals(Duration.ofSeconds(10), WebPanelLocalForwardConfig().remoteConnectTimeout)
    }

    private suspend fun resolveStandaloneSshTarget(
        webPanelAccessId: WebPanelAccessId,
        access: ServerAccess,
        remoteHost: String,
        remotePort: Int,
    ) = resolveTarget(
        webPanelAccess = WebPanelAccess(
            id = webPanelAccessId,
            installationLink = WebPanelInstallationLink.Standalone,
            username = "panel-user",
            passwordSecretId = SecretId("panel-secret"),
            route = WebPanelRoute.SshTunnel(access.id),
        ),
        serverAccess = access,
        request = WebPanelTargetResolutionRequest(
            webPanelAccessId = webPanelAccessId,
            scheme = WebPanelScheme.HTTP,
            standaloneTarget = StandaloneWebPanelTargetDetails.SshTunnel(
                remoteHost = remoteHost,
                port = remotePort,
                webBasePath = "/panel/",
            ),
        ),
    )

    private suspend fun resolveStandaloneDirectTarget(
        webPanelAccessId: WebPanelAccessId,
        host: String,
        port: Int,
    ) = resolveTarget(
        webPanelAccess = WebPanelAccess(
            id = webPanelAccessId,
            installationLink = WebPanelInstallationLink.Standalone,
            username = "panel-user",
            passwordSecretId = SecretId("panel-secret"),
            route = WebPanelRoute.Direct(host),
        ),
        serverAccess = null,
        request = WebPanelTargetResolutionRequest(
            webPanelAccessId = webPanelAccessId,
            scheme = WebPanelScheme.HTTPS,
            standaloneTarget = StandaloneWebPanelTargetDetails.Direct(
                port = port,
                webBasePath = "/panel/",
            ),
        ),
    )

    private suspend fun resolveTarget(
        webPanelAccess: WebPanelAccess,
        serverAccess: ServerAccess?,
        request: WebPanelTargetResolutionRequest,
    ) = ExactWebPanelTargetResolver(
        webPanelAccessRepository = object : WebPanelAccessRepository {
            override suspend fun get(webPanelAccessId: WebPanelAccessId) =
                if (webPanelAccessId == webPanelAccess.id) {
                    RepositoryResult.Success(VersionedRecord(webPanelAccess, RecordRevision(7)))
                } else {
                    RepositoryResult.NotFound
                }

            override suspend fun list() = error("list fallback forbidden")
            override suspend fun updateMetadata(access: WebPanelAccess, expectedRevision: RecordRevision) =
                error("write forbidden")
            override suspend fun delete(webPanelAccessId: WebPanelAccessId, expectedRevision: RecordRevision) =
                error("write forbidden")
        },
        installationRepository = object : XuiInstallationRepository {
            override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
                error("standalone resolver must not read installation")
            override suspend fun listForServer(serverId: ServerId) = error("list fallback forbidden")
            override suspend fun create(installation: XuiInstallation) = error("write forbidden")
            override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) =
                error("write forbidden")
            override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) =
                error("write forbidden")
        },
        serverRepository = object : ServerRepository {
            override suspend fun get(serverId: ServerId) =
                if (serverAccess != null && serverId == serverAccess.serverId) {
                    RepositoryResult.Success(
                        VersionedRecord(
                            Server(serverId, "Forward fixture", Instant.parse("2026-09-10T10:00:00Z")),
                            RecordRevision(3),
                        ),
                    )
                } else {
                    RepositoryResult.NotFound
                }

            override suspend fun list() = error("list fallback forbidden")
            override suspend fun create(server: Server) = error("write forbidden")
            override suspend fun update(server: Server, expectedRevision: RecordRevision) = error("write forbidden")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision) = error("write forbidden")
        },
        serverAccessRepository = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId) =
                if (serverAccess != null && serverAccessId == serverAccess.id) {
                    RepositoryResult.Success(serverAccess)
                } else {
                    RepositoryResult.NotFound
                }

            override suspend fun listForServer(serverId: ServerId) = error("list fallback forbidden")
            override suspend fun delete(serverAccessId: ServerAccessId) = error("write forbidden")
        },
    ).resolve(request).let { result ->
        check(result is WebPanelTargetResolutionResult.Resolved) { "Target did not resolve: $result" }
        result.target
    }

    private fun roundTrip(endpoint: WebPanelLoopbackEndpoint, payload: ByteArray): ByteArray =
        Socket().use { socket ->
            socket.connect(InetSocketAddress(endpoint.host, endpoint.port), 2_000)
            socket.soTimeout = 2_000
            socket.getOutputStream().write(payload)
            socket.getOutputStream().flush()
            val result = ByteArray(payload.size)
            var offset = 0
            while (offset < result.size) {
                val read = socket.getInputStream().read(result, offset, result.size - offset)
                check(read > 0) { "Forwarded target closed before echo completed" }
                offset += read
            }
            result
        }

    private fun assertEventuallyClosed(endpoint: WebPanelLoopbackEndpoint) {
        repeat(40) {
            val connected = runCatching {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(endpoint.host, endpoint.port), 75)
                }
            }.isSuccess
            if (!connected) return
            Thread.sleep(25)
        }
        throw AssertionError("Loopback forward listener remained reachable after deterministic close")
    }

    private class LocalForwardingSshFixture : AutoCloseable {
        private val hostKey = java.security.KeyPairGenerator.getInstance("RSA").apply {
            initialize(3072)
        }.generateKeyPair()
        val passwordAttempts = AtomicInteger(0)
        private val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                passwordAttempts.incrementAndGet()
                username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD
            }
            forwardingFilter = AcceptAllForwardingFilter.INSTANCE
        }
        private val hostFingerprint: String

        init {
            hostFingerprint = KeyUtils.getFingerPrint(hostKey.public)
            server.start()
            check(server.port in 1..65535)
        }

        fun access(id: ServerAccessId) = ServerAccess(
            id = id,
            serverId = SERVER_ID,
            endpoint = SshEndpoint(LOOPBACK_HOST, server.port),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.Password(FIXTURE_SECRET_ID),
            pinnedHostKey = HostKeyFingerprint(hostFingerprint),
        )

        suspend fun connectHandle(access: ServerAccess, owner: SessionOwner): SshSessionHandle {
            val result = JschSshConnectionFactory(
                StaticPasswordSecretStore(FIXTURE_SECRET_ID, FIXTURE_PASSWORD),
                detectPrivilege = false,
            ).connect(access, owner, SSH_CONFIG)
            check(result is SshConnectResult.Connected) { "SSH fixture connection failed: $result" }
            return result.handle
        }

        override fun close() {
            runCatching { server.stop() }
        }
    }

    private class TcpEchoFixture : AutoCloseable {
        private val closed = AtomicBoolean(false)
        private val socket = ServerSocket(0, 50, InetAddress.getByName(LOOPBACK_HOST))
        val port: Int = socket.localPort
        val acceptedConnections = AtomicInteger(0)
        private val worker = thread(start = true, isDaemon = true, name = "velum-webpanel-forward-target") {
            while (!closed.get()) {
                val client = try {
                    socket.accept()
                } catch (_: Exception) {
                    if (closed.get()) break else continue
                }
                acceptedConnections.incrementAndGet()
                client.use { accepted ->
                    accepted.soTimeout = 2_000
                    val input = accepted.getInputStream()
                    val output = accepted.getOutputStream()
                    val buffer = ByteArray(4096)
                    while (true) {
                        val read = try {
                            input.read(buffer)
                        } catch (_: Exception) {
                            break
                        }
                        if (read <= 0) break
                        output.write(buffer, 0, read)
                        output.flush()
                    }
                }
            }
        }

        override fun close() {
            if (closed.compareAndSet(false, true)) {
                runCatching { socket.close() }
                worker.join(1_000)
            }
        }
    }

    private class NonForwardingHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        private val open = AtomicBoolean(true)
        override val isOpen: Boolean
            get() = open.get()

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig) = SshCommandResult(
            dispatchState = CommandDispatchState.NOT_DISPATCHED,
            completion = CommandCompletion.Unknown("not used"),
            stdout = CapturedOutput.EMPTY,
            stderr = CapturedOutput.EMPTY,
        )

        override fun close() {
            open.set(false)
        }
    }

    private class StaticPasswordSecretStore(
        private val id: SecretId,
        password: String,
    ) : SecretStore {
        private val encoded = password.encodeToByteArray()

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Fixture store is read-only")

        override suspend fun read(secretId: SecretId): SecretReadResult = if (secretId == id) {
            SecretReadResult.Found(SecretMaterial.fromBytes(encoded))
        } else {
            SecretReadResult.NotFound
        }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Fixture store is read-only")

        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(id))
    }

    private companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-forward-fixture"
        const val FIXTURE_PASSWORD = "VELUM-forward-fixture-password-only"
        val SERVER_ID = ServerId("phase-7-3-server")
        val SERVER_ACCESS_ID = ServerAccessId("phase-7-3-access")
        val WEB_PANEL_ID = WebPanelAccessId("phase-7-3-panel")
        val FIXTURE_SECRET_ID = SecretId("phase-7-3-ssh-secret")
        val SSH_CONFIG = SshTransportConfig(
            tcpConnectTimeout = Duration.ofSeconds(5),
            handshakeAndAuthTimeout = Duration.ofSeconds(5),
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 4 * 1024,
            stderrCaptureLimitBytes = 4 * 1024,
        )
        val FORWARD_CONFIG = WebPanelLocalForwardConfig(remoteConnectTimeout = Duration.ofSeconds(2))
    }
}
