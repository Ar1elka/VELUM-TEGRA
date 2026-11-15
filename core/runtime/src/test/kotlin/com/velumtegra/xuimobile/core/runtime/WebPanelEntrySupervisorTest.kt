package com.velumtegra.xuimobile.core.runtime

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
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.WebPanelForwardingSshSessionHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardConfig
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardOpenResult
import com.velumtegra.xuimobile.core.ssh.WebPanelLoopbackEndpoint
import com.velumtegra.xuimobile.core.webpanel.CredentialSubmissionState
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticatedSession
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationClient
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationFailure
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationFailureEvidence
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationRequest
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationStage
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationTransport
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class WebPanelEntrySupervisorTest {
    private val panelId = WebPanelAccessId("panel-a")
    private val serverId = ServerId("server-a")
    private val sshId = ServerAccessId("ssh-a")

    @Test
    fun directEntryAuthenticatesOnceWithoutTouchingSshAndSecondOpenReusesProcessLocalEntry() = runBlocking {
        val fixture = Fixture.direct()

        val first = fixture.supervisor.open(fixture.directRequest())
        assertTrue(first is WebPanelEntryResult.Opened)
        assertEquals(1, fixture.auth.calls.size)
        assertEquals(0, fixture.connection.calls)
        assertTrue(fixture.auth.calls.single().transport is WebPanelAuthenticationTransport.Direct)

        val second = fixture.supervisor.open(fixture.directRequest())
        assertTrue(second is WebPanelEntryResult.AlreadyOpen)
        assertEquals(1, fixture.auth.calls.size)
        assertEquals(WebPanelEntryStatus.ALREADY_OPEN, (second as WebPanelEntryResult.AlreadyOpen).projection.status)

        assertEquals(WebPanelEntryCloseResult.CLOSED, fixture.supervisor.close(panelId))
        assertTrue(fixture.auth.sessions.single().closed)
        assertEquals(WebPanelEntryCloseResult.ALREADY_CLOSED, fixture.supervisor.close(panelId))
    }

    @Test
    fun directFailureNeverFallsBackToSsh() = runBlocking {
        val fixture = Fixture.direct(
            authResult = { _ ->
                WebPanelAuthenticationResult.Failed(
                    WebPanelAuthenticationFailureEvidence(
                        stage = WebPanelAuthenticationStage.PREFLIGHT_CSRF,
                        failure = WebPanelAuthenticationFailure.NETWORK_FAILURE,
                        credentialSubmission = CredentialSubmissionState.NOT_STARTED,
                    ),
                )
            },
        )

        val result = fixture.supervisor.open(fixture.directRequest())

        assertTrue(result is WebPanelEntryResult.Failed)
        assertEquals(1, fixture.auth.calls.size)
        assertEquals(0, fixture.connection.calls)
        val failure = (result as WebPanelEntryResult.Failed).projection.failure
        assertTrue(failure is WebPanelEntryFailure.Authentication)
    }

    @Test
    fun sshEntryUsesExactWebPanelOwnerExactAccessForwardAndAuthorityThenCloseReleasesEverything() = runBlocking {
        val fixture = Fixture.ssh()

        val result = fixture.supervisor.open(fixture.sshRequest())

        assertTrue(result is WebPanelEntryResult.Opened)
        assertEquals(1, fixture.connection.calls)
        assertEquals(SessionOwner.WebPanel(panelId), fixture.connection.owners.single())
        assertEquals(sshId, fixture.connection.accesses.single().id)
        assertEquals(1, fixture.auth.calls.size)
        val authTransport = fixture.auth.calls.single().transport as WebPanelAuthenticationTransport.SshTunnel
        assertEquals(WebPanelHost("panel.example.test"), authTransport.authorityHost)
        assertSame(fixture.connection.handles.single().forward, authTransport.forward)
        assertEquals(1, fixture.sessionRegistry.size())

        (result as WebPanelEntryResult.Opened).session.close()

        assertEquals(0, fixture.sessionRegistry.size())
        assertTrue(fixture.connection.handles.single().closed)
        assertTrue(fixture.connection.handles.single().forward.closed)
        assertTrue(fixture.auth.sessions.single().closed)
    }

    @Test
    fun sshAuthorityIsExplicitAndMissingAuthorityStopsBeforeTransport() = runBlocking {
        val fixture = Fixture.ssh()
        val request = fixture.sshRequest().copy(sshAuthorityHost = null)

        val result = fixture.supervisor.open(request)

        assertTrue(result is WebPanelEntryResult.Failed)
        val failure = (result as WebPanelEntryResult.Failed).projection.failure as WebPanelEntryFailure.Local
        assertEquals(WebPanelEntryLocalFailure.SSH_AUTHORITY_REQUIRED, failure.kind)
        assertEquals(0, fixture.connection.calls)
        assertEquals(0, fixture.auth.calls.size)
    }

    @Test
    fun transientSshFailureUsesCanonicalRetryClassifierButSupervisorDoesNotRetry() = runBlocking {
        val fixture = Fixture.ssh(
            connectionFailure = SshConnectFailure.Unreachable("raw-sensitive-network-reason"),
        )

        val result = fixture.supervisor.open(fixture.sshRequest())

        assertTrue(result is WebPanelEntryResult.Failed)
        assertEquals(1, fixture.connection.calls)
        assertEquals(0, fixture.auth.calls.size)
        val failed = result as WebPanelEntryResult.Failed
        val failure = failed.projection.failure as WebPanelEntryFailure.SshConnect
        assertEquals(RetryFailureCategory.TRANSIENT_TRANSPORT, failure.category)
        assertTrue(failure.retryableOnFreshConnectivity)
        assertFalse(failed.projection.toString().contains("raw-sensitive-network-reason"))
    }

    @Test
    fun authenticationRejectionDoesNotReconnectOrResubmitAndCleansSshTransport() = runBlocking {
        val fixture = Fixture.ssh(
            authResult = {
                WebPanelAuthenticationResult.Failed(
                    WebPanelAuthenticationFailureEvidence(
                        stage = WebPanelAuthenticationStage.LOGIN,
                        failure = WebPanelAuthenticationFailure.AUTHENTICATION_REJECTED,
                        credentialSubmission = CredentialSubmissionState.REJECTED,
                    ),
                )
            },
        )

        val result = fixture.supervisor.open(fixture.sshRequest())

        assertTrue(result is WebPanelEntryResult.Failed)
        assertEquals(1, fixture.connection.calls)
        assertEquals(1, fixture.auth.calls.size)
        assertEquals(0, fixture.sessionRegistry.size())
        assertTrue(fixture.connection.handles.single().forward.closed)
        assertTrue(fixture.connection.handles.single().closed)
    }

    @Test
    fun staleEntryCloseCannotRemoveFreshReplacementSessionId() = runBlocking {
        val fixture = Fixture.ssh()
        val result = fixture.supervisor.open(fixture.sshRequest()) as WebPanelEntryResult.Opened
        val first = fixture.connection.handles.single()
        val owner = SessionOwner.WebPanel(panelId)
        val replacement = FakeForwardingSession(
            SessionBinding(SessionId("replacement-session"), sshId, owner),
        )

        fixture.sessionRegistry.install(replacement)
        assertTrue(first.closed)
        assertFalse(result.session.isOpen)

        result.session.close()

        assertSame(replacement, fixture.sessionRegistry.find(owner, sshId))
        assertTrue(replacement.isOpen)
    }

    @Test
    fun mismatchedFactoryBindingFailsClosedBeforeForwardOrAuthentication() = runBlocking {
        val wrongOwner = SessionOwner.WebPanel(WebPanelAccessId("other-panel"))
        val fixture = Fixture.ssh(
            handleFactory = {
                FakeForwardingSession(SessionBinding(SessionId("bad"), sshId, wrongOwner))
            },
        )

        val result = fixture.supervisor.open(fixture.sshRequest())

        assertTrue(result is WebPanelEntryResult.Failed)
        val local = (result as WebPanelEntryResult.Failed).projection.failure as WebPanelEntryFailure.Local
        assertEquals(WebPanelEntryLocalFailure.SSH_SESSION_BINDING_MISMATCH, local.kind)
        assertEquals(0, fixture.auth.calls.size)
        assertTrue(fixture.connection.handles.single().closed)
    }

    @Test
    fun deadSshProjectionDisposesAuthenticatedStateAndExactRegistryEntry() = runBlocking {
        val fixture = Fixture.ssh()
        val opened = fixture.supervisor.open(fixture.sshRequest()) as WebPanelEntryResult.Opened
        val authenticated = fixture.auth.sessions.single()
        val handle = fixture.connection.handles.single()

        // Simulate lower-layer transport loss after successful authentication.
        handle.close()
        assertFalse(opened.session.isOpen)
        assertFalse(authenticated.closed)

        assertNull(fixture.supervisor.projection(panelId))

        assertTrue(authenticated.closed)
        assertTrue(handle.forward.closed)
        assertEquals(0, fixture.sessionRegistry.size())
        assertFalse(opened.session.isOpen)
    }

    @Test
    fun safeProjectionDoesNotExposeEndpointPathSessionOrEphemeralPort() = runBlocking {
        val fixture = Fixture.ssh()
        val result = fixture.supervisor.open(fixture.sshRequest()) as WebPanelEntryResult.Opened
        val text = result.session.projection.toString()

        assertTrue(text.contains(panelId.value))
        assertFalse(text.contains("panel.example.test"))
        assertFalse(text.contains("127.0.0.1"))
        assertFalse(text.contains("/private-panel/"))
        assertFalse(text.contains("session-"))
        assertFalse(text.contains("45678"))
    }

    @Test
    fun supervisorCloseIsProcessLocalAndDoesNotCallAnyRepositoryMutation() = runBlocking {
        val fixture = Fixture.direct()
        fixture.supervisor.open(fixture.directRequest())

        fixture.supervisor.close()

        assertEquals(0, fixture.webPanelRepository.updateCalls)
        assertEquals(0, fixture.webPanelRepository.deleteCalls)
        assertEquals(0, fixture.serverAccessRepository.deleteCalls)
        assertTrue(fixture.auth.sessions.single().closed)
    }

    private class Fixture private constructor(
        val webPanelRepository: FakeWebPanelRepository,
        val serverAccessRepository: FakeServerAccessRepository,
        val connection: FakeConnectionFactory,
        val auth: FakeAuthenticationClient,
        val sessionRegistry: ExactSessionRegistry,
        val supervisor: WebPanelEntrySupervisor,
        private val panelId: WebPanelAccessId,
        private val serverId: ServerId,
        private val sshId: ServerAccessId,
    ) {
        fun directRequest() = WebPanelEntryRequest(
            targetRequest = WebPanelTargetResolutionRequest(
                webPanelAccessId = panelId,
                scheme = WebPanelScheme.HTTPS,
                standaloneTarget = StandaloneWebPanelTargetDetails.Direct(
                    port = 8443,
                    webBasePath = "/private-panel/",
                ),
            ),
        )

        fun sshRequest() = WebPanelEntryRequest(
            targetRequest = WebPanelTargetResolutionRequest(
                webPanelAccessId = panelId,
                scheme = WebPanelScheme.HTTPS,
                standaloneTarget = StandaloneWebPanelTargetDetails.SshTunnel(
                    remoteHost = "127.0.0.1",
                    port = 2053,
                    webBasePath = "/private-panel/",
                ),
            ),
            sshAuthorityHost = WebPanelHost("panel.example.test"),
        )

        companion object {
            fun direct(
                authResult: (WebPanelAuthenticationRequest) -> WebPanelAuthenticationResult = { request ->
                    WebPanelAuthenticationResult.Authenticated(FakeAuthenticatedSession(request.target))
                },
            ): Fixture = build(
                route = WebPanelRoute.Direct("sensitive.example.test"),
                authResult = authResult,
            )

            fun ssh(
                connectionFailure: SshConnectFailure? = null,
                authResult: (WebPanelAuthenticationRequest) -> WebPanelAuthenticationResult = { request ->
                    WebPanelAuthenticationResult.Authenticated(FakeAuthenticatedSession(request.target))
                },
                handleFactory: ((SessionOwner.WebPanel) -> FakeForwardingSession)? = null,
            ): Fixture = build(
                route = WebPanelRoute.SshTunnel(ServerAccessId("ssh-a")),
                connectionFailure = connectionFailure,
                authResult = authResult,
                handleFactory = handleFactory,
            )

            private fun build(
                route: WebPanelRoute,
                connectionFailure: SshConnectFailure? = null,
                authResult: (WebPanelAuthenticationRequest) -> WebPanelAuthenticationResult,
                handleFactory: ((SessionOwner.WebPanel) -> FakeForwardingSession)? = null,
            ): Fixture {
                val panelId = WebPanelAccessId("panel-a")
                val serverId = ServerId("server-a")
                val sshId = ServerAccessId("ssh-a")
                val webPanel = FakeWebPanelRepository(
                    VersionedRecord(
                        WebPanelAccess(
                            id = panelId,
                            installationLink = WebPanelInstallationLink.Standalone,
                            username = "panel-user",
                            passwordSecretId = SecretId("panel-secret"),
                            route = route,
                        ),
                        RecordRevision(7),
                    ),
                )
                val sshAccess = ServerAccess(
                    id = sshId,
                    serverId = serverId,
                    endpoint = SshEndpoint("ssh.example.test", 22),
                    username = "root",
                    auth = SshAuthRef.Password(SecretId("ssh-secret")),
                    pinnedHostKey = HostKeyFingerprint("SHA256:fixture"),
                )
                val serverAccessRepository = FakeServerAccessRepository(sshAccess)
                val resolver = ExactWebPanelTargetResolver(
                    webPanelAccessRepository = webPanel,
                    installationRepository = EmptyInstallationRepository,
                    serverRepository = FakeServerRepository(
                        Server(serverId, "Fixture", Instant.parse("2026-09-11T10:00:00Z")),
                    ),
                    serverAccessRepository = serverAccessRepository,
                )
                val registry = ExactSessionRegistry()
                val connection = FakeConnectionFactory(
                    failure = connectionFailure,
                    handleFactory = handleFactory ?: { owner ->
                        FakeForwardingSession(
                            SessionBinding(
                                sessionId = SessionId("session-${owner.webPanelAccessId.value}"),
                                serverAccessId = sshId,
                                owner = owner,
                            ),
                        )
                    },
                )
                val auth = FakeAuthenticationClient(authResult)
                val supervisor = WebPanelEntrySupervisor(
                    targetResolver = resolver,
                    serverAccessRepository = serverAccessRepository,
                    connectionFactory = connection,
                    sessionRegistry = registry,
                    authenticationClient = auth,
                )
                return Fixture(
                    webPanel,
                    serverAccessRepository,
                    connection,
                    auth,
                    registry,
                    supervisor,
                    panelId,
                    serverId,
                    sshId,
                )
            }
        }
    }

    private class FakeAuthenticationClient(
        private val result: (WebPanelAuthenticationRequest) -> WebPanelAuthenticationResult,
    ) : WebPanelAuthenticationClient {
        val calls = mutableListOf<WebPanelAuthenticationRequest>()
        val sessions = mutableListOf<FakeAuthenticatedSession>()

        override suspend fun authenticate(request: WebPanelAuthenticationRequest): WebPanelAuthenticationResult {
            calls += request
            return result(request).also { value ->
                if (value is WebPanelAuthenticationResult.Authenticated && value.session is FakeAuthenticatedSession) {
                    sessions += value.session as FakeAuthenticatedSession
                }
            }
        }
    }

    private class FakeAuthenticatedSession(
        override val target: com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget,
    ) : WebPanelAuthenticatedSession {
        override val webPanelAccessId: WebPanelAccessId = target.webPanelAccessId
        var closed = false
        override val isOpen: Boolean get() = !closed
        override fun close() {
            closed = true
        }
    }

    private class FakeConnectionFactory(
        private val failure: SshConnectFailure?,
        private val handleFactory: (SessionOwner.WebPanel) -> FakeForwardingSession,
    ) : SshConnectionFactory {
        var calls = 0
        val owners = mutableListOf<SessionOwner>()
        val accesses = mutableListOf<ServerAccess>()
        val handles = mutableListOf<FakeForwardingSession>()

        override suspend fun connect(
            access: ServerAccess,
            owner: SessionOwner,
            config: SshTransportConfig,
        ): SshConnectResult {
            calls += 1
            owners += owner
            accesses += access
            failure?.let { return SshConnectResult.Failed(it) }
            val exactOwner = owner as SessionOwner.WebPanel
            val handle = handleFactory(exactOwner)
            handles += handle
            return SshConnectResult.Connected(handle)
        }
    }

    private class FakeForwardingSession(
        override val binding: SessionBinding,
    ) : WebPanelForwardingSshSessionHandle {
        var closed = false
        lateinit var forward: FakeForward
        override val isOpen: Boolean get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            error("WebPanel supervisor must not execute remote commands")
        }

        override fun openWebPanelLocalForward(
            target: com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget,
            config: WebPanelLocalForwardConfig,
        ): WebPanelLocalForwardOpenResult {
            forward = FakeForward(binding, target)
            return WebPanelLocalForwardOpenResult.Opened(forward)
        }

        override fun close() {
            if (closed) return
            closed = true
            if (::forward.isInitialized) forward.close()
        }
    }

    private class FakeForward(
        override val sessionBinding: SessionBinding,
        override val target: com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget,
    ) : WebPanelLocalForwardHandle {
        var closed = false
        override val localEndpoint: WebPanelLoopbackEndpoint = loopbackEndpoint(45678)
        override val isOpen: Boolean get() = !closed
        override fun close() {
            closed = true
        }
    }

    private class FakeWebPanelRepository(
        private val record: VersionedRecord<WebPanelAccess>,
    ) : WebPanelAccessRepository {
        var updateCalls = 0
        var deleteCalls = 0
        override suspend fun get(webPanelAccessId: WebPanelAccessId) =
            if (webPanelAccessId == record.value.id) RepositoryResult.Success(record) else RepositoryResult.NotFound

        override suspend fun list() = RepositoryResult.Success(listOf(record))
        override suspend fun updateMetadata(access: WebPanelAccess, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> {
            updateCalls += 1
            error("Not expected")
        }
        override suspend fun delete(webPanelAccessId: WebPanelAccessId, expectedRevision: RecordRevision): RepositoryResult<Unit> {
            deleteCalls += 1
            error("Not expected")
        }
    }

    private class FakeServerAccessRepository(
        private val access: ServerAccess,
    ) : ServerAccessRepository {
        var deleteCalls = 0
        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
            if (serverAccessId == access.id) RepositoryResult.Success(access) else RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(access))
        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> {
            deleteCalls += 1
            error("Not expected")
        }
    }

    private class FakeServerRepository(private val server: Server) : ServerRepository {
        override suspend fun get(serverId: ServerId) =
            if (serverId == server.id) RepositoryResult.Success(VersionedRecord(server, RecordRevision(1))) else RepositoryResult.NotFound
        override suspend fun list() = RepositoryResult.Success(listOf(VersionedRecord(server, RecordRevision(1))))
        override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("Not expected")
        override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("Not expected")
        override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("Not expected")
    }

    private object EmptyInstallationRepository : XuiInstallationRepository {
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> = RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = RepositoryResult.Success(emptyList())
        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("Not expected")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("Not expected")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("Not expected")
    }

    companion object {
        private fun loopbackEndpoint(port: Int): WebPanelLoopbackEndpoint {
            val constructor = WebPanelLoopbackEndpoint::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType!!)
            constructor.isAccessible = true
            return constructor.newInstance(port)
        }
    }
}
