package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class WebPanelTargetResolutionTest {
    private val serverId = ServerId("server-a")
    private val serverAccessId = ServerAccessId("ssh-a")
    private val installationId = XuiInstallationId("installation-a")
    private val webPanelAccessId = WebPanelAccessId("panel-a")
    private val capturedAt = Instant.parse("2026-09-10T10:00:00Z")

    @Test
    fun linkedDirectUsesExactRouteHostAndAcceptedBaseline() = runBlocking {
        val fixture = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(panelPort = 2053, webBasePath = "/panel/"),
        )

        val target = resolvedTarget(fixture.resolver.resolve(linkedRequest(WebPanelScheme.HTTPS)))
        val route = target.routeTarget as ResolvedWebPanelRouteTarget.Direct
        val linked = target.installation as ResolvedWebPanelInstallation.Linked

        assertEquals(webPanelAccessId, target.webPanelAccessId)
        assertEquals(RecordRevision(7), target.webPanelAccessRevision)
        assertEquals(installationId, linked.installationId)
        assertEquals(RecordRevision(11), linked.installationRevision)
        assertEquals(serverId, linked.serverId)
        assertEquals(WebPanelScheme.HTTPS, route.origin.scheme)
        assertEquals(WebPanelHost("panel.example.test"), route.origin.host)
        assertEquals(2053, route.origin.port)
        assertEquals(WebPanelBasePath("/panel/"), route.origin.webBasePath)
        assertEquals(0, fixture.serverAccessRepository.getCalls)
        fixture.assertNoListFallback()
    }

    @Test
    fun linkedSshUsesExactListenAddressAsRemoteDestinationNotSshEndpointHost() = runBlocking {
        val fixture = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(panelPort = 54321, listenAddress = "127.0.0.1"),
            serverAccess = serverAccess(endpointHost = "ssh-public.example.test"),
        )

        val target = resolvedTarget(fixture.resolver.resolve(linkedRequest(WebPanelScheme.HTTP)))
        val route = target.routeTarget as ResolvedWebPanelRouteTarget.SshTunnel

        assertEquals(serverAccessId, route.serverAccessId)
        assertEquals(serverId, route.serverId)
        assertEquals(WebPanelRemoteEndpoint(WebPanelHost("127.0.0.1"), 54321), route.remoteEndpoint)
        assertEquals(WebPanelScheme.HTTP, route.scheme)
        assertEquals(WebPanelBasePath("/panel/"), route.webBasePath)
        assertTrue(route.remoteEndpoint.host.value != "ssh-public.example.test")
        fixture.assertNoListFallback()
    }

    @Test
    fun standaloneDirectCanResolveOnlyFromDurableRoutePlusExplicitStructuralDetails() = runBlocking {
        val fixture = Fixture(
            access = webPanelAccess(
                route = WebPanelRoute.Direct("standalone.example.test"),
                link = WebPanelInstallationLink.Standalone,
            ),
        )

        val target = resolvedTarget(
            fixture.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId = webPanelAccessId,
                    scheme = WebPanelScheme.HTTPS,
                    standaloneTarget = StandaloneWebPanelTargetDetails.Direct(
                        port = 8443,
                        webBasePath = "/standalone/",
                    ),
                ),
            ),
        )
        val route = target.routeTarget as ResolvedWebPanelRouteTarget.Direct

        assertEquals(ResolvedWebPanelInstallation.Standalone, target.installation)
        assertEquals(WebPanelHost("standalone.example.test"), route.origin.host)
        assertEquals(8443, route.origin.port)
        assertEquals(WebPanelBasePath("/standalone/"), route.origin.webBasePath)
        assertEquals(WebPanelScheme.HTTPS, route.origin.scheme)
        assertEquals(0, fixture.installationRepository.getCalls)
        assertEquals(0, fixture.serverRepository.getCalls)
        assertEquals(0, fixture.serverAccessRepository.getCalls)
        fixture.assertNoListFallback()
    }

    @Test
    fun standaloneSshUsesExactAccessAndExplicitRemoteTargetWithoutBorrowingSshHost() = runBlocking {
        val fixture = Fixture(
            access = webPanelAccess(
                route = WebPanelRoute.SshTunnel(serverAccessId),
                link = WebPanelInstallationLink.Standalone,
            ),
            serverAccess = serverAccess(endpointHost = "ssh-public.example.test"),
        )

        val target = resolvedTarget(
            fixture.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId = webPanelAccessId,
                    scheme = WebPanelScheme.HTTP,
                    standaloneTarget = StandaloneWebPanelTargetDetails.SshTunnel(
                        remoteHost = "127.0.0.1",
                        port = 54321,
                        webBasePath = "/standalone/",
                    ),
                ),
            ),
        )
        val route = target.routeTarget as ResolvedWebPanelRouteTarget.SshTunnel

        assertEquals(ResolvedWebPanelInstallation.Standalone, target.installation)
        assertEquals(serverAccessId, route.serverAccessId)
        assertEquals(serverId, route.serverId)
        assertEquals(WebPanelRemoteEndpoint(WebPanelHost("127.0.0.1"), 54321), route.remoteEndpoint)
        assertTrue(route.remoteEndpoint.host.value != "ssh-public.example.test")
        assertEquals(0, fixture.installationRepository.getCalls)
        assertEquals(1, fixture.serverAccessRepository.getCalls)
        assertEquals(1, fixture.serverRepository.getCalls)
        fixture.assertNoListFallback()
    }

    @Test
    fun standaloneWithoutTargetDetailsStaysValidButUnresolved() = runBlocking {
        val fixture = Fixture(
            access = webPanelAccess(
                route = WebPanelRoute.Direct("standalone.example.test"),
                link = WebPanelInstallationLink.Standalone,
            ),
        )

        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(
                WebPanelTargetUnresolvedReason.STANDALONE_TARGET_DETAILS_REQUIRED,
            ),
            fixture.resolver.resolve(linkedRequest()),
        )
        assertEquals(0, fixture.installationRepository.getCalls)
        assertEquals(0, fixture.serverRepository.getCalls)
        assertEquals(0, fixture.serverAccessRepository.getCalls)
        fixture.assertNoListFallback()
    }

    @Test
    fun standaloneDetailsMustMatchDurableRouteAndCannotOverrideLinkedBaseline() = runBlocking {
        val standaloneDirect = Fixture(
            access = webPanelAccess(
                route = WebPanelRoute.Direct("standalone.example.test"),
                link = WebPanelInstallationLink.Standalone,
            ),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(
                WebPanelTargetConflictReason.STANDALONE_ROUTE_DETAILS_MISMATCH,
            ),
            standaloneDirect.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId,
                    WebPanelScheme.HTTP,
                    StandaloneWebPanelTargetDetails.SshTunnel("127.0.0.1", 54321, "/panel/"),
                ),
            ),
        )

        val linkedDirect = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(panelPort = 54321),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(
                WebPanelTargetConflictReason.STANDALONE_DETAILS_FOR_LINKED_ACCESS,
            ),
            linkedDirect.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId,
                    WebPanelScheme.HTTP,
                    StandaloneWebPanelTargetDetails.Direct(9999, "/override/"),
                ),
            ),
        )
        assertEquals(0, linkedDirect.installationRepository.getCalls)
        assertEquals(0, linkedDirect.serverRepository.getCalls)
        listOf(standaloneDirect, linkedDirect).forEach { it.assertNoListFallback() }
    }

    @Test
    fun linkedSshMissingOrWildcardListenAddressFailsClosedWithoutLoopbackOrSshHostFallback() = runBlocking {
        val missing = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(listenAddress = null),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.SSH_REMOTE_HOST_UNRESOLVED),
            missing.resolver.resolve(linkedRequest()),
        )

        val wildcard = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(listenAddress = "0.0.0.0"),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.SSH_REMOTE_HOST_UNRESOLVED),
            wildcard.resolver.resolve(linkedRequest()),
        )

        listOf(missing, wildcard).forEach { it.assertNoListFallback() }
    }

    @Test
    fun linkedSshRejectsCrossServerAccessByExactIdentityEvenWhenHostTextMatches() = runBlocking {
        val fixture = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(listenAddress = "127.0.0.1"),
            serverAccess = serverAccess(serverId = ServerId("server-b"), endpointHost = "127.0.0.1"),
        )

        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.SSH_SERVER_SCOPE_MISMATCH),
            fixture.resolver.resolve(linkedRequest()),
        )
        fixture.assertNoListFallback()
    }

    @Test
    fun exactMissingRecordsRemainTypedAndNeverSelectFromLists() = runBlocking {
        val missingAccess = Fixture(accessResult = RepositoryResult.NotFound)
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.WEB_PANEL_ACCESS_NOT_FOUND),
            missingAccess.resolver.resolve(linkedRequest()),
        )

        val missingInstallation = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installationResult = RepositoryResult.NotFound,
        )
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.LINKED_INSTALLATION_NOT_FOUND),
            missingInstallation.resolver.resolve(linkedRequest()),
        )

        val missingLinkedServer = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(),
            serverResult = RepositoryResult.NotFound,
        )
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.LINKED_SERVER_NOT_FOUND),
            missingLinkedServer.resolver.resolve(linkedRequest()),
        )

        val missingSshAccess = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(listenAddress = "127.0.0.1"),
            serverAccessResult = RepositoryResult.NotFound,
        )
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.SSH_SERVER_ACCESS_NOT_FOUND),
            missingSshAccess.resolver.resolve(linkedRequest()),
        )

        val missingStandaloneSshServer = Fixture(
            access = webPanelAccess(
                WebPanelRoute.SshTunnel(serverAccessId),
                WebPanelInstallationLink.Standalone,
            ),
            serverResult = RepositoryResult.NotFound,
        )
        assertEquals(
            WebPanelTargetResolutionResult.Unresolved(WebPanelTargetUnresolvedReason.SSH_SERVER_NOT_FOUND),
            missingStandaloneSshServer.resolver.resolve(standaloneSshRequest()),
        )

        listOf(
            missingAccess,
            missingInstallation,
            missingLinkedServer,
            missingSshAccess,
            missingStandaloneSshServer,
        ).forEach { it.assertNoListFallback() }
    }

    @Test
    fun exactLookupIdentityMismatchIsCorruptionNotFallback() = runBlocking {
        val wrongAccess = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")).copy(
                id = WebPanelAccessId("other-panel"),
            ),
        )
        assertEquals(WebPanelTargetResolutionResult.Corruption, wrongAccess.resolver.resolve(linkedRequest()))

        val wrongInstallation = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation().copy(id = XuiInstallationId("other-installation")),
        )
        assertEquals(WebPanelTargetResolutionResult.Corruption, wrongInstallation.resolver.resolve(linkedRequest()))

        val wrongLinkedServer = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(),
            server = server().copy(id = ServerId("other-server")),
        )
        assertEquals(WebPanelTargetResolutionResult.Corruption, wrongLinkedServer.resolver.resolve(linkedRequest()))

        val wrongSshAccess = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(listenAddress = "127.0.0.1"),
            serverAccess = serverAccess().copy(id = ServerAccessId("other-access")),
        )
        assertEquals(WebPanelTargetResolutionResult.Corruption, wrongSshAccess.resolver.resolve(linkedRequest()))

        val wrongStandaloneSshServer = Fixture(
            access = webPanelAccess(
                WebPanelRoute.SshTunnel(serverAccessId),
                WebPanelInstallationLink.Standalone,
            ),
            server = server().copy(id = ServerId("other-server")),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Corruption,
            wrongStandaloneSshServer.resolver.resolve(standaloneSshRequest()),
        )
    }

    @Test
    fun invalidDurableOrExplicitTargetDataFailsTypedWithoutNormalization() = runBlocking {
        val wildcardDirect = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("0.0.0.0")),
            installation = installation(),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.INVALID_DIRECT_ORIGIN_HOST),
            wildcardDirect.resolver.resolve(linkedRequest()),
        )

        val hostWithEmbeddedPort = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test:443")),
            installation = installation(),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.INVALID_DIRECT_ORIGIN_HOST),
            hostWithEmbeddedPort.resolver.resolve(linkedRequest()),
        )

        val nonNormalizedPath = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(webBasePath = "/panel//nested/"),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.INVALID_WEB_BASE_PATH),
            nonNormalizedPath.resolver.resolve(linkedRequest()),
        )

        val invalidStandalonePort = Fixture(
            access = webPanelAccess(
                WebPanelRoute.Direct("panel.example.test"),
                WebPanelInstallationLink.Standalone,
            ),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.INVALID_PANEL_PORT),
            invalidStandalonePort.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId,
                    WebPanelScheme.HTTP,
                    StandaloneWebPanelTargetDetails.Direct(0, "/panel/"),
                ),
            ),
        )

        val invalidStandaloneSshHost = Fixture(
            access = webPanelAccess(
                WebPanelRoute.SshTunnel(serverAccessId),
                WebPanelInstallationLink.Standalone,
            ),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.INVALID_SSH_REMOTE_HOST),
            invalidStandaloneSshHost.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId,
                    WebPanelScheme.HTTP,
                    StandaloneWebPanelTargetDetails.SshTunnel("::", 54321, "/panel/"),
                ),
            ),
        )
    }

    @Test
    fun repositoryConflictCorruptionAndStorageFailureRemainDistinct() = runBlocking {
        val accessConflict = Fixture(
            accessResult = RepositoryResult.ConstraintConflict("conflict"),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.REPOSITORY_READ_CONFLICT),
            accessConflict.resolver.resolve(linkedRequest()),
        )

        val installationCorruption = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installationResult = RepositoryResult.Corruption("bad-row"),
        )
        assertEquals(WebPanelTargetResolutionResult.Corruption, installationCorruption.resolver.resolve(linkedRequest()))

        val serverStorageFailure = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(),
            serverResult = RepositoryResult.StorageFailure("io"),
        )
        assertEquals(WebPanelTargetResolutionResult.StorageFailure, serverStorageFailure.resolver.resolve(linkedRequest()))

        val sshAccessConflict = Fixture(
            access = webPanelAccess(WebPanelRoute.SshTunnel(serverAccessId)),
            installation = installation(listenAddress = "127.0.0.1"),
            serverAccessResult = RepositoryResult.StaleRevision(RecordRevision(1), RecordRevision(2)),
        )
        assertEquals(
            WebPanelTargetResolutionResult.Conflict(WebPanelTargetConflictReason.REPOSITORY_READ_CONFLICT),
            sshAccessConflict.resolver.resolve(linkedRequest()),
        )
    }

    @Test
    fun schemeNeverInfersOrRewritesPanelPort() = runBlocking {
        val https = Fixture(
            access = webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
            installation = installation(panelPort = 2053),
        )
        val route = resolvedTarget(https.resolver.resolve(linkedRequest(WebPanelScheme.HTTPS))).routeTarget
            as ResolvedWebPanelRouteTarget.Direct
        assertEquals(WebPanelScheme.HTTPS, route.origin.scheme)
        assertEquals(2053, route.origin.port)

        val standalone = Fixture(
            access = webPanelAccess(
                WebPanelRoute.Direct("standalone.example.test"),
                WebPanelInstallationLink.Standalone,
            ),
        )
        val standaloneRoute = resolvedTarget(
            standalone.resolver.resolve(
                WebPanelTargetResolutionRequest(
                    webPanelAccessId,
                    WebPanelScheme.HTTPS,
                    StandaloneWebPanelTargetDetails.Direct(9443, "/panel/"),
                ),
            ),
        ).routeTarget as ResolvedWebPanelRouteTarget.Direct
        assertEquals(9443, standaloneRoute.origin.port)
    }

    @Test
    fun hostAndPathContractsRejectUnsafeShapesButAllowExactIpv6() {
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost(" https://panel.example.test ") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("0.0.0.0") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("panel.example.test:443") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("::::") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("::0") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("[0::]") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("999.999.999.999") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("-bad.example") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("bad..example") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelHost("[2001:db8::1") }
        assertEquals(WebPanelHost("2001:db8::1"), WebPanelHost("2001:db8::1"))
        assertEquals(WebPanelHost("[2001:db8::1]"), WebPanelHost("[2001:db8::1]"))
        assertEquals(WebPanelHost("2001:db8::192.0.2.1"), WebPanelHost("2001:db8::192.0.2.1"))

        assertThrows(IllegalArgumentException::class.java) { WebPanelBasePath("panel/") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelBasePath("/a/../b/") }
        assertThrows(IllegalArgumentException::class.java) { WebPanelBasePath("/a//b/") }
        assertTrue(WebPanelBasePath("/").value == "/")
    }

    private fun linkedRequest(scheme: WebPanelScheme = WebPanelScheme.HTTP) =
        WebPanelTargetResolutionRequest(webPanelAccessId, scheme)

    private fun standaloneSshRequest() = WebPanelTargetResolutionRequest(
        webPanelAccessId = webPanelAccessId,
        scheme = WebPanelScheme.HTTP,
        standaloneTarget = StandaloneWebPanelTargetDetails.SshTunnel(
            remoteHost = "127.0.0.1",
            port = 54321,
            webBasePath = "/panel/",
        ),
    )

    private fun resolvedTarget(result: WebPanelTargetResolutionResult): ResolvedWebPanelTarget =
        (result as WebPanelTargetResolutionResult.Resolved).target

    private fun server() = Server(serverId, "Server A", capturedAt.minusSeconds(100))

    private fun serverAccess(
        serverId: ServerId = this.serverId,
        endpointHost: String = "ssh.example.test",
    ) = ServerAccess(
        id = serverAccessId,
        serverId = serverId,
        endpoint = SshEndpoint(endpointHost, 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("ssh-secret")),
        pinnedHostKey = HostKeyFingerprint("SHA256:test-pin"),
    )

    private fun installation(
        panelPort: Int = 54321,
        webBasePath: String = "/panel/",
        listenAddress: String? = "127.0.0.1",
    ) = XuiInstallation(
        id = installationId,
        serverId = serverId,
        ownership = InstallationOwnership.ADOPTED,
        identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = null,
        ),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = panelPort,
            webBasePath = webBasePath,
            listenAddress = listenAddress,
            capturedAt = capturedAt,
        ),
    )

    private fun webPanelAccess(
        route: WebPanelRoute,
        link: WebPanelInstallationLink = WebPanelInstallationLink.Linked(installationId),
    ) = WebPanelAccess(
        id = webPanelAccessId,
        installationLink = link,
        username = "admin",
        passwordSecretId = SecretId("panel-secret"),
        route = route,
    )

    private inner class Fixture(
        access: WebPanelAccess? = null,
        installation: XuiInstallation? = null,
        server: Server? = null,
        serverAccess: ServerAccess? = null,
        accessResult: RepositoryResult<VersionedRecord<WebPanelAccess>>? = null,
        installationResult: RepositoryResult<VersionedRecord<XuiInstallation>>? = null,
        serverResult: RepositoryResult<VersionedRecord<Server>>? = null,
        serverAccessResult: RepositoryResult<ServerAccess>? = null,
    ) {
        val webPanelRepository = FakeWebPanelAccessRepository(
            accessResult ?: RepositoryResult.Success(
                VersionedRecord(
                    access ?: this@WebPanelTargetResolutionTest.webPanelAccess(WebPanelRoute.Direct("panel.example.test")),
                    RecordRevision(7),
                ),
            ),
        )
        val installationRepository = FakeInstallationRepository(
            installationResult ?: RepositoryResult.Success(
                VersionedRecord(
                    installation ?: this@WebPanelTargetResolutionTest.installation(),
                    RecordRevision(11),
                ),
            ),
        )
        val serverRepository = FakeServerRepository(
            serverResult ?: RepositoryResult.Success(
                VersionedRecord(server ?: this@WebPanelTargetResolutionTest.server(), RecordRevision(5)),
            ),
        )
        val serverAccessRepository = FakeServerAccessRepository(
            serverAccessResult ?: RepositoryResult.Success(
                serverAccess ?: this@WebPanelTargetResolutionTest.serverAccess(),
            ),
        )
        val resolver = ExactWebPanelTargetResolver(
            webPanelAccessRepository = webPanelRepository,
            installationRepository = installationRepository,
            serverRepository = serverRepository,
            serverAccessRepository = serverAccessRepository,
        )

        fun assertNoListFallback() {
            assertEquals(0, webPanelRepository.listCalls)
            assertEquals(0, installationRepository.listCalls)
            assertEquals(0, serverRepository.listCalls)
            assertEquals(0, serverAccessRepository.listCalls)
        }
    }

    private class FakeWebPanelAccessRepository(
        private val result: RepositoryResult<VersionedRecord<WebPanelAccess>>,
    ) : WebPanelAccessRepository {
        var getCalls = 0
        var listCalls = 0

        override suspend fun get(webPanelAccessId: WebPanelAccessId): RepositoryResult<VersionedRecord<WebPanelAccess>> {
            getCalls += 1
            return result
        }

        override suspend fun list(): RepositoryResult<List<VersionedRecord<WebPanelAccess>>> {
            listCalls += 1
            error("list() fallback must not be used")
        }

        override suspend fun updateMetadata(
            access: WebPanelAccess,
            expectedRevision: RecordRevision,
        ): RepositoryResult<RecordRevision> = error("resolver must not write")

        override suspend fun delete(
            webPanelAccessId: WebPanelAccessId,
            expectedRevision: RecordRevision,
        ): RepositoryResult<Unit> = error("resolver must not write")
    }

    private class FakeInstallationRepository(
        private val result: RepositoryResult<VersionedRecord<XuiInstallation>>,
    ) : XuiInstallationRepository {
        var getCalls = 0
        var listCalls = 0

        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> {
            getCalls += 1
            return result
        }

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> {
            listCalls += 1
            error("listForServer() fallback must not be used")
        }

        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> =
            error("resolver must not write")

        override suspend fun update(
            installation: XuiInstallation,
            expectedRevision: RecordRevision,
        ): RepositoryResult<RecordRevision> = error("resolver must not write")

        override suspend fun delete(
            installationId: XuiInstallationId,
            expectedRevision: RecordRevision,
        ): RepositoryResult<Unit> = error("resolver must not write")
    }

    private class FakeServerRepository(
        private val result: RepositoryResult<VersionedRecord<Server>>,
    ) : ServerRepository {
        var getCalls = 0
        var listCalls = 0

        override suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>> {
            getCalls += 1
            return result
        }

        override suspend fun list(): RepositoryResult<List<VersionedRecord<Server>>> {
            listCalls += 1
            error("list() fallback must not be used")
        }

        override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("resolver must not write")
        override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> =
            error("resolver must not write")
        override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> =
            error("resolver must not write")
    }

    private class FakeServerAccessRepository(
        private val result: RepositoryResult<ServerAccess>,
    ) : ServerAccessRepository {
        var getCalls = 0
        var listCalls = 0

        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> {
            getCalls += 1
            return result
        }

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> {
            listCalls += 1
            error("listForServer() fallback must not be used")
        }

        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> =
            error("resolver must not write")
    }
}
