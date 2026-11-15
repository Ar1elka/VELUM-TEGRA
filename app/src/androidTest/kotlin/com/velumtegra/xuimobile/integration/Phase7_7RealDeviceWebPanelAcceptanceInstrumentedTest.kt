package com.velumtegra.xuimobile.integration

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.runtime.WebPanelEntryRequest
import com.velumtegra.xuimobile.core.runtime.WebPanelEntryResult
import com.velumtegra.xuimobile.core.runtime.WebPanelEntryRouteKind
import com.velumtegra.xuimobile.core.runtime.WebPanelEntryStatus
import com.velumtegra.xuimobile.core.runtime.WebPanelEntrySupervisor
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationConfig
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase7_7RealDeviceWebPanelAcceptanceInstrumentedTest {
    @Test
    fun realDeviceSshTunnelAuthenticatesOnceThenNetworkLossCleansExactEntry() = runBlocking {
        val sshPort = requiredIntArgument(ARG_FIXTURE_PORT)
        val panelPort = requiredIntArgument(ARG_PANEL_PORT)
        val fingerprint = requiredArgument(ARG_FIXTURE_FINGERPRINT)
        val runTag = requiredArgument(ARG_RUN_TAG)

        val panelId = WebPanelAccessId("phase77-panel-$runTag")
        val serverId = ServerId("phase77-server-$runTag")
        val serverAccessId = ServerAccessId("phase77-access-$runTag")
        val sshSecretId = SecretId("phase77-ssh-secret-$runTag")
        val panelSecretId = SecretId("phase77-panel-secret-$runTag")

        val panelAccess = WebPanelAccess(
            id = panelId,
            installationLink = WebPanelInstallationLink.Standalone,
            username = PANEL_USERNAME,
            passwordSecretId = panelSecretId,
            route = WebPanelRoute.SshTunnel(serverAccessId),
        )
        val server = Server(
            id = serverId,
            displayName = "Phase 7.7 controlled fixture",
            createdAt = Instant.parse("2026-09-11T00:00:00Z"),
        )
        val serverAccess = ServerAccess(
            id = serverAccessId,
            serverId = serverId,
            endpoint = SshEndpoint(LOOPBACK_HOST, sshPort),
            username = SSH_USERNAME,
            auth = SshAuthRef.Password(sshSecretId),
            pinnedHostKey = HostKeyFingerprint(fingerprint),
        )

        val webPanelRepository = ExactWebPanelRepository(panelAccess)
        val serverRepository = ExactServerRepository(server)
        val serverAccessRepository = ExactServerAccessRepository(serverAccess)
        val secretStore = FixtureSecretStore(
            mapOf(
                sshSecretId to SSH_PASSWORD.encodeToByteArray(),
                panelSecretId to PANEL_PASSWORD.encodeToByteArray(),
            ),
        )
        val resolver = ExactWebPanelTargetResolver(
            webPanelAccessRepository = webPanelRepository,
            installationRepository = EmptyInstallationRepository,
            serverRepository = serverRepository,
            serverAccessRepository = serverAccessRepository,
        )
        val sessionRegistry = ExactSessionRegistry()
        val supervisor = WebPanelEntrySupervisor(
            targetResolver = resolver,
            serverAccessRepository = serverAccessRepository,
            connectionFactory = JschSshConnectionFactory(secretStore) {
                SessionId("phase77-session-$runTag")
            },
            sessionRegistry = sessionRegistry,
            authenticationClient = OkHttpWebPanelAuthenticationClient(webPanelRepository, secretStore),
        )

        try {
            val result = supervisor.open(
                WebPanelEntryRequest(
                    targetRequest = WebPanelTargetResolutionRequest(
                        webPanelAccessId = panelId,
                        scheme = WebPanelScheme.HTTP,
                        standaloneTarget = StandaloneWebPanelTargetDetails.SshTunnel(
                            remoteHost = LOOPBACK_HOST,
                            port = panelPort,
                            webBasePath = "/base/",
                        ),
                    ),
                    sshAuthorityHost = WebPanelHost(LOOPBACK_HOST),
                    authenticationConfig = WebPanelAuthenticationConfig(
                        connectTimeout = Duration.ofSeconds(5),
                        readTimeout = Duration.ofSeconds(5),
                        writeTimeout = Duration.ofSeconds(5),
                        callTimeout = Duration.ofSeconds(10),
                    ),
                ),
            )

            if (result !is WebPanelEntryResult.Opened) {
                val safeFailure = (result as? WebPanelEntryResult.Failed)?.projection?.failure
                throw AssertionError("Integrated SSH-tunneled WebPanel entry must authenticate; safeFailure=$safeFailure")
            }
            val opened = result
            assertEquals(WebPanelEntryRouteKind.SSH_TUNNEL, opened.session.projection.routeKind)
            assertEquals(WebPanelEntryStatus.OPEN, opened.session.projection.status)
            assertEquals(1, sessionRegistry.size())
            assertTrue(opened.session.isOpen)

            val safeProjection = opened.session.projection.toString()
            listOf(
                SSH_USERNAME,
                SSH_PASSWORD,
                PANEL_USERNAME,
                PANEL_PASSWORD,
                LOOPBACK_HOST,
                "/base/",
                fingerprint,
            ).forEach { forbidden ->
                assertFalse("Safe projection leaked controlled sensitive/route material", safeProjection.contains(forbidden))
            }

            // The host fixture closes the authenticated SSH server after the successful login response.
            awaitCondition("owning SSH loss did not close the WebPanel entry") { !opened.session.isOpen }

            // Observing the now-dead exact entry must dispose authenticated HTTP/cookie state and
            // remove only the same exact registry binding. No reconnect/resubmit is performed.
            assertNull(supervisor.projection(panelId))
            assertEquals(0, sessionRegistry.size())
            assertFalse(opened.session.isOpen)

            // Give any forbidden hidden retry enough time to become observable by the host witness.
            Thread.sleep(750)
            assertEquals(0, sessionRegistry.size())
            assertEquals(0, webPanelRepository.updateCalls.get())
            assertEquals(0, webPanelRepository.deleteCalls.get())
            assertEquals(0, serverAccessRepository.deleteCalls.get())
        } finally {
            supervisor.close()
            sessionRegistry.close()
            secretStore.close()
        }
    }

    private class ExactWebPanelRepository(
        private val access: WebPanelAccess,
    ) : WebPanelAccessRepository {
        val updateCalls = AtomicInteger(0)
        val deleteCalls = AtomicInteger(0)

        override suspend fun get(webPanelAccessId: WebPanelAccessId): RepositoryResult<VersionedRecord<WebPanelAccess>> =
            if (webPanelAccessId == access.id) {
                RepositoryResult.Success(VersionedRecord(access, PANEL_REVISION))
            } else {
                RepositoryResult.NotFound
            }

        override suspend fun list(): RepositoryResult<List<VersionedRecord<WebPanelAccess>>> =
            error("Phase 7.7 forbids list/fallback selection")

        override suspend fun updateMetadata(
            access: WebPanelAccess,
            expectedRevision: RecordRevision,
        ): RepositoryResult<RecordRevision> {
            updateCalls.incrementAndGet()
            error("Phase 7.7 performs no durable WebPanel mutation")
        }

        override suspend fun delete(
            webPanelAccessId: WebPanelAccessId,
            expectedRevision: RecordRevision,
        ): RepositoryResult<Unit> {
            deleteCalls.incrementAndGet()
            error("Phase 7.7 performs no durable WebPanel deletion")
        }
    }

    private class ExactServerRepository(
        private val server: Server,
    ) : ServerRepository {
        override suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>> =
            if (serverId == server.id) {
                RepositoryResult.Success(VersionedRecord(server, RecordRevision(1)))
            } else {
                RepositoryResult.NotFound
            }

        override suspend fun list(): RepositoryResult<List<VersionedRecord<Server>>> =
            error("Phase 7.7 forbids list/fallback selection")
        override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("No writes")
        override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("No writes")
        override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("No writes")
    }

    private class ExactServerAccessRepository(
        private val access: ServerAccess,
    ) : ServerAccessRepository {
        val deleteCalls = AtomicInteger(0)

        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
            if (serverAccessId == access.id) RepositoryResult.Success(access) else RepositoryResult.NotFound

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> =
            error("Phase 7.7 forbids access list/fallback selection")

        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> {
            deleteCalls.incrementAndGet()
            error("Phase 7.7 performs no ServerAccess mutation")
        }
    }

    private object EmptyInstallationRepository : XuiInstallationRepository {
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
            RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> =
            error("Phase 7.7 standalone route must not list installations")
        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("No writes")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("No writes")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("No writes")
    }

    private class FixtureSecretStore(
        source: Map<SecretId, ByteArray>,
    ) : SecretStore, AutoCloseable {
        private val values = source.mapValues { (_, bytes) -> bytes.copyOf() }.toMutableMap()

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            error("Phase 7.7 secret store is read-only")

        override suspend fun read(secretId: SecretId): SecretReadResult =
            values[secretId]?.let { SecretReadResult.Found(SecretMaterial.fromBytes(it)) } ?: SecretReadResult.NotFound

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            error("Phase 7.7 secret store is read-only")

        override suspend fun listIds(): SecretListResult =
            error("Phase 7.7 forbids secret fallback/list selection")

        override fun close() {
            values.values.forEach { java.util.Arrays.fill(it, 0) }
            values.clear()
        }
    }

    private fun requiredArgument(name: String): String =
        InstrumentationRegistry.getArguments().getString(name)?.trim()?.takeIf { it.isNotEmpty() }
            ?: error("Missing required instrumentation argument: $name")

    private fun requiredIntArgument(name: String): Int =
        requiredArgument(name).toIntOrNull()?.takeIf { it in 1..65535 }
            ?: error("Invalid required port argument: $name")

    private fun awaitCondition(message: String, condition: () -> Boolean) {
        repeat(400) {
            if (condition()) return
            Thread.sleep(25)
        }
        throw AssertionError(message)
    }

    private companion object {
        const val ARG_FIXTURE_PORT = "phase77.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase77.fixtureFingerprint"
        const val ARG_PANEL_PORT = "phase77.panelPort"
        const val ARG_RUN_TAG = "phase77.runTag"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val SSH_USERNAME = "phase77ssh"
        const val SSH_PASSWORD = "P77SshPasswordOnly"
        const val PANEL_USERNAME = "phase77panel"
        const val PANEL_PASSWORD = "P77PanelPasswordOnly"
        val PANEL_REVISION = RecordRevision(7)
    }
}
