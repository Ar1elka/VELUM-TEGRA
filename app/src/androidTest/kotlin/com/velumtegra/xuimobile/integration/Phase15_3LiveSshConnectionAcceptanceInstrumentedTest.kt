package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.readiness.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

@RunWith(AndroidJUnit4::class)
class Phase15_3LiveSshConnectionAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val pin = "SHA256:" + "A".repeat(43)
    private fun summary(id: String = "access-1") = LocalSshAccessSummary(
        id, "example.org", 22, "root", "Пароль", pin, "digest-not-secret",
    )
    private class LocalReads(private val entries: List<LocalSshAccessSummary>) : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(entries)
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult =
            entries.firstOrNull { it.accessId == accessId }?.let { LocalSshReadinessResult.MetadataPresent(it) }
                ?: LocalSshReadinessResult.Blocked("absent")
    }
    private class NoNetworkPort : LiveSshConnectionPort {
        var attempts = 0
        var last: String? = null
        override suspend fun connectExact(
            serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
            typedTarget: String, consent: Boolean,
        ): LiveSshConnectionResult {
            attempts++
            last = typedTarget
            return LiveSshConnectionResult.Verified(typedTarget, reviewed.savedFingerprint)
        }
    }
    private fun waitFor(id: String) = compose.waitUntil(8_000) {
        compose.onAllNodesWithTag(id).fetchSemanticsNodes().isNotEmpty()
    }

    @Test fun explicitConsentAndExactTargetRequiredBeforeNetwork() {
        val connection = NoNetworkPort()
        compose.setContent { LiveSshConnectionScreen("server-1", "VPS", LocalReads(listOf(summary())), connection) {} }
        waitFor("live_ssh_select_access-1")
        compose.onNodeWithTag("live_ssh_select_access-1").performScrollTo().performClick()
        waitFor("live_ssh_target")
        compose.onNodeWithTag("live_ssh_connect").assertIsNotEnabled()
        compose.onNodeWithTag("live_ssh_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("live_ssh_connect").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, connection.attempts) }
    }

    @Test fun oneExplicitClickInvokesExactlyOneConnectionWithoutCommands() {
        val connection = NoNetworkPort()
        compose.setContent { LiveSshConnectionScreen("server-1", "VPS", LocalReads(listOf(summary())), connection) {} }
        waitFor("live_ssh_select_access-1")
        compose.onNodeWithTag("live_ssh_select_access-1").performScrollTo().performClick()
        waitFor("live_ssh_target")
        compose.onNodeWithTag("live_ssh_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("live_ssh_consent").performScrollTo().performClick()
        compose.onNodeWithTag("live_ssh_connect").performScrollTo().performClick()
        waitFor("live_ssh_verified")
        compose.runOnIdle { assertEquals(1, connection.attempts); assertEquals("root@example.org:22", connection.last) }
    }

    @Test fun selectingDifferentAccessClearsPriorConsentAndTarget() {
        val connection = NoNetworkPort()
        compose.setContent { LiveSshConnectionScreen("server-1", "VPS", LocalReads(listOf(summary(), summary("access-2"))), connection) {} }
        waitFor("live_ssh_select_access-2")
        compose.onNodeWithTag("live_ssh_select_access-1").performScrollTo().performClick()
        waitFor("live_ssh_target")
        compose.onNodeWithTag("live_ssh_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("live_ssh_consent").performScrollTo().performClick()
        compose.onNodeWithTag("live_ssh_select_access-2").performScrollTo().performClick()
        waitFor("live_ssh_target")
        compose.onNodeWithTag("live_ssh_connect").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, connection.attempts) }
    }

    @Test fun staleCredentialReferenceIsBlockedBeforeFactoryConnect() = runBlocking {
        val server = Server(ServerId("server-1"), "VPS", Instant.EPOCH)
        val access = ServerAccess(
            ServerAccessId("access-1"), server.id, SshEndpoint("example.org",22), "root",
            SshAuthRef.Password(SecretId("secret-CHANGED")), HostKeyFingerprint(pin),
        )
        val servers = object : ServerRepository {
            override suspend fun get(serverId: ServerId) = RepositoryResult.Success(VersionedRecord(server, RecordRevision(0)))
            override suspend fun list() = RepositoryResult.Success(listOf(VersionedRecord(server, RecordRevision(0))))
            override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("create forbidden")
            override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("update forbidden")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("delete forbidden")
        }
        val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> = RepositoryResult.Success(access)
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = RepositoryResult.Success(listOf(access))
            override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("delete forbidden")
        }
        var factoryCalls = 0
        val factory = object : SshConnectionFactory {
            override suspend fun connect(access: ServerAccess, owner: SessionOwner, config: SshTransportConfig): SshConnectResult {
                factoryCalls++
                error("unexpected network")
            }
        }
        val result = RepositoryLiveSshConnectionPort(servers, accesses, factory).connectExact(
            "server-1", "access-1", summary(), "root@example.org:22", true,
        )
        assertTrue(result is LiveSshConnectionResult.Blocked)
        assertEquals(0, factoryCalls)
    }
}
