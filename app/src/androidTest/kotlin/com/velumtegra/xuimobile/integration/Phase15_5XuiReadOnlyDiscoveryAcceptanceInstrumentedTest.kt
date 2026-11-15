package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase15_5XuiReadOnlyDiscoveryAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val pin = "SHA256:" + "A".repeat(43)
    private fun summary(digest: String = "credential-hash") = LocalSshAccessSummary(
        "access-1", "example.org", 22, "root", "Пароль", pin, digest,
    )

    @Test fun discoveryRequiresOneExplicitConsentAndExactTarget() {
        val reviewed = summary()
        val current = LocalSshReadinessResult.MetadataPresent(reviewed)
        assertTrue(XuiDiscoveryConsentPolicy.reject("server-1", "access-1", reviewed,
            current, "root@example.org:22", false) != null)
        assertTrue(XuiDiscoveryConsentPolicy.reject("server-1", "access-1", reviewed,
            current, "root@other:22", true) != null)
        assertEquals(null, XuiDiscoveryConsentPolicy.reject("server-1", "access-1", reviewed,
            current, "root@example.org:22", true))
    }

    @Test fun staleCredentialAndWrongAccessBlockBeforeRemoteWork() {
        val reviewed = summary()
        assertTrue(XuiDiscoveryConsentPolicy.reject("server-1", "access-1", reviewed,
            LocalSshReadinessResult.MetadataPresent(summary("rotated")), "root@example.org:22", true) != null)
        assertTrue(XuiDiscoveryConsentPolicy.reject("server-1", "access-other", reviewed,
            LocalSshReadinessResult.MetadataPresent(reviewed), "root@example.org:22", true) != null)
        assertTrue(XuiDiscoveryConsentPolicy.reject("server-1", "access-1", reviewed,
            LocalSshReadinessResult.Blocked("unavailable"), "root@example.org:22", true) != null)
    }

    @Test fun noConsentNeverReadsRepositoryOrOpensNetwork() = runBlocking {
        var reads = 0
        val servers = object : ServerRepository {
            override suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>> { reads++; return RepositoryResult.NotFound }
            override suspend fun list() = RepositoryResult.Success(emptyList<VersionedRecord<Server>>())
            override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("forbidden")
            override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("forbidden")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("forbidden")
        }
        val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> { reads++; return RepositoryResult.NotFound }
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(emptyList<ServerAccess>())
            override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("forbidden")
        }
        var connects = 0
        val transport = object : SshConnectionFactory {
            override suspend fun connect(access: ServerAccess, owner: SessionOwner, config: SshTransportConfig): SshConnectResult {
                connects++
                return SshConnectResult.Failed(SshConnectFailure.AuthenticationRejected)
            }
        }
        val result = RepositoryXuiReadOnlyDiscoveryPort(servers, accesses, transport)
            .inspectExact("server-1", "access-1", summary(), "root@example.org:22", false)
        assertTrue(result is XuiReadOnlyDiscoveryResult.Blocked)
        assertEquals(0, reads)
        assertEquals(0, connects)
    }

    @Test fun screenCannotStartDiscoveryBeforeTargetAndConsent() {
        val local = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary()))
            override suspend fun previewExact(serverId: String, accessId: String) =
                LocalSshReadinessResult.MetadataPresent(summary())
        }
        var attempts = 0
        val network = object : XuiReadOnlyDiscoveryPort {
            override suspend fun inspectExact(serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
                repeatedTarget: String, consent: Boolean): XuiReadOnlyDiscoveryResult {
                attempts++
                return XuiReadOnlyDiscoveryResult.Observation("fixture", "no network")
            }
        }
        compose.setContent { XuiReadOnlyDiscoveryScreen("server-1", "VPS", local, network, {}) }
        compose.waitUntil(8_000) { compose.onAllNodesWithTag("xui_discovery_select_access-1").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("xui_discovery_select_access-1").performScrollTo().performClick()
        compose.waitUntil(8_000) { compose.onAllNodesWithTag("xui_discovery_start").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("xui_discovery_start").assertIsNotEnabled()
        compose.onNodeWithTag("xui_discovery_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_discovery_start").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, attempts) }
    }
}
