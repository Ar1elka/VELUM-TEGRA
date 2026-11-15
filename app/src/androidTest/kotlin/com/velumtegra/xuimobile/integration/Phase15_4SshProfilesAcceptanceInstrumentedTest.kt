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
import com.velumtegra.xuimobile.profiles.*
import com.velumtegra.xuimobile.readiness.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase15_4SshProfilesAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val pin = "SHA256:" + "A".repeat(43)
    private fun metadata(id: String = "access-1", digest: String = "hash") = LocalSshAccessSummary(
        id, "example.org", 22, "root", "Пароль", pin, digest,
    )
    private fun review(id: String = "access-1", count: Int = 0, digest: String = "hash") =
        SshProfileReview("server-1", metadata(id, digest), count, 0)

    @Test fun deletionRequiresExactTargetAndExplicitConsent() {
        val fixed = review()
        val present = SshProfileReviewResult.Ready(fixed)
        assertTrue(SshProfileDeletionPolicy.reject("server-1", "access-1", fixed, present, "root@example.org:22", false) != null)
        assertTrue(SshProfileDeletionPolicy.reject("server-1", "access-1", fixed, present, "root@wrong.example:22", true) != null)
        assertEquals(null, SshProfileDeletionPolicy.reject("server-1", "access-1", fixed, present, "root@example.org:22", true))
    }

    @Test fun staleCredentialsAndAddedLinksRevokeDeletionConsent() {
        val fixed = review()
        assertTrue(SshProfileDeletionPolicy.reject("server-1", "access-1", fixed,
            SshProfileReviewResult.Ready(review(digest = "rotated")), "root@example.org:22", true) != null)
        assertTrue(SshProfileDeletionPolicy.reject("server-1", "access-1", fixed,
            SshProfileReviewResult.Ready(review(count = 1)), "root@example.org:22", true) != null)
        assertTrue(SshProfileDeletionPolicy.reject("server-2", "access-1", fixed,
            SshProfileReviewResult.Ready(fixed), "root@example.org:22", true) != null)
    }

    @Test fun linkedProfileCannotCallCredentialDeletionGateway() = runBlocking {
        val server = Server(ServerId("server-1"), "VPS", Instant.EPOCH)
        val access = ServerAccess(ServerAccessId("access-1"), server.id, SshEndpoint("example.org", 22),
            "root", SshAuthRef.Password(SecretId("secret-1")), HostKeyFingerprint(pin))
        val servers = object : ServerRepository {
            override suspend fun get(serverId: ServerId) = RepositoryResult.Success(VersionedRecord(server, RecordRevision(0)))
            override suspend fun list() = RepositoryResult.Success(listOf(VersionedRecord(server, RecordRevision(0))))
            override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("creation forbidden")
            override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("update forbidden")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("delete forbidden")
        }
        val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId) = RepositoryResult.Success(access)
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(access))
            override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("transaction gateway required")
        }
        val management = object : ManagementAccessRepository {
            override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<ManagementAccess> = RepositoryResult.NotFound
            override suspend fun listForInstallation(installationId: XuiInstallationId) = RepositoryResult.Success(emptyList<ManagementAccess>())
            override suspend fun listForServerAccess(serverAccessId: ServerAccessId) = RepositoryResult.Success(
                listOf(ManagementAccess(XuiInstallationId("xui-1"), access.id)))
            override suspend fun create(access: ManagementAccess): RepositoryResult<Unit> = error("create forbidden")
            override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("delete forbidden")
        }
        val panels = object : WebPanelAccessRepository {
            override suspend fun get(webPanelAccessId: WebPanelAccessId): RepositoryResult<VersionedRecord<WebPanelAccess>> = RepositoryResult.NotFound
            override suspend fun list() = RepositoryResult.Success(emptyList<VersionedRecord<WebPanelAccess>>())
            override suspend fun updateMetadata(access: WebPanelAccess, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("update forbidden")
            override suspend fun delete(webPanelAccessId: WebPanelAccessId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("delete forbidden")
        }
        var writes = 0
        val port = RepositorySshProfileManagementPort(servers, accesses, management, panels) { _ ->
            writes++
            CredentialTransactionResult.Success(Unit)
        }
        val outcome = port.reviewExact("server-1", "access-1")
        assertTrue(outcome is SshProfileReviewResult.Ready)
        val current = (outcome as SshProfileReviewResult.Ready).review
        assertEquals(1, current.managementLinks)
        assertTrue(port.deleteUnused("server-1", "access-1", current, "root@example.org:22", true) is SshProfileDeleteResult.Blocked)
        assertEquals(0, writes)
    }

    @Test fun screenNeverDeletesBeforeExactConsent() {
        val summary = metadata()
        val local = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String) = LocalSshReadinessResult.MetadataPresent(summary)
        }
        var deletes = 0
        val port = object : SshProfileManagementPort {
            override suspend fun reviewExact(serverId: String, accessId: String) = SshProfileReviewResult.Ready(review())
            override suspend fun deleteUnused(serverId: String, accessId: String, reviewed: SshProfileReview,
                repeatedTarget: String, explicitConsent: Boolean): SshProfileDeleteResult {
                deletes++
                return SshProfileDeleteResult.Removed
            }
        }
        compose.setContent { SshProfileManagementScreen("server-1", "VPS", local, port, {}, {}) }
        compose.waitUntil(8_000) { compose.onAllNodesWithTag("ssh_profiles_select_access-1").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("ssh_profiles_select_access-1").performScrollTo().performClick()
        compose.waitUntil(8_000) { compose.onAllNodesWithTag("ssh_profiles_target").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("ssh_profiles_delete").assertIsNotEnabled()
        compose.onNodeWithTag("ssh_profiles_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("ssh_profiles_delete").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, deletes) }
    }
}
