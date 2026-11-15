package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.inventory.LocalServerCardActions
import com.velumtegra.xuimobile.inventory.ServerCardActionResult
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** User-facing local CRUD of server cards. No SSH or VPS mutation. */
@RunWith(AndroidJUnit4::class)
class Phase15_1AServerCardActionsAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    private fun awaitTag(tag: String) = compose.waitUntil(8_000) {
        compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
    }

    @Test fun renameAndDeleteEmptyCardFromRealServerTabWithoutAppDataReset() {
        val application = ApplicationProvider.getApplicationContext<VelumTegraApplication>()
        val repo = application.inventoryServerRepository
        val id = ServerId("phase15-user-card-" + UUID.randomUUID())
        val original = "Проверка VPS " + id.value.takeLast(6)
        val renamed = "Переименован " + id.value.takeLast(6)
        runBlocking { assertTrue(repo.create(Server(id, original, Instant.now())) is RepositoryResult.Success) }
        try {
            compose.onNodeWithTag("nav_servers").performClick()
            awaitTag("inventory_rename_server_${id.value}")
            // The server list is vertically scrollable. Target buttons may be outside
            // the viewport when more per-server actions are added in later phases.
            compose.onNodeWithTag("inventory_rename_server_${id.value}").performScrollTo()
            compose.onNodeWithTag("inventory_rename_server_${id.value}").assertIsDisplayed()
            compose.onNodeWithTag("inventory_rename_server_${id.value}").performClick()
            awaitTag("inventory_rename_input")
            compose.onNodeWithTag("inventory_rename_input").performTextReplacement(renamed)
            compose.onNodeWithTag("inventory_rename_confirm").performClick()
            compose.waitUntil(8_000) {
                runBlocking { (repo.get(id) as? RepositoryResult.Success)?.value?.value?.displayName == renamed }
            }
            // Persisted rename can be visible before the Compose action coroutine
            // clears actionBusy and refreshes the card. Wait for the *rendered*
            // renamed card and its enabled delete action, not merely the tag.
            val deleteTag = "inventory_delete_server_${id.value}"
            compose.waitUntil(15_000) {
                val renamedIsRendered = compose.onAllNodesWithText(
                    renamed, useUnmergedTree = true,
                ).fetchSemanticsNodes().isNotEmpty()
                val deleteIsEnabled = compose.onAllNodesWithTag(
                    deleteTag, useUnmergedTree = true,
                ).fetchSemanticsNodes().any { node ->
                    !node.config.contains(SemanticsProperties.Disabled)
                }
                renamedIsRendered && deleteIsEnabled
            }
            // The Phase 15.5 discovery button increased card height and can put
            // "Delete" below the visible viewport. A semantics node being enabled
            // does not mean a screen-coordinate click will reach it.
            compose.onNodeWithTag(deleteTag).performScrollTo()
            compose.onNodeWithTag(deleteTag).assertIsDisplayed()
            compose.onNodeWithTag(deleteTag).performClick()
            awaitTag("inventory_delete_confirm")
            compose.onNodeWithTag("inventory_delete_confirm").performClick()
            compose.waitUntil(8_000) { runBlocking { repo.get(id) is RepositoryResult.NotFound } }
        } finally {
            // Clean only this unique fixture; never clear app database or touch other servers.
            runBlocking { val left = repo.get(id); if (left is RepositoryResult.Success) repo.delete(id, left.value.revision) }
        }
    }

    @Test fun staleCardNameNeverRenamesOrDeletesAnotherRevision() = runBlocking {
        val id = ServerId("fixture-15-a")
        val fake = FakeServers(Server(id, "Updated by another action", Instant.EPOCH))
        val actions = LocalServerCardActions(fake, EmptyAccess(), EmptyXui())
        assertTrue(actions.rename(id.value, "Old screen label", "new") is ServerCardActionResult.Blocked)
        assertTrue(actions.deleteEmpty(id.value, "Old screen label") is ServerCardActionResult.Blocked)
        assertEquals(0, fake.writes)
    }

    @Test fun deleteBlockedWhenLinkedDataExists() = runBlocking {
        val id = ServerId("fixture-15-b")
        val fake = FakeServers(Server(id, "Linked", Instant.EPOCH))
        val actions = LocalServerCardActions(fake, UnknownAccess(), EmptyXui())
        assertTrue(actions.deleteEmpty(id.value, "Linked") is ServerCardActionResult.Blocked)
        assertEquals(0, fake.writes)
    }

    @Test fun rejectInvalidRenameBeforePersistence() = runBlocking {
        val id = ServerId("fixture-15-c")
        val fake = FakeServers(Server(id, "Original", Instant.EPOCH))
        val actions = LocalServerCardActions(fake, EmptyAccess(), EmptyXui())
        assertTrue(actions.rename(id.value, "Original", " ") is ServerCardActionResult.Blocked)
        assertTrue(actions.rename(id.value, "Original", "x".repeat(81)) is ServerCardActionResult.Blocked)
        assertEquals(0, fake.writes)
    }

    private class FakeServers(var item: Server) : ServerRepository {
        var writes = 0
        override suspend fun get(serverId: ServerId) = if (serverId == item.id) RepositoryResult.Success(VersionedRecord(item, RecordRevision(0))) else RepositoryResult.NotFound
        override suspend fun list() = RepositoryResult.Success(listOf(VersionedRecord(item, RecordRevision(0))))
        override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("not expected")
        override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> { writes++; item = server; return RepositoryResult.Success(RecordRevision(1)) }
        override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> { writes++; return RepositoryResult.Success(Unit) }
    }
    private open class EmptyAccess : ServerAccessRepository {
        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> = RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = RepositoryResult.Success(emptyList())
        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = RepositoryResult.NotFound
    }
    private class UnknownAccess : EmptyAccess() {
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = RepositoryResult.StorageFailure("unavailable")
    }
    private class EmptyXui : XuiInstallationRepository {
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> = RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = RepositoryResult.Success(emptyList())
        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("not expected")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("not expected")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("not expected")
    }
}
