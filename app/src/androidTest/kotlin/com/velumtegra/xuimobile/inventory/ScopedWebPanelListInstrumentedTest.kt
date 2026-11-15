package com.velumtegra.xuimobile.inventory

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real [InventoryScreen] in scoped Web Panel mode over in-memory fake repositories.
 * No network, no SSH, no credentials, no SecretStore, no Room and no real addresses.
 */
@RunWith(AndroidJUnit4::class)
class ScopedWebPanelListInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val serverA = ServerId("fixture-server-a")
    private val serverB = ServerId("fixture-server-b")
    private val installA = XuiInstallationId("fixture-install-a")
    private val installB = XuiInstallationId("fixture-install-b")
    private val rev = RecordRevision(1)

    private fun installation(id: XuiInstallationId, server: ServerId, managed: String) = XuiInstallation(
        id = id, serverId = server, ownership = InstallationOwnership.MANAGED,
        identity = InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui",
            "/etc/x-ui/x-ui.db", ManagedInstallId(managed)),
        baseline = InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui",
            "/etc/x-ui/x-ui.db", 2053, "/fixture/", null, Instant.EPOCH),
    )

    private fun panel(id: String, user: String, link: WebPanelInstallationLink) = WebPanelAccess(
        id = WebPanelAccessId(id), installationLink = link, username = user,
        passwordSecretId = SecretId("fixture-secret-$id"), route = WebPanelRoute.Direct("panel.fixture.invalid"),
    )

    private val servers = listOf(serverA, serverB).map {
        VersionedRecord(Server(it, "Fixture ${it.value}", Instant.EPOCH), rev)
    }
    private val installations = listOf(
        VersionedRecord(installation(installA, serverA, "a"), rev),
        VersionedRecord(installation(installB, serverB, "b"), rev),
    )
    private val panels = linkedMapOf(
        "wp-a" to panel("wp-a", "alice", WebPanelInstallationLink.Linked(installA)),
        "wp-b" to panel("wp-b", "bob", WebPanelInstallationLink.Linked(installB)),
        "wp-s" to panel("wp-s", "carol", WebPanelInstallationLink.Standalone),
    )

    private val serverRepo = object : ServerRepository {
        override suspend fun get(serverId: ServerId) =
            servers.firstOrNull { it.value.id == serverId }?.let { RepositoryResult.Success(it) } ?: RepositoryResult.NotFound
        override suspend fun list() = RepositoryResult.Success(servers)
        override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("read-only fixture")
        override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("read-only fixture")
        override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("read-only fixture")
    }
    private val accessRepo = object : ServerAccessRepository {
        override suspend fun get(serverAccessId: ServerAccessId) = RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(emptyList<ServerAccess>())
        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("read-only fixture")
    }
    private val installRepo = object : XuiInstallationRepository {
        override suspend fun get(installationId: XuiInstallationId) =
            installations.firstOrNull { it.value.id == installationId }?.let { RepositoryResult.Success(it) } ?: RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) =
            RepositoryResult.Success(installations.filter { it.value.serverId == serverId })
        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("read-only fixture")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("read-only fixture")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("read-only fixture")
    }
    private val managementRepo = object : ManagementAccessRepository {
        override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = RepositoryResult.NotFound
        override suspend fun listForInstallation(installationId: XuiInstallationId) = RepositoryResult.Success(emptyList<ManagementAccess>())
        override suspend fun listForServerAccess(serverAccessId: ServerAccessId) = RepositoryResult.Success(emptyList<ManagementAccess>())
        override suspend fun create(access: ManagementAccess): RepositoryResult<Unit> = error("read-only fixture")
        override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("read-only fixture")
    }
    private val panelRepo = object : WebPanelAccessRepository {
        override suspend fun get(webPanelAccessId: WebPanelAccessId) =
            panels[webPanelAccessId.value]?.let { RepositoryResult.Success(VersionedRecord(it, rev)) } ?: RepositoryResult.NotFound
        override suspend fun list() = RepositoryResult.Success(panels.values.map { VersionedRecord(it, rev) })
        override suspend fun updateMetadata(access: WebPanelAccess, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("read-only fixture")
        override suspend fun delete(webPanelAccessId: WebPanelAccessId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("read-only fixture")
    }

    private val launched = mutableListOf<String>()
    private var backs = 0

    private fun showScopedList() = compose.setContent {
        InventoryScreen(
            section = InventorySection.WEB_PANEL,
            serverRepository = serverRepo, serverAccessRepository = accessRepo,
            installationRepository = installRepo, managementAccessRepository = managementRepo,
            webPanelAccessRepository = panelRepo,
            onOpenWebPanelInApp = { launched += it },
            webPanelScope = WebPanelInstallationScope(serverA.value, installA.value),
            onBackToManagement = { backs++ },
        )
    }

    private fun AndroidComposeTestRule<*, *>.awaitTag(tag: String) =
        waitUntil(10_000) { onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    @Test fun listShowsOnlySelectedInstallationAndBackIsScopedWithoutLaunch() {
        showScopedList()
        compose.awaitTag("inventory_webpanel_open_saved_wp-a")
        compose.onNodeWithText("Web Panel · alice").assertExists()
        compose.onAllNodesWithText("Web Panel · bob").assertCountEquals0()
        compose.onAllNodesWithText("Web Panel · carol").assertCountEquals0()
        compose.onAllNodesWithTag("inventory_webpanel_open_saved_wp-b").assertCountEquals0()
        compose.onAllNodesWithTag("inventory_webpanel_open_saved_wp-s").assertCountEquals0()
        compose.runOnIdle { assertEquals(0, launched.size) }

        compose.onNodeWithTag("inventory_scoped_back").performScrollTo().performClick()
        compose.runOnIdle {
            assertEquals(1, backs)
            compose.activity.onBackPressedDispatcher.onBackPressed()
        }
        compose.runOnIdle {
            assertEquals(2, backs)
            assertEquals(0, launched.size)
        }
    }

    @Test fun relinkedDirectProfileAfterListLoadIsRefusedWithoutLaunch() {
        showScopedList()
        compose.awaitTag("inventory_webpanel_open_saved_wp-a")
        // The stale card stays on screen while the saved profile is re-linked to the other installation.
        compose.runOnIdle {
            panels["wp-a"] = panel("wp-a", "alice", WebPanelInstallationLink.Linked(installB))
        }
        val open = compose.onNodeWithTag("inventory_webpanel_open_saved_wp-a")
        open.performScrollTo().performClick()
        compose.awaitTag("inventory_saved_panel_open_notice")
        compose.onNodeWithTag("inventory_saved_panel_open_notice").assertTextContains("изменился", substring = true)
        compose.runOnIdle { assertEquals(0, launched.size) }

        // The same card can open when its saved link matches the scope again.
        compose.runOnIdle {
            panels["wp-a"] = panel("wp-a", "alice", WebPanelInstallationLink.Linked(installA))
        }
        open.performScrollTo().performClick()
        compose.waitUntil(10_000) { compose.runOnIdle { launched.isNotEmpty() } }
        compose.runOnIdle {
            assertEquals(listOf("https://panel.fixture.invalid:2053/fixture/"), launched)
        }
    }

    private fun androidx.compose.ui.test.SemanticsNodeInteractionCollection.assertCountEquals0() =
        assertEquals(0, fetchSemanticsNodes().size)
}
