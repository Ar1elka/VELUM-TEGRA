package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.management.LocalManagementReview
import com.velumtegra.xuimobile.management.ManagementLocalReviewPort
import com.velumtegra.xuimobile.management.ManagementLocalReviewScreen
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** UI-only local refresh, with no SecretStore, SSH or persistence writes. */
@RunWith(AndroidJUnit4::class)
class Phase14_3CManagementLocalRefreshAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val initial = LocalManagementReview.Ready(
        serverName = "Fixture", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 1, accessIds = listOf("ssh-11"),
    )
    private val updated = initial.copy(
        panelPort = 3077, managementBindings = 1, accessIds = listOf("ssh-33"),
    )

    private fun awaitTag(tag: String) {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
        }
    }
    private fun awaitPanelPort(port: Int) {
        compose.waitUntil(5_000) {
            runCatching {
                compose.onNodeWithTag("management_review_panel_port")
                    .assertTextContains(port.toString(), substring = true)
                true
            }.getOrDefault(false)
        }
    }

    @Test fun manualRefreshRevokesReadyPlanAndReadsChangedLocalInstallation() {
        val count = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (count.incrementAndGet() < 3) initial else updated
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitTag("management_quick_preview_ready")
        compose.onNodeWithTag("management_review_refresh").performClick()
        awaitPanelPort(3077)
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_access_ssh-11").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_access_ssh-33").assertExists()
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        assertEquals(3, count.get())
    }

    @Test fun retryAfterUnavailableLocalReadRecoversWithoutNavigation() {
        val count = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (count.incrementAndGet() == 1) LocalManagementReview.Unavailable("Локальная запись временно недоступна")
            else initial
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_review_unavailable")
        compose.onNodeWithTag("management_review_refresh").performClick()
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_review_unavailable").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        assertEquals(2, count.get())
    }

    @Test fun lateEarlierRefreshCannotOverwriteNewerExplicitRefresh() {
        val delayed = CompletableDeferred<LocalManagementReview>()
        val count = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            when (count.incrementAndGet()) {
                1 -> initial
                2 -> withContext(NonCancellable) { delayed.await() }
                else -> updated
            }
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_review_refresh").performClick()
        compose.waitUntil(5_000) { count.get() == 2 }
        compose.onNodeWithTag("management_review_refresh").performClick()
        awaitPanelPort(3077)
        delayed.complete(initial)
        compose.waitForIdle()
        compose.onNodeWithTag("management_quick_access_ssh-33").assertExists()
        compose.onNodeWithTag("management_quick_access_ssh-11").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        assertEquals(3, count.get())
    }

    @Test fun lateManualRefreshAfterBackgroundCannotRestoreStaleSelection() {
        val delayed = CompletableDeferred<LocalManagementReview>()
        val count = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            when (count.incrementAndGet()) {
                1 -> initial
                2 -> withContext(NonCancellable) { delayed.await() }
                else -> updated
            }
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_review_refresh").performClick()
        compose.waitUntil(5_000) { count.get() == 2 }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        awaitPanelPort(3077)
        delayed.complete(initial)
        compose.waitForIdle()
        compose.onNodeWithTag("management_quick_access_ssh-33").assertExists()
        compose.onNodeWithTag("management_quick_access_ssh-11").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        assertEquals(3, count.get())
    }
}
