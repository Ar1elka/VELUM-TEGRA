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

/** Memory-only real Activity: exact access selection and offline plan, never a host launch. */
@RunWith(AndroidJUnit4::class)
class Phase14_3BExactManagementAccessDraftAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val initial = LocalManagementReview.Ready(
        serverName = "Fixture server", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 2,
        accessIds = listOf("ssh-11", "ssh-22"),
    )

    private fun awaitAccess(tag: String) {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test fun explicitExactAccessChoiceAndFreshRereadRequiredForOfflinePlan() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { server, installation ->
            assertEquals("server-7", server)
            assertEquals("install-7", installation)
            reads.incrementAndGet()
            initial
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        awaitAccess("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_access_ssh-22").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitAccess("management_quick_preview_ready")
        compose.onNodeWithTag("management_quick_preview_access").assertTextContains("ssh-22", substring = true)
        compose.onNodeWithTag("management_review_offline").assertExists()
        assertEquals(2, reads.get())
    }

    @Test fun changedLocalBindingBlocksStaleOfflinePreview() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() == 1) initial else initial.copy(
                managementBindings = 1, accessIds = listOf("ssh-33"),
            )
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        awaitAccess("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitAccess("management_quick_preview_blocked")
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_access_ssh-33").assertExists()
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        assertEquals(2, reads.get())
    }

    @Test fun latePreviewForPriorAccessCannotOverwriteNewSelection() {
        val delayed = CompletableDeferred<LocalManagementReview>()
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() == 2) withContext(NonCancellable) { delayed.await() }
            else initial
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        awaitAccess("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        compose.waitUntil(5_000) { reads.get() == 2 }
        compose.onNodeWithTag("management_quick_access_ssh-22").performClick()
        delayed.complete(initial)
        compose.waitForIdle()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_access_ssh-22").assertTextContains("Выбран: ssh-22", substring = true)
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitAccess("management_quick_preview_ready")
        compose.onNodeWithTag("management_quick_preview_access").assertTextContains("ssh-22", substring = true)
        assertEquals(3, reads.get())
    }

    @Test fun backgroundStopRevokesOfflineAccessSelectionAndPreview() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ -> reads.incrementAndGet(); initial }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        awaitAccess("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitAccess("management_quick_preview_ready")
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(5_000) { reads.get() == 3 }
        awaitAccess("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_button").assertIsNotEnabled()
        assertEquals(3, reads.get())
    }
}
