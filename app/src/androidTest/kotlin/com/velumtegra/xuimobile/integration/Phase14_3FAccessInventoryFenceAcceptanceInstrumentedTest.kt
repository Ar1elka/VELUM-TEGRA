package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.management.LocalManagementReview
import com.velumtegra.xuimobile.management.ManagementLocalReviewPort
import com.velumtegra.xuimobile.management.ManagementLocalReviewScreen
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Memory-only fail-closed review of malformed SSH access inventories; never executes SSH. */
@RunWith(AndroidJUnit4::class)
class Phase14_3FAccessInventoryFenceAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val valid = LocalManagementReview.Ready(
        serverName = "Fixture server", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 2,
        accessIds = listOf("ssh-11", "ssh-22"),
    )

    private fun awaitTag(tag: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    }

    private fun assertUnavailableAndNoAccessChoices() {
        awaitTag("management_review_unavailable")
        compose.onNodeWithTag("management_review_unavailable")
            .assertTextContains("SSH-доступов", substring = true)
        compose.onNodeWithTag("management_review_exact_server").assertDoesNotExist()
        compose.onNodeWithTag("management_review_panel_port").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_draft_card").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
    }

    @Test fun duplicateAccessIdsFromLocalPortCannotBeSelected() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(accessIds = listOf("ssh-11", "ssh-11")) }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableAndNoAccessChoices()
    }

    @Test fun blankAccessIdFromLocalPortCannotBeSelected() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(accessIds = listOf("ssh-11", "  ")) }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableAndNoAccessChoices()
    }

    @Test fun bindingCountMismatchCannotProducePartiallyTrustedAccessList() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(managementBindings = 1) }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableAndNoAccessChoices()
    }

    @Test fun invalidInventoryOnPreviewRereadRevokesSelectionAndPlan() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() == 1) valid else valid.copy(accessIds = listOf("ssh-11", "ssh-11"))
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        assertUnavailableAndNoAccessChoices()
        assertEquals(2, reads.get())
    }
}
