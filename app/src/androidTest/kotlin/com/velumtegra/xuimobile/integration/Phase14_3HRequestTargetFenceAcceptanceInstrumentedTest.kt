package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.management.LocalManagementReview
import com.velumtegra.xuimobile.management.ManagementLocalReviewPort
import com.velumtegra.xuimobile.management.ManagementLocalReviewScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Empty exact-target IDs must never become a trusted Ready from an alternate local port. */
@RunWith(AndroidJUnit4::class)
class Phase14_3HRequestTargetFenceAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val valid = LocalManagementReview.Ready(
        serverName = "Fixture server", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 2,
        accessIds = listOf("ssh-11", "ssh-22"),
    )

    private fun assertUnavailableWithoutMetadataOrPlan() {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("management_review_unavailable").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("management_review_unavailable")
            .assertTextContains("не соответствуют", substring = true)
        compose.onNodeWithTag("management_review_exact_server").assertDoesNotExist()
        compose.onNodeWithTag("management_review_exact_installation").assertDoesNotExist()
        compose.onNodeWithTag("management_review_panel_port").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_draft_card").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
    }

    @Test fun emptyRequestedServerIdCannotExposeMatchingReady() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(serverId = "") }
        compose.setContent { ManagementLocalReviewScreen("", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun whitespaceRequestedServerIdCannotExposeMatchingReady() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(serverId = "   ") }
        compose.setContent { ManagementLocalReviewScreen("   ", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun emptyRequestedInstallationIdCannotExposeMatchingReady() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(installationId = "") }
        compose.setContent { ManagementLocalReviewScreen("server-7", "", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun whitespaceRequestedInstallationIdCannotExposeMatchingReady() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(installationId = "  ") }
        compose.setContent { ManagementLocalReviewScreen("server-7", "  ", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

}
