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

/** Memory-only local metadata trust-boundary tests: no SSH, secret or durable writes. */
@RunWith(AndroidJUnit4::class)
class Phase14_3GLocalMetadataFenceAcceptanceInstrumentedTest {
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

    private fun assertUnavailableWithoutMetadataOrPlan() {
        awaitTag("management_review_unavailable")
        compose.onNodeWithTag("management_review_unavailable")
            .assertTextContains("Локальные параметры", substring = true)
        compose.onNodeWithTag("management_review_panel_port").assertDoesNotExist()
        compose.onNodeWithTag("management_review_exact_server").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_draft_card").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
    }

    @Test fun invalidPanelPortCannotAppearAsSavedLocalFact() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(panelPort = 0) }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun blankServiceUnitCannotAppearAsSavedLocalFact() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(serviceUnit = " ") }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun relativeWebBasePathCannotAppearAsSavedLocalFact() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(webBasePath = "panel") }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun unrecognizedOwnershipCannotAppearAsSavedLocalFact() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(ownership = "UNKNOWN") }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun negativeBindingCountCannotAppearForMetadataOnlyReady() {
        val port = ManagementLocalReviewPort { _, _ -> valid.copy(managementBindings = -1, accessIds = emptyList()) }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        assertUnavailableWithoutMetadataOrPlan()
    }

    @Test fun malformedMetadataOnPreviewRereadRevokesExactAccessAndPlan() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() == 1) valid else valid.copy(panelPort = 0)
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        assertUnavailableWithoutMetadataOrPlan()
        assertEquals(2, reads.get())
    }
}
