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
import com.velumtegra.xuimobile.management.isSafeLocalPanelPath
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Path trust boundary tested with offline alternate local port; no network or storage. */
@RunWith(AndroidJUnit4::class)
class Phase14_3KLocalPanelPathFenceAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val valid = LocalManagementReview.Ready(
        serverName = "Fixture", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 1, accessIds = listOf("ssh-11"),
    )
    private fun awaitTag(tag: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    }
    private fun assertBlocked() {
        awaitTag("management_review_unavailable")
        compose.onNodeWithTag("management_review_unavailable")
            .assertTextContains("Локальные параметры", substring = true)
        compose.onNodeWithTag("management_review_panel_port").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_draft_card").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
    }
    @Test fun doubleSlashAuthorityCannotAppearAsTrustedPanelPath() {
        assertFalse(isSafeLocalPanelPath("//foreign.example/panel"))
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", ManagementLocalReviewPort { _, _ -> valid.copy(webBasePath = "//foreign.example/panel") }, {}) }
        assertBlocked()
    }
    @Test fun traversalAndEncodedSegmentsAreRejectedBeforeOfflinePlan() {
        listOf("/panel/../admin", "/./panel", "/panel/%2e%2e/", "/panel\\admin", "/panel?token=x", "/panel#frag").forEach { assertFalse(it, isSafeLocalPanelPath(it)) }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", ManagementLocalReviewPort { _, _ -> valid.copy(webBasePath = "/panel/../admin") }, {}) }
        assertBlocked()
    }
    @Test fun malformedPathOnPreviewRereadRevokesSelectionAndPlan() {
        val reads = AtomicInteger()
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() == 1) valid else valid.copy(webBasePath = "//foreign.example/panel")
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        assertBlocked()
        assertEquals(2, reads.get())
    }
    @Test fun ordinaryAbsolutePathRemainsReadOnlyAndSelectable() {
        assertTrue(isSafeLocalPanelPath("/panel/v1"))
        assertTrue(isSafeLocalPanelPath("/"))
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", ManagementLocalReviewPort { _, _ -> valid.copy(webBasePath = "/panel/v1") }, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_review_panel_port").assertTextContains("2053", substring = true)
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitTag("management_quick_preview_ready")
    }
}
