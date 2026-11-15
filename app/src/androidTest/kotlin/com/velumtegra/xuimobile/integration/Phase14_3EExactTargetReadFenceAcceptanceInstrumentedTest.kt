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

/** Memory-only, no SSH, secrets or persistence: reject foreign identities at every UI read. */
@RunWith(AndroidJUnit4::class)
class Phase14_3EExactTargetReadFenceAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val target = LocalManagementReview.Ready(
        serverName = "Target server", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 1, accessIds = listOf("ssh-11"),
    )

    private fun awaitTag(tag: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    }

    private fun assertNoTargetOrForeignUi() {
        compose.onNodeWithTag("management_review_exact_server").assertDoesNotExist()
        compose.onNodeWithTag("management_review_exact_installation").assertDoesNotExist()
        compose.onNodeWithTag("management_review_panel_port").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_access_ssh-11").assertDoesNotExist()
        compose.onNodeWithTag("management_quick_preview_ready").assertDoesNotExist()
    }

    @Test fun foreignServerFromInitialReadCannotPopulateManagementUi() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            reads.incrementAndGet()
            target.copy(serverName = "Foreign server", serverId = "server-8")
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_review_unavailable")
        compose.onNodeWithTag("management_review_unavailable")
            .assertTextContains("не соответствуют", substring = true)
        assertNoTargetOrForeignUi()
        assertEquals(1, reads.get())
    }

    @Test fun foreignInstallationFromInitialReadCannotPopulateManagementUi() {
        val port = ManagementLocalReviewPort { _, _ ->
            target.copy(installationId = "install-8", panelPort = 9999)
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_review_unavailable")
        compose.onNodeWithTag("management_review_unavailable")
            .assertTextContains("не соответствуют", substring = true)
        assertNoTargetOrForeignUi()
    }

    @Test fun foreignInstallationFromManualRefreshRevokesVisiblePlan() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() <= 2) target else target.copy(installationId = "install-8")
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitTag("management_quick_preview_ready")
        compose.onNodeWithTag("management_review_refresh").performClick()
        awaitTag("management_review_unavailable")
        assertNoTargetOrForeignUi()
        assertEquals(3, reads.get())
    }

    @Test fun foreignServerFromPreviewRereadCannotReplaceTargetReview() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (reads.incrementAndGet() == 1) target else target.copy(serverId = "server-8")
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, {}) }
        awaitTag("management_quick_access_ssh-11")
        compose.onNodeWithTag("management_quick_access_ssh-11").performClick()
        compose.onNodeWithTag("management_quick_preview_button").performClick()
        awaitTag("management_review_unavailable")
        assertNoTargetOrForeignUi()
        assertEquals(2, reads.get())
    }
}
