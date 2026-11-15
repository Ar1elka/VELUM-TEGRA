package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.management.LocalManagementReview
import com.velumtegra.xuimobile.management.ManagementLocalReviewPort
import com.velumtegra.xuimobile.management.ManagementLocalReviewScreen
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real Activity with memory-only port; no repository writes, network, SSH or secret reads. */
@RunWith(AndroidJUnit4::class)
class Phase14_3ALocalManagementReviewAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val first = LocalManagementReview.Ready(
        serverName = "Fixture server", serverId = "server-7", installationId = "install-7",
        ownership = "MANAGED", serviceUnit = "x-ui.service", panelPort = 2053,
        webBasePath = "/panel", managementBindings = 1,
    )

    @Test fun exactInstallationLocalDetailsAreVisibleWithoutRemoteStatusClaim() {
        val reads = AtomicInteger(0)
        val port = ManagementLocalReviewPort { server, installation ->
            assertEquals("server-7", server)
            assertEquals("install-7", installation)
            reads.incrementAndGet()
            first
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("management_review_exact_installation").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("management_review_exact_server").assertTextContains("server-7", substring = true)
        compose.onNodeWithTag("management_review_exact_installation").assertTextContains("install-7", substring = true)
        compose.onNodeWithTag("management_review_bindings").assertTextContains("1", substring = true)
        compose.onNodeWithTag("management_review_offline").assertExists()
        assertEquals(1, reads.get())
    }

    @Test fun delayedOldLocalReadCannotOverwriteFreshForegroundTargetDetails() {
        val previous = CompletableDeferred<LocalManagementReview>()
        val calls = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ ->
            if (calls.incrementAndGet() == 1) {
                withContext(NonCancellable) { previous.await() }
            } else {
                first.copy(panelPort = 2087)
            }
        }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        compose.waitUntil(5_000) { calls.get() == 1 }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("management_review_exact_installation").fetchSemanticsNodes().isNotEmpty()
        }
        previous.complete(first.copy(panelPort = 9999))
        compose.waitForIdle()
        compose.onNodeWithTag("management_review_exact_installation").assertTextContains("install-7", substring = true)
        compose.onNodeWithTag("management_review_panel_port").assertTextContains("2087", substring = true)
        compose.onNodeWithTag("management_review_offline").assertExists()
        assertEquals(2, calls.get())
    }

    @Test fun unavailableForegroundReadClearsPreviousInstallationDetails() {
        val response = AtomicReference<LocalManagementReview>(first)
        val calls = AtomicInteger(0)
        val port = ManagementLocalReviewPort { _, _ -> calls.incrementAndGet(); response.get() }
        compose.setContent { ManagementLocalReviewScreen("server-7", "install-7", port, onBack = {}) }
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("management_review_exact_installation").fetchSemanticsNodes().isNotEmpty()
        }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        response.set(LocalManagementReview.Unavailable("Удалено из локальной базы"))
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("management_review_unavailable").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("management_review_exact_installation").assertDoesNotExist()
        compose.onNodeWithTag("management_review_unavailable").assertTextContains("Удалено", substring = true)
        assertEquals(2, calls.get())
    }
}
