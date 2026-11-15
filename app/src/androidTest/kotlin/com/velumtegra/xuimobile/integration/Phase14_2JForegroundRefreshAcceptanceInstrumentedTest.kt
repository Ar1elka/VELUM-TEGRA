package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import com.velumtegra.xuimobile.readiness.SshReadinessScreen
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real lifecycle + memory-only fake. Never touches SSH, secrets, networking or persistence. */
@RunWith(AndroidJUnit4::class)
class Phase14_2JForegroundRefreshAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val access7 = LocalSshAccessSummary(
        "access-7", "node.example", 22, "operator", "Пароль (ссылка на секрет)",
        "SHA256:" + "A".repeat(43), "digest-a",
    )
    private val access8 = access7.copy(accessId = "access-8", host = "changed.example")

    private fun chooseAndReview() {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertExists()
    }

    @Test fun foregroundResumeReplacesRemovedAccessAndRequiresReselection() {
        val current = AtomicReference<LocalSshAccessList>(LocalSshAccessList.Available(listOf(access7)))
        val calls = AtomicInteger(0)
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String): LocalSshAccessList {
                calls.incrementAndGet()
                return current.get()
            }
            override suspend fun previewExact(serverId: String, accessId: String) =
                LocalSshReadinessResult.MetadataPresent(access7)
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        chooseAndReview()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        current.set(LocalSshAccessList.Available(listOf(access8)))
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-8").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_exact_access").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertDoesNotExist()
        assertEquals(2, calls.get())
    }

    @Test fun latePreStopListReadCannotReplaceNewForegroundList() {
        val blockedOldList = CompletableDeferred<LocalSshAccessList>()
        val calls = AtomicInteger(0)
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String): LocalSshAccessList =
                if (calls.incrementAndGet() == 1) {
                    // Deliberately ignore coroutine cancellation to exercise the generation fence.
                    withContext(NonCancellable) { blockedOldList.await() }
                } else {
                    LocalSshAccessList.Available(listOf(access8))
                }
            override suspend fun previewExact(serverId: String, accessId: String) =
                LocalSshReadinessResult.MetadataPresent(access8)
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        compose.waitUntil(5_000) { calls.get() == 1 }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-8").fetchSemanticsNodes().isNotEmpty()
        }
        blockedOldList.complete(LocalSshAccessList.Available(listOf(access7)))
        compose.waitForIdle()
        compose.onNodeWithTag("ssh_readiness_choose_access-8").assertExists()
        compose.onNodeWithTag("ssh_readiness_choose_access-7").assertDoesNotExist()
        assertEquals(2, calls.get())
    }

    @Test fun failedForegroundRefreshRemovesOldChoice() {
        val current = AtomicReference<LocalSshAccessList>(LocalSshAccessList.Available(listOf(access7)))
        val calls = AtomicInteger(0)
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String): LocalSshAccessList {
                calls.incrementAndGet()
                return current.get()
            }
            override suspend fun previewExact(serverId: String, accessId: String) =
                LocalSshReadinessResult.MetadataPresent(access7)
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        chooseAndReview()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        current.set(LocalSshAccessList.Unavailable("Локальный список временно недоступен"))
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_load_error").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_exact_access").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertDoesNotExist()
        assertEquals(2, calls.get())
    }
}
