package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import com.velumtegra.xuimobile.readiness.SshReadinessScreen
import kotlinx.coroutines.CompletableDeferred
import org.junit.Assert.assertEquals
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real Activity lifecycle, fake in-memory metadata; no SSH/network/secret store/persistence. */
@RunWith(AndroidJUnit4::class)
class Phase14_2ILifecycleRevocationAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val summary = LocalSshAccessSummary("access-7", "node.example", 22,
        "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43), "digest-a")
    private val target = "operator@node.example:22"

    private fun fake(): SshReadinessPort = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
        override suspend fun previewExact(serverId: String, accessId: String) =
            LocalSshReadinessResult.MetadataPresent(summary)
    }

    private fun chooseAndReview() {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertExists()
    }

    private fun armConsent() {
        chooseAndReview()
        compose.onNodeWithTag("ssh_draft_target").performScrollTo().performTextInput(target)
        compose.onNodeWithTag("ssh_draft_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepared").assertExists()
        compose.onNodeWithTag("ssh_consent_target").performScrollTo().performTextInput(target)
        compose.onNodeWithTag("ssh_consent_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_arm").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_armed").assertExists()
    }

    @Test fun backgroundStopRevokesConsentAndRequiresFreshReviewOnResume() {
        val port = fake()
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        armConsent()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitForIdle()
        compose.onNodeWithTag("ssh_consent_armed").assertDoesNotExist()
        compose.onNodeWithTag("ssh_handoff_inspect").assertDoesNotExist()
        compose.onNodeWithTag("ssh_draft_prepared").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertDoesNotExist()
        // Phase14.2J now clears the previous access choice on STOP and rereads the exact local
        // access list on START. The old acknowledgement must be absent until a fresh selection.
        compose.onNodeWithTag("ssh_readiness_exact_access").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_acknowledge").assertDoesNotExist()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").assertIsOff()
    }

    @Test fun oldInFlightConsentReadCannotArmAfterStopAndResume() {
        val pending = CompletableDeferred<LocalSshReadinessResult>()
        val reads = AtomicInteger(0)
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                return if (reads.incrementAndGet() == 3) pending.await() else LocalSshReadinessResult.MetadataPresent(summary)
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        chooseAndReview()
        compose.onNodeWithTag("ssh_draft_target").performScrollTo().performTextInput(target)
        compose.onNodeWithTag("ssh_draft_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepared").assertExists()
        compose.onNodeWithTag("ssh_consent_target").performScrollTo().performTextInput(target)
        compose.onNodeWithTag("ssh_consent_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_arm").performScrollTo().performClick()
        compose.waitUntil(5_000) { reads.get() == 3 }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        pending.complete(LocalSshReadinessResult.MetadataPresent(summary))
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitForIdle()
        compose.onNodeWithTag("ssh_consent_armed").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertDoesNotExist()
        assertEquals(3, reads.get())
    }

    @Test fun changingRepositoryPortDropsStaleReviewedStateAndConsent() {
        val original = fake()
        val replacement = fake()
        var activePort by mutableStateOf<SshReadinessPort>(original)
        compose.setContent { SshReadinessScreen("server-7", "Fixture", activePort, onBack = {}) }
        armConsent()
        compose.runOnUiThread { activePort = replacement }
        compose.waitForIdle()
        compose.onNodeWithTag("ssh_consent_armed").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_exact_access").assertDoesNotExist()
        compose.onNodeWithTag("ssh_readiness_choose_access-7").assertExists()
    }
}
