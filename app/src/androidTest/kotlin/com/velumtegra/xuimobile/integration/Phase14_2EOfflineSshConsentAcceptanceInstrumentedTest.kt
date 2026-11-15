package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import com.velumtegra.xuimobile.readiness.SshReadinessScreen
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Offline Compose fixtures. No sockets, Keystore, secrets or persistent writes. */
@RunWith(AndroidJUnit4::class)
class Phase14_2EOfflineSshConsentAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val saved = LocalSshAccessSummary("access-7", "node.example", 22,
        "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43))

    private fun completeDraft() {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_target").performScrollTo().performTextInput("operator@node.example:22")
        compose.onNodeWithTag("ssh_draft_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepared").assertExists()
    }

    @Test fun oneShotOfflineConsentRehearsalCannotExecuteSsh() {
        var reads = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(saved))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                assertEquals("server-7", serverId)
                assertEquals("access-7", accessId)
                reads++
                return LocalSshReadinessResult.MetadataPresent(saved)
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        completeDraft()
        compose.onNodeWithTag("ssh_consent_target").performScrollTo().performTextInput("operator@node.example:22")
        compose.onNodeWithTag("ssh_consent_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_arm").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_armed").assertExists()
        compose.onNodeWithTag("ssh_consent_simulate").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_simulated").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_consent_simulate").fetchSemanticsNodes().size)
        assertEquals(4, reads) // preview, draft fresh-read, arm fresh-read, simulate fresh-read
    }

    @Test fun changedPinBeforeOneShotUseFailsClosed() {
        var reads = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(saved))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                reads++
                return LocalSshReadinessResult.MetadataPresent(
                    if (reads < 4) saved else saved.copy(savedFingerprint = "SHA256:" + "B".repeat(43)))
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        completeDraft()
        compose.onNodeWithTag("ssh_consent_target").performScrollTo().performTextInput("operator@node.example:22")
        compose.onNodeWithTag("ssh_consent_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_arm").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_armed").assertExists()
        compose.onNodeWithTag("ssh_consent_simulate").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_blocked").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_consent_simulated").fetchSemanticsNodes().size)
        assertEquals(4, reads)
    }
}
