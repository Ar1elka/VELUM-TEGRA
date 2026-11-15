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

/** Pure offline fixture: fake metadata repository; no SSH transport, Keystore or persistent writes. */
@RunWith(AndroidJUnit4::class)
class Phase14_2FOfflineSshHandoffAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val summary = LocalSshAccessSummary("access-7", "node.example", 22,
        "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43))

    private fun armConsent() {
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
        compose.onNodeWithTag("ssh_consent_target").performScrollTo().performTextInput("operator@node.example:22")
        compose.onNodeWithTag("ssh_consent_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_arm").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_armed").assertExists()
    }

    @Test fun offlineHandoffConsumesSingleConsentAndGrantsNoNetworkAccess() {
        var reads = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                assertEquals("server-7", serverId)
                assertEquals("access-7", accessId)
                reads++
                return LocalSshReadinessResult.MetadataPresent(summary)
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        armConsent()
        compose.onNodeWithTag("ssh_handoff_inspect").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_handoff_inspected").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspect").fetchSemanticsNodes().size)
        assertEquals(4, reads)
    }

    @Test fun changedPinOnFreshReadBlocksHandoff() {
        var reads = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                reads++
                return LocalSshReadinessResult.MetadataPresent(
                    if (reads < 4) summary else summary.copy(savedFingerprint = "SHA256:" + "B".repeat(43)),
                )
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        armConsent()
        compose.onNodeWithTag("ssh_handoff_inspect").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_handoff_blocked").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspected").fetchSemanticsNodes().size)
        assertEquals(4, reads)
    }

    @Test fun cancelledOfflineConsentCannotBeInspected() {
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String) = LocalSshReadinessResult.MetadataPresent(summary)
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        armConsent()
        compose.onNodeWithTag("ssh_handoff_cancel").performScrollTo().performClick()
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspect").fetchSemanticsNodes().size)
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspected").fetchSemanticsNodes().size)
    }
}
