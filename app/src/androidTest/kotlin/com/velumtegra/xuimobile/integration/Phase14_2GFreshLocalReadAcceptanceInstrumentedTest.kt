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

/** Phase14.2G UI fixture: only fake local repository metadata, never a transport/secret store. */
@RunWith(AndroidJUnit4::class)
class Phase14_2GFreshLocalReadAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val summary = LocalSshAccessSummary("access-7", "node.example", 22,
        "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43))

    private fun reachHandoff() {
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

    @Test fun localPortReadFailureDuringHandoffConsumesReceiptAndBlocks() {
        var reads = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                reads++
                if (reads == 4) throw IllegalStateException("fixture local read unavailable")
                return LocalSshReadinessResult.MetadataPresent(summary)
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        reachHandoff()
        compose.onNodeWithTag("ssh_handoff_inspect").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_handoff_blocked").assertExists()
        assertEquals(4, reads)
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspect").fetchSemanticsNodes().size)
    }

    @Test fun changedAuthenticationOnFreshHandoffReadBlocks() {
        var reads = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                reads++
                val metadata = if (reads == 4) summary.copy(authLabel = "Приватный ключ (ссылка на секрет)") else summary
                return LocalSshReadinessResult.MetadataPresent(metadata)
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack = {}) }
        reachHandoff()
        compose.onNodeWithTag("ssh_handoff_inspect").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_handoff_blocked").assertExists()
        assertEquals(4, reads)
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspected").fetchSemanticsNodes().size)
    }
}
