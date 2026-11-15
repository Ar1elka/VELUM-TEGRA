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

/** Test fixtures only. No SSH, secrets, sockets or persistence mutations. */
@RunWith(AndroidJUnit4::class)
class Phase14_2DOfflineSshDraftAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val fixed = LocalSshAccessSummary(
        "access-7", "node.example", 22, "operator", "Пароль (ссылка на секрет)",
        "SHA256:" + "A".repeat(43),
    )

    @Test fun explicitTwoStepOfflineConfirmationPreparesNoNetworkDraft() {
        var calls = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(fixed))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                assertEquals("server-7", serverId)
                assertEquals("access-7", accessId)
                calls++
                return LocalSshReadinessResult.MetadataPresent(fixed)
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack={}) }
        compose.waitUntil(5_000) { compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.waitUntil(5_000) { calls == 1 }
        compose.onNodeWithTag("ssh_draft_target").performScrollTo().performTextInput("operator@node.example:22")
        compose.onNodeWithTag("ssh_draft_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.waitUntil(5_000) { calls == 2 }
        compose.onNodeWithTag("ssh_draft_prepared").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_draft_blocked").fetchSemanticsNodes().size)
    }

    @Test fun changedHostOnFreshReadBlocksOfflineDraft() {
        var calls = 0
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(fixed))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                calls++
                return LocalSshReadinessResult.MetadataPresent(
                    if (calls == 1) fixed else fixed.copy(host = "different.example"),
                )
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", fake, onBack={}) }
        compose.waitUntil(5_000) { compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.waitUntil(5_000) { calls == 1 }
        compose.onNodeWithTag("ssh_draft_target").performScrollTo().performTextInput("operator@node.example:22")
        compose.onNodeWithTag("ssh_draft_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.waitUntil(5_000) { calls == 2 }
        compose.onNodeWithTag("ssh_draft_blocked").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_draft_prepared").fetchSemanticsNodes().size)
    }
}
