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

/** All fixture reads are in memory; never opens SSH, reads credentials or persists data. */
@RunWith(AndroidJUnit4::class)
class Phase14_2HCredentialReferenceAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val summary = LocalSshAccessSummary("access-7", "node.example", 22,
        "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43), "digest-a")
    private val target = "operator@node.example:22"

    private fun readyForDraft() {
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-7").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-7").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_target").performScrollTo().performTextInput(target)
        compose.onNodeWithTag("ssh_draft_acknowledge").performScrollTo().performClick()
    }

    @Test fun changedCredentialReferenceDuringDraftBlocksDespiteSameAuthLabel() {
        var reads = 0
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                reads++
                return LocalSshReadinessResult.MetadataPresent(
                    if (reads == 2) summary.copy(credentialRefDigest = "digest-b") else summary,
                )
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        readyForDraft()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_blocked").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_draft_prepared").fetchSemanticsNodes().size)
        assertEquals(2, reads)
    }

    @Test fun changedCredentialReferenceDuringHandoffConsumesConsentAndBlocks() {
        var reads = 0
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                reads++
                return LocalSshReadinessResult.MetadataPresent(
                    if (reads == 4) summary.copy(credentialRefDigest = "digest-b") else summary,
                )
            }
        }
        compose.setContent { SshReadinessScreen("server-7", "Fixture", port, onBack = {}) }
        readyForDraft()
        compose.onNodeWithTag("ssh_draft_prepare").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_draft_prepared").assertExists()
        compose.onNodeWithTag("ssh_consent_target").performScrollTo().performTextInput(target)
        compose.onNodeWithTag("ssh_consent_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_arm").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_consent_armed").assertExists()
        compose.onNodeWithTag("ssh_handoff_inspect").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_handoff_blocked").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_handoff_inspected").fetchSemanticsNodes().size)
        assertEquals(4, reads)
    }
}
