package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
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

/** Fixture only: does not create any local records, secrets, sockets or SSH sessions. */
@RunWith(AndroidJUnit4::class)
class Phase14_2COfflineSshReadinessAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun onlyExactAccessAfterExplicitOfflineAcknowledgementCanBePreviewed() {
        var previewCalls = 0
        var returned = false
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String): LocalSshAccessList {
                assertEquals("server-A", serverId)
                return LocalSshAccessList.Available(listOf(
                    LocalSshAccessSummary("access-1", "one.example", 22, "operator", "Пароль", "SHA256:" + "A".repeat(43)),
                    LocalSshAccessSummary("access-2", "two.example", 2222, "root", "Приватный ключ", "SHA256:" + "B".repeat(43)),
                ))
            }
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                previewCalls++
                assertEquals("server-A", serverId)
                assertEquals("access-2", accessId)
                return LocalSshReadinessResult.MetadataPresent(
                    LocalSshAccessSummary("access-2", "two.example", 2222, "root", "Приватный ключ", "SHA256:" + "B".repeat(43)),
                )
            }
        }
        compose.setContent {
            SshReadinessScreen(serverId="server-A", serverName="Fixture A", port=fake, onBack={ returned = true })
        }
        compose.onNodeWithTag("ssh_readiness_root").assertExists()
        compose.onNodeWithTag("ssh_readiness_exact_server").assertExists()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-2").fetchSemanticsNodes().isNotEmpty()
        }
        // No implicit selection and no unconsented preview.
        compose.onNodeWithTag("ssh_readiness_preview").assertExists()
        compose.runOnIdle { assertEquals(0, previewCalls) }
        compose.onNodeWithTag("ssh_readiness_choose_access-1").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_choose_access-2").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_exact_access").assertExists()
        compose.runOnIdle { assertEquals(0, previewCalls) }
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.waitUntil(5_000) { previewCalls == 1 }
        compose.onNodeWithTag("ssh_readiness_metadata_present").assertExists()
        compose.onNodeWithTag("ssh_readiness_back").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(true, returned) }
    }

    @Test fun blockedResultNeverClaimsMetadataPresent() {
        val fake = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(
                LocalSshAccessSummary("access-x", "example.org", 22, "operator", "Пароль", "SHA256:" + "A".repeat(43)),
            ))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                assertEquals("server-x", serverId)
                assertEquals("access-x", accessId)
                return LocalSshReadinessResult.Blocked("Недопустимое локальное состояние")
            }
        }
        compose.setContent {
            SshReadinessScreen(serverId="server-x", serverName="Fixture X", port=fake, onBack={})
        }
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("ssh_readiness_choose_access-x").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("ssh_readiness_choose_access-x").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_acknowledge").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_preview").performScrollTo().performClick()
        compose.onNodeWithTag("ssh_readiness_blocked").assertExists()
        assertEquals(0, compose.onAllNodesWithTag("ssh_readiness_metadata_present").fetchSemanticsNodes().size)
    }
}
