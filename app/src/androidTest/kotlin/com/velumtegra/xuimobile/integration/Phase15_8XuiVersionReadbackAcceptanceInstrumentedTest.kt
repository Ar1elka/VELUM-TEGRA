package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase15_8XuiVersionReadbackAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val candidate = XuiCandidateIdentityEvidence("x-ui.service", "/usr/local/x-ui/x-ui",
        "/usr/local/x-ui", "/etc/x-ui/x-ui.db")
    private val profile = LocalSshAccessSummary(
        "ssh-158", "example.org", 22, "root", "Пароль", "SHA256:" + "A".repeat(43), "digest-158",
    )
    private val local = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(profile))
        override suspend fun previewExact(serverId: String, accessId: String) =
            LocalSshReadinessResult.MetadataPresent(profile)
    }

    @Test fun onlyTwoCanonicalCandidateLayoutsMayRequestBinaryVersion() {
        assertTrue(XuiVersionVerificationPolicy.approvedCandidate(candidate))
        assertTrue(XuiVersionVerificationPolicy.approvedCandidate(candidate.copy(
            binaryPath = "/opt/x-ui/x-ui", rootPath = "/opt/x-ui", databasePath = "/opt/x-ui/x-ui.db",
        )))
    }

    @Test fun injectedOrForeignCandidateIsRejectedBeforeConnection() {
        assertFalse(XuiVersionVerificationPolicy.approvedCandidate(candidate.copy(binaryPath = "/bin/sh")))
        assertFalse(XuiVersionVerificationPolicy.approvedCandidate(candidate.copy(binaryPath = "/tmp/x-ui")))
        assertFalse(XuiVersionVerificationPolicy.approvedCandidate(candidate.copy(rootPath = "/tmp")))
        assertFalse(XuiVersionVerificationPolicy.approvedCandidate(candidate.copy(serviceUnit = "other.service")))
        assertFalse(XuiVersionVerificationPolicy.approvedCandidate(candidate.copy(binaryPath = "/usr/local/x-ui/x-ui; curl bad")))
    }

    private fun showCandidate(verify: suspend (
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ) -> XuiVersionVerificationResult) {
        val remote = object : XuiReadOnlyDiscoveryPort {
            override suspend fun inspectExact(serverId: String, accessId: String,
                reviewed: LocalSshAccessSummary, repeatedTarget: String, consent: Boolean,
            ) = XuiReadOnlyDiscoveryResult.Observation("3x-ui", "Первичный осмотр.", candidate)
            override suspend fun verifyVersionExact(serverId: String, accessId: String,
                reviewed: LocalSshAccessSummary, repeatedTarget: String, consent: Boolean,
                candidate: XuiCandidateIdentityEvidence,
            ) = verify(serverId, accessId, reviewed, repeatedTarget, consent, candidate)
        }
        compose.setContent { XuiReadOnlyDiscoveryScreen("srv-158", "VPS fixture", local, remote, {}) }
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_discovery_select_ssh-158").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("xui_discovery_select_ssh-158").performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_discovery_target").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("xui_discovery_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_discovery_consent").performScrollTo().performClick()
        compose.onNodeWithTag("xui_discovery_start").performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_version_verify_start").fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test fun discoveryAndServiceNeverImplicitlyTriggerVersionReadback() {
        var versionCalls = 0
        showCandidate { _, _, _, _, _, _ ->
            versionCalls++
            XuiVersionVerificationResult.Observed("v3.7.0")
        }
        compose.onNodeWithTag("xui_version_verify_start").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("xui_version_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_version_verify_start").performScrollTo().assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, versionCalls) }
    }

    @Test fun freshIndependentConsentReadsOneSanitizedVersionWithoutPanelSettings() {
        var versionCalls = 0
        showCandidate { _, accessId, reviewed, repeated, consent, identity ->
            versionCalls++
            assertEquals("ssh-158", accessId)
            assertEquals(profile, reviewed)
            assertEquals("root@example.org:22", repeated)
            assertTrue(consent)
            assertEquals(candidate, identity)
            XuiVersionVerificationResult.Observed("v3.7.0")
        }
        compose.onNodeWithTag("xui_version_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_version_consent").performScrollTo().performClick()
        compose.onNodeWithTag("xui_version_verify_start").performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_version_verified_value").fetchSemanticsNodes().isNotEmpty()
        }
        compose.runOnIdle { assertEquals(1, versionCalls) }
    }
}
