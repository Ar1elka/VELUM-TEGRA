package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.ssh.XuiObservedServiceState
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase15_7XuiServiceStateVerificationAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val candidate = XuiCandidateIdentityEvidence(
        serviceUnit = "x-ui.service", binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui", databasePath = "/etc/x-ui/x-ui.db",
    )
    private val profile = LocalSshAccessSummary(
        "ssh-157", "example.org", 22, "root", "Пароль", "SHA256:" + "A".repeat(43), "digest-157",
    )
    private val local = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(profile))
        override suspend fun previewExact(serverId: String, accessId: String) =
            LocalSshReadinessResult.MetadataPresent(profile)
    }

    @Test fun canonicalCandidateAllowsOnlyKnownServiceAndMatchingLayout() {
        assertTrue(XuiServiceVerificationPolicy.approvedCandidate(candidate))
        assertTrue(XuiServiceVerificationPolicy.approvedCandidate(candidate.copy(
            binaryPath = "/opt/x-ui/x-ui", rootPath = "/opt/x-ui", databasePath = "/opt/x-ui/db/x-ui.db",
        )))
    }

    @Test fun mismatchedOrInjectedCandidateIsDeniedBeforeNetwork() {
        assertFalse(XuiServiceVerificationPolicy.approvedCandidate(candidate.copy(serviceUnit = "other.service")))
        assertFalse(XuiServiceVerificationPolicy.approvedCandidate(candidate.copy(binaryPath = "/tmp/x-ui")))
        assertFalse(XuiServiceVerificationPolicy.approvedCandidate(candidate.copy(rootPath = "/opt/x-ui")))
        assertFalse(XuiServiceVerificationPolicy.approvedCandidate(candidate.copy(databasePath = "/tmp/x-ui.db")))
        assertFalse(XuiServiceVerificationPolicy.approvedCandidate(candidate.copy(serviceUnit = "x-ui.service; reboot")))
    }

    private fun showCandidate(verify: suspend (
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, identity: XuiCandidateIdentityEvidence,
    ) -> XuiServiceVerificationResult) {
        val remote = object : XuiReadOnlyDiscoveryPort {
            override suspend fun inspectExact(serverId: String, accessId: String,
                reviewed: LocalSshAccessSummary, repeatedTarget: String, consent: Boolean
            ): XuiReadOnlyDiscoveryResult = XuiReadOnlyDiscoveryResult.Observation(
                label = "Обнаружены признаки 3x-ui", detail = "Только первичное обнаружение.",
                candidateIdentity = candidate,
            )
            override suspend fun verifyServiceExact(serverId: String, accessId: String,
                reviewed: LocalSshAccessSummary, repeatedTarget: String, consent: Boolean,
                candidate: XuiCandidateIdentityEvidence,
            ): XuiServiceVerificationResult = verify(serverId, accessId, reviewed, repeatedTarget, consent, candidate)
        }
        compose.setContent { XuiReadOnlyDiscoveryScreen("srv-157", "VPS fixture", local, remote, {}) }
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_discovery_select_ssh-157").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("xui_discovery_select_ssh-157").performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_discovery_target").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("xui_discovery_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_discovery_consent").performScrollTo().performClick()
        compose.onNodeWithTag("xui_discovery_start").performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_service_verify_start").fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test fun firstDiscoveryNeverAutomaticallyRunsSecondSshProbe() {
        var serviceCalls = 0
        showCandidate { _, _, _, _, _, _ ->
            serviceCalls++
            XuiServiceVerificationResult.Observed(XuiObservedServiceState.ACTIVE)
        }
        compose.onNodeWithTag("xui_service_verify_start").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("xui_service_target").performScrollTo()
            .performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_service_verify_start").performScrollTo().assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, serviceCalls) }
    }

    @Test fun secondExactTargetAndFreshConsentMakeExactlyOneExplicitRead() {
        var serviceCalls = 0
        showCandidate { _, accessId, reviewed, repeated, consent, identity ->
            serviceCalls++
            assertEquals("ssh-157", accessId)
            assertEquals(profile, reviewed)
            assertEquals("root@example.org:22", repeated)
            assertTrue(consent)
            assertEquals(candidate, identity)
            XuiServiceVerificationResult.Observed(XuiObservedServiceState.ACTIVE)
        }
        compose.onNodeWithTag("xui_service_target").performScrollTo()
            .performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_service_consent").performScrollTo().performClick()
        compose.onNodeWithTag("xui_service_verify_start").performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("xui_service_verified_state").fetchSemanticsNodes().isNotEmpty()
        }
        compose.runOnIdle { assertEquals(1, serviceCalls) }
    }
}
