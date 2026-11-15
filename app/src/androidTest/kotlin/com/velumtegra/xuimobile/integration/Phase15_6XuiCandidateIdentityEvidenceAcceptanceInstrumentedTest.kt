package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase15_6XuiCandidateIdentityEvidenceAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val whenSeen: Instant = Instant.parse("2026-01-01T00:00:00Z")
    private val scope = DiscoveryScope(OperationId("op-156"), ServerId("srv-156"), ServerAccessId("ssh-156"))

    private fun fixture(
        db: Boolean = true,
        foreignPanel: Boolean = false,
    ): DiscoveryEvidence {
        val observations = mutableListOf<DiscoveryObservation>(
            DiscoveryObservation.Platform(DiscoveryPlatform("ubuntu", "24.04"), whenSeen),
            DiscoveryObservation.ServiceUnit("x-ui.service", DiscoveryPresence.PRESENT, whenSeen),
            DiscoveryObservation.InstallationPath(DiscoveryPathKind.BINARY,
                "/usr/local/x-ui/x-ui", DiscoveryPresence.PRESENT, whenSeen),
            DiscoveryObservation.InstallationPath(DiscoveryPathKind.ROOT,
                "/usr/local/x-ui", DiscoveryPresence.PRESENT, whenSeen),
        )
        if (db) observations += DiscoveryObservation.InstallationPath(DiscoveryPathKind.DATABASE,
            "/etc/x-ui/x-ui.db", DiscoveryPresence.PRESENT, whenSeen)
        if (foreignPanel) {
            // Ambiguous requires two conflicting family observations, not just a foreign marker.
            observations += DiscoveryObservation.PanelFamily(
                DiscoveryPanelFamily.SUPPORTED_3X_UI, whenSeen)
            observations += DiscoveryObservation.PanelFamily(
                DiscoveryPanelFamily.FOREIGN_PANEL, whenSeen)
        }
        return DiscoveryEvidence(scope, observations)
    }

    @Test fun completeCanonicalEvidenceShowsExactCandidateStructureWithoutAdoption() {
        val observation = XuiDiscoveryConsentPolicy.presentEvidence(fixture())
        val identity = observation.candidateIdentity
        assertTrue(observation.label.contains("3x-ui"))
        assertEquals("x-ui.service", identity?.serviceUnit)
        assertEquals("/usr/local/x-ui/x-ui", identity?.binaryPath)
        assertEquals("/usr/local/x-ui", identity?.rootPath)
        assertEquals("/etc/x-ui/x-ui.db", identity?.databasePath)
        assertTrue(observation.detail.contains("ещё не подтверждены"))
    }

    @Test fun missingDatabaseCannotBePresentedAsProvenCandidateIdentity() {
        val evidence = fixture(db = false)
        assertTrue(DiscoveryClassifier.classify(evidence) is DiscoveryClassification.SupportedCandidate)
        assertNull(XuiDiscoveryConsentPolicy.presentEvidence(evidence).candidateIdentity)
    }

    @Test fun conflictingForeignPanelNeverCreatesCandidateIdentity() {
        val evidence = fixture(foreignPanel = true)
        val conflicting = DiscoveryClassifier.classify(evidence)
        assertTrue(conflicting is DiscoveryClassification.Ambiguous)
        assertTrue(DiscoveryConflict.SUPPORTED_AND_FOREIGN_PANEL_EVIDENCE in
            (conflicting as DiscoveryClassification.Ambiguous).conflicts)
        assertNull(XuiDiscoveryConsentPolicy.presentEvidence(evidence).candidateIdentity)

        // Foreign marker alone is classified ForeignPanel, never as a proven 3x-ui identity.
        val foreignOnly = DiscoveryEvidence(scope, fixture().observations +
            DiscoveryObservation.PanelFamily(DiscoveryPanelFamily.FOREIGN_PANEL, whenSeen))
        assertTrue(DiscoveryClassifier.classify(foreignOnly) is DiscoveryClassification.ForeignPanel)
        assertNull(XuiDiscoveryConsentPolicy.presentEvidence(foreignOnly).candidateIdentity)
    }

    @Test fun userApprovedScreenDisplaysOnlyFixtureCandidateAndOneAttempt() {
        val pin = "SHA256:" + "A".repeat(43)
        val profile = LocalSshAccessSummary("ssh-156", "example.org", 22, "root", "Пароль", pin, "digest-156")
        val local = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(profile))
            override suspend fun previewExact(serverId: String, accessId: String) =
                LocalSshReadinessResult.MetadataPresent(profile)
        }
        var attempts = 0
        val remote = object : XuiReadOnlyDiscoveryPort {
            override suspend fun inspectExact(serverId: String, accessId: String,
                reviewed: LocalSshAccessSummary, repeatedTarget: String,
                consent: Boolean): XuiReadOnlyDiscoveryResult {
                attempts++
                return XuiDiscoveryConsentPolicy.presentEvidence(fixture())
            }
        }
        compose.setContent { XuiReadOnlyDiscoveryScreen("srv-156", "VPS fixture", local, remote, {}) }
        compose.waitUntil(8_000) {
            compose.onAllNodesWithTag("xui_discovery_select_ssh-156").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("xui_discovery_select_ssh-156").performScrollTo().performClick()
        compose.waitUntil(8_000) {
            compose.onAllNodesWithTag("xui_discovery_target").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("xui_discovery_target").performScrollTo().performTextInput("root@example.org:22")
        compose.onNodeWithTag("xui_discovery_consent").performScrollTo().performClick()
        compose.onNodeWithTag("xui_discovery_start").performScrollTo().performClick()
        compose.waitUntil(8_000) {
            compose.onAllNodesWithTag("xui_discovery_candidate_identity").fetchSemanticsNodes().isNotEmpty()
        }
        compose.runOnIdle { assertEquals(1, attempts) }
    }
}
