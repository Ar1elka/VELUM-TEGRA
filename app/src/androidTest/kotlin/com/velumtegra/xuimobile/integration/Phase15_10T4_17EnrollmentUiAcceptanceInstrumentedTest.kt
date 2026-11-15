package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Memory-only UI contracts; real target/credentials are exercised by a separate opt-in runner. */
class Phase15_10T4_17EnrollmentUiAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private var at = Instant.parse("2026-10-22T00:00:00Z")
    private val profile = LocalSshAccessSummary("ssh", "fixture", 22, "root", "Fixture", "SHA256:" + "A".repeat(43), "digest")
    private val target = "root@fixture:22"
    private val candidate = XuiCandidateIdentityEvidence("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db")
    private val reads = AtomicInteger()
    private val saves = AtomicInteger()
    private val discards = AtomicInteger()
    private val discoveries = AtomicInteger()
    private val navigations = AtomicInteger()
    private fun ready() = XuiEnrollmentReview.Ready("review", target, candidate.serviceUnit,
        candidate.binaryPath, candidate.databasePath, 2053, "/panel/", at.plusSeconds(90))
    private var read: suspend () -> XuiEnrollmentReview = { ready() }
    private var save: suspend () -> XuiEnrollmentSave = { XuiEnrollmentSave.Saved("install", false) }
    private val local = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(profile))
        override suspend fun previewExact(serverId: String, accessId: String) = LocalSshReadinessResult.MetadataPresent(profile)
    }
    private val discovery = object : XuiReadOnlyDiscoveryPort {
        override suspend fun inspectExact(serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
            repeatedTarget: String, consent: Boolean): XuiReadOnlyDiscoveryResult {
            discoveries.incrementAndGet()
            return XuiReadOnlyDiscoveryResult.Observation("3x-ui", "Fixture", candidate)
        }
    }
    private val enrollment = object : XuiVerifiedEnrollmentPort {
        override suspend fun reviewExact(serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
            repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence): XuiEnrollmentReview {
            assertEquals("server", serverId); assertEquals(profile, reviewed); assertEquals(target, repeatedTarget); assertTrue(consent)
            reads.incrementAndGet(); return read()
        }
        override suspend fun saveReviewed(reviewToken: String, serverId: String, accessId: String): XuiEnrollmentSave {
            assertEquals("review", reviewToken); assertEquals("server", serverId); assertEquals("ssh", accessId)
            saves.incrementAndGet(); return save()
        }
        override fun discard(reviewToken: String) { discards.incrementAndGet() }
    }
    private fun click(tag: String) = compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun type(tag: String, value: String) = compose.onNodeWithTag(tag).performScrollTo().performTextInput(value)
    private fun await(tag: String) = compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun show() {
        compose.setContent { VelumTegraTheme { XuiReadOnlyDiscoveryScreen("server", "Fixture", local, discovery, {},
            enrollment, { navigations.incrementAndGet() }, now = { at }) } }
        await("xui_discovery_select_ssh")
    }
    private fun candidate() {
        show(); click("xui_discovery_select_ssh"); await("xui_discovery_target")
        type("xui_discovery_target", target); click("xui_discovery_consent"); click("xui_discovery_start")
        await("xui_enroll_target")
    }
    private fun review() {
        candidate(); type("xui_enroll_target", target); click("xui_enroll_read_consent"); click("xui_enroll_review_start")
    }
    private fun reviewed() { review(); await("xui_enroll_verified") }
    @Test fun openingHasNoNetworkOrSave() {
        show(); compose.onNodeWithTag("xui_connect_step_access").assertExists()
        assertEquals(0, discoveries.get()); assertEquals(0, reads.get()); assertEquals(0, saves.get())
    }
    @Test fun discoveryDoesNotImplicitlyEnroll() {
        candidate(); compose.onNodeWithTag("xui_connect_step_discovery").assertExists()
        compose.onNodeWithTag("xui_connect_step_enrollment").assertExists()
        compose.onNodeWithTag("xui_enroll_scope").assertTextContains("резервная копия создаётся отдельно", substring = true)
        assertEquals(1, discoveries.get()); assertEquals(0, reads.get()); absent("xui_enroll_save")
    }
    @Test fun exactTargetAndSeparateConsentRequired() {
        candidate(); type("xui_enroll_target", target); compose.onNodeWithTag("xui_enroll_review_start").assertIsNotEnabled()
        assertEquals(0, reads.get())
    }
    @Test fun wrongTargetCannotStartRead() {
        candidate(); type("xui_enroll_target", "root@other:22"); click("xui_enroll_read_consent")
        compose.onNodeWithTag("xui_enroll_review_start").assertIsNotEnabled(); assertEquals(0, reads.get())
    }
    @Test fun reviewedFactsStillRequireSaveConsent() {
        reviewed(); compose.onNodeWithTag("xui_enroll_confirm_target").assertTextContains(target, substring = true)
        compose.onNodeWithTag("xui_enroll_save").assertIsNotEnabled(); assertEquals(0, saves.get())
    }
    @Test fun explicitSavePublishesOnceAndShowsNextUiStep() {
        reviewed(); click("xui_enroll_save_consent"); click("xui_enroll_save"); await("xui_enroll_saved")
        assertEquals(1, saves.get()); assertEquals(1, navigations.get()); absent("xui_enroll_not_saved")
    }
    @Test fun rejectedSaveCannotNavigateOrClaimSuccess() {
        save = { XuiEnrollmentSave.Blocked("Fixture rejection") }; reviewed(); click("xui_enroll_save_consent"); click("xui_enroll_save")
        await("xui_enroll_save_blocked"); absent("xui_enroll_saved"); assertEquals(0, navigations.get())
    }
    @Test fun readFailureShowsNoSaveControl() {
        read = { XuiEnrollmentReview.Blocked("Fixture missing settings") }; review(); await("xui_enroll_review_blocked")
        absent("xui_enroll_save"); assertEquals(0, saves.get())
    }
    @Test fun foreignReadyIsDiscardedBeforeDisplay() {
        read = { ready().copy(exactTarget = "root@foreign:22") }; review(); await("xui_enroll_review_blocked")
        absent("xui_enroll_verified"); assertEquals(1, discards.get()); assertEquals(0, saves.get())
    }
    @Test fun elapsedReviewCannotDispatchLocalSave() {
        reviewed(); compose.runOnIdle { at = at.plusSeconds(91) }; click("xui_enroll_save_consent"); click("xui_enroll_save")
        await("xui_enroll_review_blocked"); assertEquals(0, saves.get()); assertEquals(0, navigations.get())
    }
    @Test fun inFlightReadLocksRefreshDiscoveryAndOtherActions() {
        val gate = CompletableDeferred<XuiEnrollmentReview>(); read = { gate.await() }; review(); await("xui_enroll_progress")
        for (tag in listOf("xui_discovery_refresh", "xui_discovery_start", "xui_service_verify_start", "xui_version_verify_start", "xui_enroll_review_start")) {
            compose.onNodeWithTag(tag).assertIsNotEnabled()
        }
        click("xui_enroll_cancel"); gate.complete(XuiEnrollmentReview.Blocked("cancelled")); assertEquals(0, saves.get())
    }
    @Test fun lateReadAfterCancelCannotPublishReview() {
        val returned = AtomicInteger()
        val gate = CompletableDeferred<XuiEnrollmentReview>()
        read = { withContext(NonCancellable) { gate.await().also { returned.incrementAndGet() } } }
        review(); await("xui_enroll_progress"); click("xui_enroll_cancel"); gate.complete(ready())
        compose.waitUntil(10_000) { returned.get() == 1 }; compose.waitForIdle()
        absent("xui_enroll_verified"); assertEquals(0, saves.get())
    }
    @Test fun targetEditRevokesReviewedConsent() {
        reviewed(); type("xui_enroll_target", "x"); absent("xui_enroll_save"); assertTrue(discards.get() > 0); assertEquals(0, saves.get())
    }
    @Test fun duplicateSaveWhileSuspendedCannotDispatchAgain() {
        val gate = CompletableDeferred<XuiEnrollmentSave>(); save = { gate.await() }; reviewed(); click("xui_enroll_save_consent"); click("xui_enroll_save")
        compose.waitUntil(10_000) { saves.get() == 1 }; compose.onNodeWithTag("xui_enroll_save").assertIsNotEnabled()
        compose.onNodeWithTag("xui_discovery_refresh").assertIsNotEnabled(); gate.complete(XuiEnrollmentSave.Saved("install", false)); await("xui_enroll_saved")
        assertEquals(1, saves.get())
    }
}
