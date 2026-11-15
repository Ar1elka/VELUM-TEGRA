package com.velumtegra.xuimobile.discovery

import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class XuiEnrollmentUiPolicyTest {
    private val at = Instant.parse("2026-10-22T00:00:00Z")
    private val candidate = XuiCandidateIdentityEvidence("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db")
    private val ready = XuiEnrollmentReview.Ready("token", "root@fixture:22", candidate.serviceUnit,
        candidate.binaryPath, candidate.databasePath, 2053, "/panel/", at.plusSeconds(90))
    private fun valid(r: XuiEnrollmentReview.Ready = ready, target: String = ready.exactTarget,
        c: XuiCandidateIdentityEvidence = candidate, time: Instant = at) = XuiEnrollmentUiPolicy.matches(r, target, c, time)
    @Test fun exactFreshReviewIsDisplayable() { assertTrue(valid()) }
    @Test fun expiredAndExactDeadlineAreNotConsent() { assertFalse(valid(time = ready.expiresAt)); assertFalse(valid(time = at.plusSeconds(91))) }
    @Test fun implausiblyFutureReviewFailsClosed() { assertFalse(valid(ready.copy(expiresAt = at.plusSeconds(91)))) }
    @Test fun foreignTargetFailsClosed() { assertFalse(valid(target = "root@other:22")) }
    @Test fun blankAndOversizedTokensFailClosed() { assertFalse(valid(ready.copy(reviewToken = " "))); assertFalse(valid(ready.copy(reviewToken = "a".repeat(129)))) }
    @Test fun mismatchedCanonicalFieldsFailClosed() {
        assertFalse(valid(ready.copy(serviceUnit = "other.service")))
        assertFalse(valid(ready.copy(binaryPath = "/opt/x-ui/x-ui")))
        assertFalse(valid(ready.copy(databasePath = "/opt/x-ui/x-ui.db")))
    }
    @Test fun injectedCandidateCannotMakeMatchingStringsTrusted() {
        val c = candidate.copy(binaryPath = "/bin/sh")
        assertFalse(valid(ready.copy(binaryPath = c.binaryPath), c = c))
    }
    @Test fun invalidPortsFailClosed() { assertFalse(valid(ready.copy(panelPort = 0))); assertFalse(valid(ready.copy(panelPort = 65536))) }
    @Test fun unsafeWebPathFailsClosed() { assertFalse(valid(ready.copy(webBasePath = "https://foreign/"))); assertFalse(valid(ready.copy(webBasePath = "/../private/"))) }
    @Test fun alternativeApprovedLayoutRequiresMatchingFields() {
        val c = XuiCandidateIdentityEvidence("x-ui.service", "/opt/x-ui/x-ui", "/opt/x-ui", "/opt/x-ui/x-ui.db")
        assertTrue(valid(ready.copy(binaryPath = c.binaryPath, databasePath = c.databasePath), c = c))
    }
}
