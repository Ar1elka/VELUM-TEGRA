package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import java.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiEnrollmentReviewPolicyTest {
    private val at = Instant.parse("2026-10-13T00:00:00Z")
    private val candidate = XuiCandidateIdentityEvidence(
        "x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db",
    )
    private val identity = InstallationIdentity(
        candidate.serviceUnit, candidate.binaryPath, candidate.rootPath, candidate.databasePath, null,
    )
    private val proof = DiscoveryProof(
        DiscoveryProofId("proof"),
        DiscoveryScope(OperationId("run"), ServerId("server"), ServerAccessId("ssh")),
        identity, null,
        setOf(DiscoveryProofSignal.SERVICE_UNIT, DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH, DiscoveryProofSignal.DATABASE_PATH), at,
    )
    private val baseline = InstallationBaseline(
        candidate.serviceUnit, candidate.binaryPath, candidate.rootPath, candidate.databasePath,
        2053, "/safe-panel/", "127.0.0.1", at,
    )

    @Test fun acceptsExactCandidateProofAndVerifiedSettings() {
        assertTrue(XuiEnrollmentReviewPolicy.matches(candidate, proof, baseline))
    }

    @Test fun rejectsMismatchedDiscoveryCandidate() {
        assertFalse(XuiEnrollmentReviewPolicy.matches(
            candidate.copy(binaryPath = "/opt/x-ui/x-ui"), proof, baseline))
    }

    @Test fun rejectsMismatchedDatabaseBaseline() {
        assertFalse(XuiEnrollmentReviewPolicy.matches(
            candidate, proof, baseline.copy(databasePath = "/opt/x-ui/db/x-ui.db")))
    }

    @Test fun rejectsUnsafePanelPath() {
        assertFalse(XuiEnrollmentReviewPolicy.matches(
            candidate, proof, baseline.copy(webBasePath = "//evil.example")))
        assertFalse(XuiEnrollmentReviewPolicy.matches(
            candidate, proof, baseline.copy(webBasePath = "/a/../admin")))
    }
}
