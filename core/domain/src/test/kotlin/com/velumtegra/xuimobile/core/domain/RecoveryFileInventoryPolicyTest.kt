package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class RecoveryFileInventoryPolicyTest {
    private val at = Instant.parse("2026-10-17T04:00:00Z")
    private val scope = ManagementScope(OperationId("read"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("install"))
    private fun inventory() = RecoveryFileInventory(scope, RecoveryFileGroup.values().associateWith {
        when (it) { RecoveryFileGroup.RUNTIME -> RecoveryFileGroupObservation(2, 300000)
            RecoveryFileGroup.SERVICE -> RecoveryFileGroupObservation(1, 200)
            else -> RecoveryFileGroupObservation(0, 0) }
    }, 3, 300200, emptySet(), "a".repeat(64), at)
    private fun report(files: RecoveryFileInventory? = inventory()) = UpdatePreflightSnapshot(scope, UpdateRootStatus.DIRECT_ROOT,
        UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0",
        ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, at, UpdateServerArchitecture.AMD64, recoveryFiles = files)

    @Test fun observedKnownSetKeepsEveryArchiveAndRestoreProofPending() {
        val result = RecoveryFileInventoryPolicy.review(report(), at.plusSeconds(1)) as RecoveryFileInventoryReview.KnownSet
        assertEquals(3, result.fileCount); assertEquals(RecoveryFileArtifactProof.values().toList(), result.pendingProofs)
    }
    @Test fun oldReportWithoutFileInventoryRequiresANewExplicitRead() {
        assertEquals(RecoveryFileInventoryReview.Missing, RecoveryFileInventoryPolicy.review(report(null), at))
    }
    @Test fun fiveMinuteBoundaryAndFutureClockCannotProduceFreshEvidence() {
        assertEquals(RecoveryFileInventoryReview.Stale, RecoveryFileInventoryPolicy.review(report(), at.plusSeconds(300)))
        assertEquals(RecoveryFileInventoryReview.Stale, RecoveryFileInventoryPolicy.review(report(), at.minusSeconds(1)))
    }
    @Test fun recentOuterReportCannotRefreshAnOldInventoryTimestamp() {
        val value = report().copy(observedAt = at.plusSeconds(299))
        assertEquals(RecoveryFileInventoryReview.Stale, RecoveryFileInventoryPolicy.review(value, at.plusSeconds(300)))
    }
    @Test fun everyFiniteIssueRemainsAFindingRatherThanSuccess() {
        RecoveryFileIssue.values().forEach { issue ->
            val files = inventory().copy(issues = setOf(issue), knownSetDigest = null)
            assertEquals(RecoveryFileInventoryReview.Findings(setOf(issue)), RecoveryFileInventoryPolicy.review(report(files), at))
        }
    }
    @Test fun rootLayoutExecutableAndSettingsAreStillRequired() {
        for (value in listOf(report().copy(root = UpdateRootStatus.NOT_ROOT), report().copy(serviceDefinition = DeepDiagnosticServiceDefinitionStatus.EXEC_START_MISMATCH, currentVersion = null),
            report().copy(layout = UpdateLayoutStatus.UNSUPPORTED, currentVersion = null), report().copy(baselineStatus = ManagementBaselineStatus.Insufficient(setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED))))) {
            assertEquals(RecoveryFileInventoryReview.Findings(setOf(RecoveryFileIssue.TARGET_UNVERIFIED)), RecoveryFileInventoryPolicy.review(value, at))
        }
    }
    @Test fun noDigestOrEmptyRuntimeCannotPretendToBeAKnownSet() {
        assertTrue(RecoveryFileInventoryPolicy.review(report(inventory().copy(knownSetDigest = null)), at) is RecoveryFileInventoryReview.Findings)
        val groups = inventory().groups + (RecoveryFileGroup.RUNTIME to RecoveryFileGroupObservation(0, 0))
        assertTrue(RecoveryFileInventoryPolicy.review(report(inventory().copy(groups = groups)), at) is RecoveryFileInventoryReview.Findings)
    }
    @Test fun modelRejectsCrossOperationOrFutureNestedFacts() {
        try { report(inventory().copy(scope = scope.copy(operationId = OperationId("foreign")))); fail("Foreign scope accepted") } catch (_: IllegalArgumentException) { }
        try { report(inventory().copy(observedAt = at.plusSeconds(1))); fail("Future nested fact accepted") } catch (_: IllegalArgumentException) { }
    }
    @Test fun modelRejectsInvalidDigestCountsAndBytes() {
        try { inventory().copy(knownSetDigest = "PrivateValue"); fail("Invalid digest accepted") } catch (_: IllegalArgumentException) { }
        try { inventory().copy(issues = setOf(RecoveryFileIssue.FILES_CHANGED)); fail("Digest with findings accepted") } catch (_: IllegalArgumentException) { }
        try { RecoveryFileGroupObservation(97, 1); fail("Limit not enforced") } catch (_: IllegalArgumentException) { }
        try { inventory().copy(totalBytes = 0); fail("Aggregate mismatch accepted") } catch (_: IllegalArgumentException) { }
    }
}
