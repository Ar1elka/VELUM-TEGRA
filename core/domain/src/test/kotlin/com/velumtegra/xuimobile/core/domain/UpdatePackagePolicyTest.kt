package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class UpdatePackagePolicyTest {
    private val now = Instant.parse("2026-10-16T20:00:00Z")
    private fun report() = UpdatePreflightSnapshot(ManagementScope(OperationId("operation"), ServerId("server"),
        ServerAccessId("ssh"), XuiInstallationId("installation")), UpdateRootStatus.DIRECT_ROOT,
        UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT,
        "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, now,
        UpdateServerArchitecture.AMD64)
    private fun blocked(value: UpdatePreflightSnapshot, reason: UpdatePackageBlocker, time: Instant = now) =
        assertEquals(UpdatePackageEligibility.Blocked(reason), UpdatePackagePolicy.review(value, time))

    @Test fun exactServerArchitectureSelectsTheReviewedArtifact() {
        assertEquals(UpdatePackageEligibility.Available(ReviewedXuiUpdatePackage.V3_10_2_AMD64), UpdatePackagePolicy.review(report(), now))
        assertEquals(UpdatePackageEligibility.Available(ReviewedXuiUpdatePackage.V3_10_2_ARM64),
            UpdatePackagePolicy.review(report().copy(architecture = UpdateServerArchitecture.ARM64), now))
    }
    @Test fun sameOrNewerInstalledVersionIsNeverProposedAsAnUpgrade() {
        listOf("3.10.2", "v3.10.2", "3.10.3", "3.11.0", "4.0.0").forEach {
            blocked(report().copy(currentVersion = it), UpdatePackageBlocker.NO_NEWER_REVIEWED_RELEASE)
        }
    }
    @Test fun numericComparisonDoesNotUseLexicographicVersionOrdering() {
        assertTrue(UpdatePackagePolicy.review(report().copy(currentVersion = "3.9.99"), now) is UpdatePackageEligibility.Available)
        blocked(report().copy(currentVersion = "3.100.0"), UpdatePackageBlocker.NO_NEWER_REVIEWED_RELEASE)
    }
    @Test fun prereleaseAndUnknownVersionShapesRequireSeparateReview() {
        listOf("3.10", "3.10.0.1", "3.10.0-rc.1").forEach {
            blocked(report().copy(currentVersion = it), UpdatePackageBlocker.UNSUPPORTED_VERSION)
        }
    }
    @Test fun unknownArchitectureDoesNotDefaultToThePhonesCpu() {
        blocked(report().copy(architecture = null), UpdatePackageBlocker.UNKNOWN_ARCHITECTURE)
    }
    @Test fun futureAndExpiredReportsCannotSelectAPackage() {
        blocked(report(), UpdatePackageBlocker.STALE_REPORT, now.minusSeconds(1))
        blocked(report(), UpdatePackageBlocker.STALE_REPORT, now.plusSeconds(601))
        assertTrue(UpdatePackagePolicy.review(report(), now.plusSeconds(600)) is UpdatePackageEligibility.Available)
    }
    @Test fun failedPrivilegeServiceOrBaselineChecksBlockSelection() {
        listOf(report().copy(root = UpdateRootStatus.NOT_ROOT), report().copy(serviceState = ManagementServiceState.INACTIVE),
            report().copy(baselineStatus = ManagementBaselineStatus.Drift(setOf(ManagementBaselineDrift.PANEL_PORT))))
            .forEach { blocked(it, UpdatePackageBlocker.PRECHECKS) }
    }
    @Test fun versionAndArchitectureMustMatchTheRequestedClosedArtifact() {
        val request = UpdatePackageRequest(report(), ReviewedXuiUpdatePackage.V3_10_2_ARM64)
        assertFalse(UpdatePackagePolicy.matches(request, now))
    }
    @Test fun receiptForAnotherTargetOrReportCannotBeReused() {
        val r = report(); val request = UpdatePackageRequest(r, ReviewedXuiUpdatePackage.V3_10_2_AMD64)
        val receipt = UpdatePackageReceipt(r.scope, now, request.release, request.release.sha256, 100, now, "0".repeat(32))
        assertTrue(UpdatePackagePolicy.receiptMatches(request, receipt, now))
        assertFalse(UpdatePackagePolicy.receiptMatches(request, receipt.copy(scope = r.scope.copy(serverAccessId = ServerAccessId("foreign"))), now))
        assertFalse(UpdatePackagePolicy.receiptMatches(request.copy(report = r.copy(observedAt = now.minusSeconds(1))), receipt, now))
    }
    @Test fun futureReceiptIsNotReportedAsVerifiedNow() {
        val r = report(); val release = ReviewedXuiUpdatePackage.V3_10_2_AMD64
        val receipt = UpdatePackageReceipt(r.scope, now, release, release.sha256, 100, now.plusSeconds(1), "0".repeat(32))
        assertFalse(UpdatePackagePolicy.receiptMatches(UpdatePackageRequest(r, release), receipt, now))
    }
    @Test fun corruptDigestCannotConstructAReceiptForAReviewedRelease() {
        val r = report(); val release = ReviewedXuiUpdatePackage.V3_10_2_AMD64
        try { UpdatePackageReceipt(r.scope, now, release, "0".repeat(64), 100, now, "0".repeat(32)); fail("Invalid digest accepted") }
        catch (_: IllegalArgumentException) { }
    }
}
