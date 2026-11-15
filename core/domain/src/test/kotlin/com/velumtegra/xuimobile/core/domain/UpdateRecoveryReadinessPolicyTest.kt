package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class UpdateRecoveryReadinessPolicyTest {
    private val time = Instant.parse("2026-10-17T00:00:00Z")
    private val scope = ManagementScope(OperationId("operation"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("installation"))
    private fun source() = UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
        UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
        DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, time)
    private fun report(source: UpdateRecoverySourceSnapshot? = source()) = UpdatePreflightSnapshot(scope,
        UpdateRootStatus.DIRECT_ROOT, UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT,
        "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, time, UpdateServerArchitecture.AMD64, source)
    private fun blocked(report: UpdatePreflightSnapshot, reason: UpdateRecoveryBlocker, now: Instant = time) {
        val result = UpdateRecoveryReadinessPolicy.review(report, now) as UpdateRecoveryPlanReview.Blocked
        assertTrue(result.reasons.contains(reason))
    }

    @Test fun healthySourceProducesOnlyAnExactExpiringDraftWithAllProofsStillPending() {
        val plan = (UpdateRecoveryReadinessPolicy.review(report(), time) as UpdateRecoveryPlanReview.Draft).plan
        assertEquals(scope, plan.scope); assertEquals("3.10.0", plan.previousVersion)
        assertEquals(time.plusSeconds(300), plan.validUntil)
        assertEquals(UpdateRecoveryComponent.values().toList(), plan.components)
        assertEquals(UpdateRecoveryRequirement.values().toList(), plan.pendingProofs)
    }
    @Test fun noSourceCannotInventBackupReadiness() { blocked(report(null), UpdateRecoveryBlocker.SOURCE_NOT_OBSERVED) }
    @Test fun expiredAndFutureReportsHaveNoReviewableDraft() {
        blocked(report(), UpdateRecoveryBlocker.STALE_OR_FUTURE_REPORT, time.plusSeconds(300))
        blocked(report(), UpdateRecoveryBlocker.STALE_OR_FUTURE_REPORT, time.minusSeconds(1))
    }
    @Test fun anOldSourceInsideAFreshParentIsStillExpired() {
        blocked(report(source().copy(observedAt = time.minusSeconds(301))), UpdateRecoveryBlocker.STALE_OR_FUTURE_REPORT)
    }
    @Test fun failedPrivilegeServiceAndSavedSettingsCannotAdmitADraft() {
        listOf(report().copy(root = UpdateRootStatus.NOT_ROOT), report().copy(serviceState = ManagementServiceState.INACTIVE),
            report().copy(baselineStatus = ManagementBaselineStatus.Insufficient(setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED))))
            .forEach { blocked(it, UpdateRecoveryBlocker.CURRENT_INSTALLATION) }
    }
    @Test fun unknownArchitectureNeverDefaultsToThePhone() { blocked(report().copy(architecture = null), UpdateRecoveryBlocker.ARCHITECTURE_UNSUPPORTED) }
    @Test fun preReleaseAndIncompleteVersionsRequireTheirOwnContract() {
        listOf("3.10.0-rc.1", "3.10", "3.10.0.1").forEach { blocked(report().copy(currentVersion = it), UpdateRecoveryBlocker.STABLE_VERSION_REQUIRED) }
    }
    @Test fun backupPlanIsAllowedForCurrentOrNewerStableVersionWithoutClaimingAnUpgrade() {
        assertTrue(UpdateRecoveryReadinessPolicy.review(report().copy(currentVersion = "3.10.3"), time) is UpdateRecoveryPlanReview.Draft)
    }
    @Test fun everyMissingToolBlocksThePlan() {
        UpdateRecoveryTool.values().forEach { tool -> blocked(report(source().copy(tools = source().tools + (tool to UpdateRecoveryToolState.MISSING))), UpdateRecoveryBlocker.REQUIRED_TOOLS) }
    }
    @Test fun unsafeDatabaseStatesCannotBecomeAConsistentCopy() {
        UpdateRecoveryDatabaseState.values().filter { it != UpdateRecoveryDatabaseState.PRIVATE_REGULAR }.forEach { state ->
            blocked(report(source().copy(database = state)), if (state == UpdateRecoveryDatabaseState.CHANGED_DURING_READ)
                UpdateRecoveryBlocker.DATABASE_CHANGED else UpdateRecoveryBlocker.DATABASE_ACCESS)
        }
    }
    @Test fun emptyMissingOrOversizedByteCountBlocksDraft() {
        listOf(null, 0L, UpdateRecoverySourceSnapshot.MAX_DATABASE_BYTES + 1).forEach {
            blocked(report(source().copy(databaseBytes = it)), UpdateRecoveryBlocker.DATABASE_ACCESS)
        }
    }
    @Test fun integrityAndExpectedTableChecksAreIndependent() {
        blocked(report(source().copy(integrity = DeepDiagnosticDatabaseIntegrityStatus.FAILED)), UpdateRecoveryBlocker.DATABASE_INTEGRITY)
        blocked(report(source().copy(schema = DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE)), UpdateRecoveryBlocker.DATABASE_SCHEMA)
    }
    @Test fun runtimeSymlinkOrAbsenceBlocksTheDraft() {
        listOf(UpdateRecoveryRuntimeState.UNSAFE_LINK, UpdateRecoveryRuntimeState.UNAVAILABLE).forEach {
            blocked(report(source().copy(runtime = it)), UpdateRecoveryBlocker.RUNTIME_FILES)
        }
    }
    @Test fun tlsPairPresenceIsDifferentFromVerifiedPrivateFileBackup() {
        val draft = UpdateRecoveryReadinessPolicy.review(report(source().copy(panelTls = UpdateRecoveryPanelTlsState.PAIR_PRESENT)), time) as UpdateRecoveryPlanReview.Draft
        assertTrue(draft.plan.pendingProofs.contains(UpdateRecoveryRequirement.PRIVATE_SETTINGS_AND_CERTIFICATES))
        listOf(UpdateRecoveryPanelTlsState.INCOMPLETE, UpdateRecoveryPanelTlsState.UNAVAILABLE, UpdateRecoveryPanelTlsState.UNOBSERVED).forEach {
            blocked(report(source().copy(panelTls = it)), UpdateRecoveryBlocker.PANEL_TLS)
        }
    }
    @Test fun sourceFromAnotherExactTargetCannotEnterAParentReport() {
        try { report(source().copy(scope = scope.copy(serverAccessId = ServerAccessId("foreign")))); fail("Foreign source accepted") }
        catch (_: IllegalArgumentException) { }
    }
    @Test fun futureSourceCannotBeAttachedToAnEarlierParentReport() {
        try { report(source().copy(observedAt = time.plusSeconds(1))); fail("Future source accepted") }
        catch (_: IllegalArgumentException) { }
    }
}
