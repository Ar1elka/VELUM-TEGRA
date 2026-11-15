package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class UpdatePreparationPolicyTest {
    private fun snapshot() = UpdatePreflightSnapshot(ManagementScope(OperationId("op"), ServerId("server"),
        ServerAccessId("ssh"), XuiInstallationId("install")), UpdateRootStatus.DIRECT_ROOT,
        UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.0.0",
        ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, Instant.parse("2026-10-16T18:00:00Z"))
    @Test fun allObservedChecksCanPassWithoutCreatingAnyMutationAuthority() {
        assertTrue(UpdatePreparationPolicy.blockingChecks(snapshot()).isEmpty())
    }
    @Test fun nonRootAndMissingVersionAreIndependentBlockingChecks() {
        assertEquals(setOf(UpdatePreparationCheck.DIRECT_ROOT, UpdatePreparationCheck.CURRENT_VERSION),
            UpdatePreparationPolicy.blockingChecks(snapshot().copy(root = UpdateRootStatus.NOT_ROOT, currentVersion = null)))
    }
    @Test fun driftGapsAndInactiveServiceNeverPass() {
        val observed = snapshot().copy(serviceState = ManagementServiceState.FAILED,
            baselineStatus = ManagementBaselineStatus.Drift(setOf(ManagementBaselineDrift.PANEL_PORT)))
        assertEquals(setOf(UpdatePreparationCheck.ACTIVE_SERVICE, UpdatePreparationCheck.SAVED_SETTINGS), UpdatePreparationPolicy.blockingChecks(observed))
        assertTrue(UpdatePreparationCheck.SAVED_SETTINGS in UpdatePreparationPolicy.blockingChecks(snapshot().copy(
            baselineStatus = ManagementBaselineStatus.Insufficient(setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED)))))
    }
    @Test fun unsupportedOrUnverifiedExecutableCannotCarryAPurportedVersion() {
        assertThrows(IllegalArgumentException::class.java) { snapshot().copy(layout = UpdateLayoutStatus.UNSUPPORTED) }
        assertThrows(IllegalArgumentException::class.java) { snapshot().copy(serviceDefinition = DeepDiagnosticServiceDefinitionStatus.EXEC_START_MISMATCH) }
        assertThrows(IllegalArgumentException::class.java) { snapshot().copy(currentVersion = "password=secret") }
    }
}
