package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import org.junit.Assert.*
import org.junit.Test

class XuiEnrollmentReadFailurePolicyTest {
    private val scope = ManagementScope(OperationId("read"), ServerId("server"), ServerAccessId("access"), XuiInstallationId("installation"))
    private val settings = ManagementProbeSpec.PanelSettingsReadback("/etc/x-ui/x-ui.db")
    private fun message(failure: ManagementSshProbeExecutionFailure, probe: ManagementProbeSpec? = settings) =
        XuiEnrollmentReadFailurePolicy.message(ManagementSshProbeRunResult.Failed(scope, probe, failure, emptyList()))

    @Test fun absentReaderHasAnActionableMessage() {
        assertEquals(XuiEnrollmentReadFailurePolicy.SQLITE_UNAVAILABLE, message(ManagementSshProbeExecutionFailure.CommandFailed(ManagementPanelSettingsExit.SQLITE_UNAVAILABLE)))
    }
    @Test fun unreadableDatabaseDoesNotClaimMissingReader() {
        assertEquals(XuiEnrollmentReadFailurePolicy.DATABASE_UNREADABLE, message(ManagementSshProbeExecutionFailure.CommandFailed(ManagementPanelSettingsExit.DATABASE_UNREADABLE)))
    }
    @Test fun failedQueryDoesNotClaimMissingReaderOrRights() {
        assertEquals(XuiEnrollmentReadFailurePolicy.QUERY_FAILED, message(ManagementSshProbeExecutionFailure.CommandFailed(ManagementPanelSettingsExit.QUERY_FAILED)))
    }
    @Test fun reservedExitOnAnotherProbeCannotDiagnoseSettings() {
        for (probe in listOf(null, ManagementProbeSpec.ServiceUnitPresence("x-ui.service"))) {
            assertEquals(XuiEnrollmentReadFailurePolicy.OTHER, message(ManagementSshProbeExecutionFailure.CommandFailed(ManagementPanelSettingsExit.SQLITE_UNAVAILABLE), probe))
        }
    }
    @Test fun unknownAndOldExitCodesNeverInventADependencyCause() {
        for (code in listOf(null, 0, 1, 2, -1, 256)) assertEquals(XuiEnrollmentReadFailurePolicy.OTHER, message(ManagementSshProbeExecutionFailure.CommandFailed(code)))
    }
    @Test fun formatAndTruncationRemainDistinct() {
        assertEquals(XuiEnrollmentReadFailurePolicy.MALFORMED_SETTINGS, message(ManagementSshProbeExecutionFailure.MalformedProbeEvidence))
        assertEquals(XuiEnrollmentReadFailurePolicy.TRUNCATED_SETTINGS, message(ManagementSshProbeExecutionFailure.OutputTruncated))
    }
    @Test fun unconfirmedReadCannotBeDiagnosedAsMissingDependency() {
        assertEquals(XuiEnrollmentReadFailurePolicy.UNCERTAIN, message(ManagementSshProbeExecutionFailure.CommandUncertain(CommandDispatchState.DISPATCHED)))
    }
    @Test fun closedOrWrongSessionCannotBeDiagnosedAsDatabaseFailure() {
        for (failure in listOf(ManagementSshProbeExecutionFailure.SessionClosed, ManagementSshProbeExecutionFailure.ExactSessionBindingMismatch,
            ManagementSshProbeExecutionFailure.ScopeTargetMismatch, ManagementSshProbeExecutionFailure.ProbeOutsideApprovedPolicy)) {
            assertEquals(XuiEnrollmentReadFailurePolicy.OTHER, message(failure))
        }
    }
}
