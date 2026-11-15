package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.model.DiscoveryFailureKind
import com.velumtegra.xuimobile.core.runtime.ReconnectPreparationFailureKind
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.runtime.ExactOperationHostDiscoveryResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequenceResult

/**
 * Reduces host/runtime outcomes to safe UI-facing process notices.
 *
 * No exception/reason string, raw command/output, credential data or session identity crosses this
 * boundary. Durable operation truth remains in OperationJournal and is never inferred from a notice.
 */
internal fun ExactOperationHostRuntimeBindResult.toDiscoveryProcessNotice(): DiscoveryProcessNotice? = when (this) {
    is ExactOperationHostRuntimeBindResult.Bound -> null
    ExactOperationHostRuntimeBindResult.InvalidOperationId -> internalFailureNotice()
    is ExactOperationHostRuntimeBindResult.OperationNotNonTerminal -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.DurableEvidenceUnavailable,
    is ExactOperationHostRuntimeBindResult.BootstrapFailed,
    is ExactOperationHostRuntimeBindResult.AdmissionFailed,
    -> DiscoveryProcessNotice.DurableStateUnavailable
    is ExactOperationHostRuntimeBindResult.NotExecutable -> DiscoveryProcessNotice.NotExecutable
    ExactOperationHostRuntimeBindResult.AlreadyOwned -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.StalePlan -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.ContractViolation -> internalFailureNotice()
}

internal fun ExactOperationHostTransportSequenceResult.toDiscoveryProcessNotice(): DiscoveryProcessNotice? = when (this) {
    is ExactOperationHostTransportSequenceResult.DiscoveryCompleted -> null
    is ExactOperationHostTransportSequenceResult.DiscoveryEnded -> discovery.toDiscoveryProcessNotice()
    is ExactOperationHostTransportSequenceResult.ManagementCompleted -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.ManagementEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.ServiceLogsEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.UpdatePreflightEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.DeepDiagnosticEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.Ended -> transportResult.toDiscoveryProcessNotice()
    is ExactOperationHostTransportSequenceResult.InstallerPrepared,
    is ExactOperationHostTransportSequenceResult.InstallerEnded,
    is ExactOperationHostTransportSequenceResult.InstallationBackupPrepared,
    is ExactOperationHostTransportSequenceResult.InstallationBackupEnded,
    is ExactOperationHostTransportSequenceResult.RestoreCheckPrepared,
    is ExactOperationHostTransportSequenceResult.RestoreCheckEnded,
    is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestorePrepared,
    is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestoreEnded,
    is ExactOperationHostTransportSequenceResult.RestoredPanelStartPrepared,
    is ExactOperationHostTransportSequenceResult.RestoredPanelStartEnded,
    is ExactOperationHostTransportSequenceResult.RestoreCompatibilityPrepared,
    is ExactOperationHostTransportSequenceResult.RestoreCompatibilityEnded,
    is ExactOperationHostTransportSequenceResult.DatabaseBackupPrepared,
    is ExactOperationHostTransportSequenceResult.DatabaseBackupEnded,
    is ExactOperationHostTransportSequenceResult.RestartPrepared,
    is ExactOperationHostTransportSequenceResult.RestartEnded,
    is ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned,
    -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.ContractViolation -> internalFailureNotice()
}

private fun ExactOperationHostDiscoveryResult.toDiscoveryProcessNotice(): DiscoveryProcessNotice = when (this) {
    is ExactOperationHostDiscoveryResult.Completed -> internalFailureNotice()
    is ExactOperationHostDiscoveryResult.NotDiscoveryOperation -> internalFailureNotice()
    ExactOperationHostDiscoveryResult.AdmissionLost -> DiscoveryProcessNotice.BusyOrSuperseded
    ExactOperationHostDiscoveryResult.SessionUnavailable -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostDiscoveryResult.StaleSession -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostDiscoveryResult.StalePlan -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostDiscoveryResult.Failed -> DiscoveryProcessNotice.DurableStateUnavailable
    is ExactOperationHostDiscoveryResult.ContractViolation -> internalFailureNotice()
}

private fun ExactOperationHostTransportResult.toDiscoveryProcessNotice(): DiscoveryProcessNotice = when (this) {
    is ExactOperationHostTransportResult.Connected -> internalFailureNotice()
    ExactOperationHostTransportResult.WaitForNetwork -> DiscoveryProcessNotice.WaitingForNetwork
    ExactOperationHostTransportResult.StaleConnectivityGeneration,
    ExactOperationHostTransportResult.AlreadyScheduledForGeneration,
    ExactOperationHostTransportResult.AdmissionLost,
    ExactOperationHostTransportResult.RetryPermitAlreadyConsumed,
    -> DiscoveryProcessNotice.BusyOrSuperseded
    is ExactOperationHostTransportResult.RecoveryBlocked -> reason.toDiscoveryProcessNotice()
    is ExactOperationHostTransportResult.PreparationFailed -> kind.toDiscoveryProcessNotice()
    is ExactOperationHostTransportResult.RetryPermitted -> internalFailureNotice()
    is ExactOperationHostTransportResult.Failed -> failure.toDiscoveryProcessNotice()
    is ExactOperationHostTransportResult.ContractViolation -> internalFailureNotice()
}

private fun RecoveryBlockReason.toDiscoveryProcessNotice(): DiscoveryProcessNotice = when (this) {
    RecoveryBlockReason.EXACT_ACCESS_MISSING -> failureNotice(DiscoveryFailureKind.EXACT_ACCESS_UNAVAILABLE)
    RecoveryBlockReason.REQUIRED_SECRET_MISSING -> failureNotice(DiscoveryFailureKind.SECRET_UNAVAILABLE)
    RecoveryBlockReason.HOST_IDENTITY_MISMATCH -> failureNotice(DiscoveryFailureKind.HOST_IDENTITY_MISMATCH)
    RecoveryBlockReason.AUTHENTICATION_REJECTED -> failureNotice(DiscoveryFailureKind.AUTHENTICATION_REJECTED)
    RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT -> DiscoveryProcessNotice.DurableStateUnavailable
}

private fun ReconnectPreparationFailureKind.toDiscoveryProcessNotice(): DiscoveryProcessNotice = when (this) {
    ReconnectPreparationFailureKind.ACCESS_STORAGE_FAILURE ->
        failureNotice(DiscoveryFailureKind.EXACT_ACCESS_UNAVAILABLE)
    ReconnectPreparationFailureKind.ACCESS_CORRUPTION,
    ReconnectPreparationFailureKind.ACCESS_CONTRACT_VIOLATION,
    ReconnectPreparationFailureKind.TRANSPORT_CONTRACT_VIOLATION,
    ReconnectPreparationFailureKind.SESSION_ID_COLLISION,
    -> internalFailureNotice()
}

private fun SshConnectFailure.toDiscoveryProcessNotice(): DiscoveryProcessNotice = when (this) {
    is SshConnectFailure.SecretUnavailable,
    is SshConnectFailure.SecretCorrupt,
    is SshConnectFailure.SecretStorageFailure,
    -> failureNotice(DiscoveryFailureKind.SECRET_UNAVAILABLE)
    is SshConnectFailure.Timeout -> failureNotice(DiscoveryFailureKind.TRANSPORT_TIMEOUT)
    is SshConnectFailure.Unreachable,
    is SshConnectFailure.NegotiationFailure,
    is SshConnectFailure.Unexpected,
    -> failureNotice(DiscoveryFailureKind.TRANSPORT_UNAVAILABLE)
    is SshConnectFailure.HostIdentityMismatch -> failureNotice(DiscoveryFailureKind.HOST_IDENTITY_MISMATCH)
    SshConnectFailure.AuthenticationRejected -> failureNotice(DiscoveryFailureKind.AUTHENTICATION_REJECTED)
    SshConnectFailure.Cancelled -> DiscoveryProcessNotice.HostInterrupted
    is SshConnectFailure.InvalidConfiguration -> internalFailureNotice()
}

private fun failureNotice(failure: DiscoveryFailureKind): DiscoveryProcessNotice =
    DiscoveryProcessNotice.Failure(failure)

private fun internalFailureNotice(): DiscoveryProcessNotice =
    failureNotice(DiscoveryFailureKind.INTERNAL_INVARIANT_FAILURE)
