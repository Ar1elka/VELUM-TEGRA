package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.ManagementFailureKind
import com.velumtegra.xuimobile.core.runtime.ReconnectPreparationFailureKind
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.runtime.ExactOperationHostDeepDiagnosticResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequenceResult

internal fun ExactOperationHostRuntimeBindResult.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice? = when (this) {
    is ExactOperationHostRuntimeBindResult.Bound -> null
    ExactOperationHostRuntimeBindResult.InvalidOperationId -> internalFailureNotice()
    is ExactOperationHostRuntimeBindResult.OperationNotNonTerminal -> DeepDiagnosticProcessNotice.NotExecutable
    is ExactOperationHostRuntimeBindResult.DurableEvidenceUnavailable,
    is ExactOperationHostRuntimeBindResult.BootstrapFailed,
    is ExactOperationHostRuntimeBindResult.AdmissionFailed,
    -> DeepDiagnosticProcessNotice.DurableStateUnavailable
    is ExactOperationHostRuntimeBindResult.NotExecutable -> DeepDiagnosticProcessNotice.NotExecutable
    ExactOperationHostRuntimeBindResult.AlreadyOwned -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.StalePlan -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.ContractViolation -> internalFailureNotice()
}

internal fun ExactOperationHostTransportSequenceResult.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice? = when (this) {
    is ExactOperationHostTransportSequenceResult.ServiceLogsEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.UpdatePreflightEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted -> null
    is ExactOperationHostTransportSequenceResult.DeepDiagnosticEnded -> deepDiagnostic.toDeepDiagnosticProcessNotice()
    is ExactOperationHostTransportSequenceResult.Ended -> transportResult.toDeepDiagnosticProcessNotice()
    is ExactOperationHostTransportSequenceResult.DiscoveryCompleted,
    is ExactOperationHostTransportSequenceResult.DiscoveryEnded,
    is ExactOperationHostTransportSequenceResult.ManagementCompleted,
    is ExactOperationHostTransportSequenceResult.ManagementEnded,
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
    is ExactOperationHostTransportSequenceResult.ContractViolation,
    -> internalFailureNotice()
}

private fun ExactOperationHostDeepDiagnosticResult.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice? = when (this) {
    is ExactOperationHostDeepDiagnosticResult.Completed -> null
    is ExactOperationHostDeepDiagnosticResult.ReadbackFailed -> null // terminal detail is published separately
    is ExactOperationHostDeepDiagnosticResult.NotDeepDiagnosticOperation -> internalFailureNotice()
    ExactOperationHostDeepDiagnosticResult.AdmissionLost -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    ExactOperationHostDeepDiagnosticResult.SessionUnavailable -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    is ExactOperationHostDeepDiagnosticResult.StaleSession -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    is ExactOperationHostDeepDiagnosticResult.StalePlan -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    is ExactOperationHostDeepDiagnosticResult.Failed -> DeepDiagnosticProcessNotice.DurableStateUnavailable
    is ExactOperationHostDeepDiagnosticResult.ContractViolation -> internalFailureNotice()
}

private fun ExactOperationHostTransportResult.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice = when (this) {
    is ExactOperationHostTransportResult.Connected -> internalFailureNotice()
    ExactOperationHostTransportResult.WaitForNetwork -> DeepDiagnosticProcessNotice.WaitingForNetwork
    ExactOperationHostTransportResult.StaleConnectivityGeneration,
    ExactOperationHostTransportResult.AlreadyScheduledForGeneration,
    ExactOperationHostTransportResult.AdmissionLost,
    ExactOperationHostTransportResult.RetryPermitAlreadyConsumed,
    -> DeepDiagnosticProcessNotice.BusyOrSuperseded
    is ExactOperationHostTransportResult.RecoveryBlocked -> reason.toDeepDiagnosticProcessNotice()
    is ExactOperationHostTransportResult.PreparationFailed -> kind.toDeepDiagnosticProcessNotice()
    is ExactOperationHostTransportResult.RetryPermitted -> internalFailureNotice()
    is ExactOperationHostTransportResult.Failed -> failure.toDeepDiagnosticProcessNotice()
    is ExactOperationHostTransportResult.ContractViolation -> internalFailureNotice()
}

private fun RecoveryBlockReason.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice = when (this) {
    RecoveryBlockReason.EXACT_ACCESS_MISSING -> failureNotice(ManagementFailureKind.EXACT_ACCESS_UNAVAILABLE)
    RecoveryBlockReason.REQUIRED_SECRET_MISSING -> failureNotice(ManagementFailureKind.SECRET_UNAVAILABLE)
    RecoveryBlockReason.HOST_IDENTITY_MISMATCH -> failureNotice(ManagementFailureKind.HOST_IDENTITY_MISMATCH)
    RecoveryBlockReason.AUTHENTICATION_REJECTED -> failureNotice(ManagementFailureKind.AUTHENTICATION_REJECTED)
    RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT -> DeepDiagnosticProcessNotice.DurableStateUnavailable
}

private fun ReconnectPreparationFailureKind.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice = when (this) {
    ReconnectPreparationFailureKind.ACCESS_STORAGE_FAILURE ->
        failureNotice(ManagementFailureKind.EXACT_ACCESS_UNAVAILABLE)
    ReconnectPreparationFailureKind.ACCESS_CORRUPTION,
    ReconnectPreparationFailureKind.ACCESS_CONTRACT_VIOLATION,
    ReconnectPreparationFailureKind.TRANSPORT_CONTRACT_VIOLATION,
    ReconnectPreparationFailureKind.SESSION_ID_COLLISION,
    -> internalFailureNotice()
}

private fun SshConnectFailure.toDeepDiagnosticProcessNotice(): DeepDiagnosticProcessNotice = when (this) {
    is SshConnectFailure.SecretUnavailable,
    is SshConnectFailure.SecretCorrupt,
    is SshConnectFailure.SecretStorageFailure,
    -> failureNotice(ManagementFailureKind.SECRET_UNAVAILABLE)
    is SshConnectFailure.Timeout -> failureNotice(ManagementFailureKind.TRANSPORT_TIMEOUT)
    is SshConnectFailure.Unreachable,
    is SshConnectFailure.NegotiationFailure,
    is SshConnectFailure.Unexpected,
    -> failureNotice(ManagementFailureKind.TRANSPORT_UNAVAILABLE)
    is SshConnectFailure.HostIdentityMismatch -> failureNotice(ManagementFailureKind.HOST_IDENTITY_MISMATCH)
    SshConnectFailure.AuthenticationRejected -> failureNotice(ManagementFailureKind.AUTHENTICATION_REJECTED)
    SshConnectFailure.Cancelled -> DeepDiagnosticProcessNotice.HostInterrupted
    is SshConnectFailure.InvalidConfiguration -> internalFailureNotice()
}

private fun failureNotice(failure: ManagementFailureKind): DeepDiagnosticProcessNotice =
    DeepDiagnosticProcessNotice.Failure(failure)

private fun internalFailureNotice(): DeepDiagnosticProcessNotice =
    failureNotice(ManagementFailureKind.INTERNAL_INVARIANT_FAILURE)
