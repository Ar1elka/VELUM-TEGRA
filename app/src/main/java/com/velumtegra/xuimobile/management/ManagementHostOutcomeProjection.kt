package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.ManagementFailureKind
import com.velumtegra.xuimobile.core.runtime.ReconnectPreparationFailureKind
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.runtime.ExactOperationHostManagementResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequenceResult

internal fun ExactOperationHostRuntimeBindResult.toManagementProcessNotice(): ManagementProcessNotice? = when (this) {
    is ExactOperationHostRuntimeBindResult.Bound -> null
    ExactOperationHostRuntimeBindResult.InvalidOperationId -> internalFailureNotice()
    is ExactOperationHostRuntimeBindResult.OperationNotNonTerminal -> ManagementProcessNotice.NotExecutable
    is ExactOperationHostRuntimeBindResult.DurableEvidenceUnavailable,
    is ExactOperationHostRuntimeBindResult.BootstrapFailed,
    is ExactOperationHostRuntimeBindResult.AdmissionFailed,
    -> ManagementProcessNotice.DurableStateUnavailable
    is ExactOperationHostRuntimeBindResult.NotExecutable -> ManagementProcessNotice.NotExecutable
    ExactOperationHostRuntimeBindResult.AlreadyOwned -> ManagementProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.StalePlan -> ManagementProcessNotice.BusyOrSuperseded
    is ExactOperationHostRuntimeBindResult.ContractViolation -> internalFailureNotice()
}

internal fun ExactOperationHostTransportSequenceResult.toManagementProcessNotice(): ManagementProcessNotice? = when (this) {
    is ExactOperationHostTransportSequenceResult.ManagementCompleted -> null
    is ExactOperationHostTransportSequenceResult.ManagementEnded -> management.toManagementProcessNotice()
    is ExactOperationHostTransportSequenceResult.Ended -> transportResult.toManagementProcessNotice()
    is ExactOperationHostTransportSequenceResult.DiscoveryCompleted,
    is ExactOperationHostTransportSequenceResult.DiscoveryEnded,
    is ExactOperationHostTransportSequenceResult.ServiceLogsEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.UpdatePreflightEnded -> internalFailureNotice()
    is ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted,
    is ExactOperationHostTransportSequenceResult.DeepDiagnosticEnded,
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

private fun ExactOperationHostManagementResult.toManagementProcessNotice(): ManagementProcessNotice? = when (this) {
    is ExactOperationHostManagementResult.Completed -> null
    is ExactOperationHostManagementResult.ReadbackFailed -> null // terminal detail is published separately
    is ExactOperationHostManagementResult.NotQuickInspectOperation -> internalFailureNotice()
    ExactOperationHostManagementResult.AdmissionLost -> ManagementProcessNotice.BusyOrSuperseded
    ExactOperationHostManagementResult.SessionUnavailable -> ManagementProcessNotice.BusyOrSuperseded
    is ExactOperationHostManagementResult.StaleSession -> ManagementProcessNotice.BusyOrSuperseded
    is ExactOperationHostManagementResult.StalePlan -> ManagementProcessNotice.BusyOrSuperseded
    is ExactOperationHostManagementResult.Failed -> ManagementProcessNotice.DurableStateUnavailable
    is ExactOperationHostManagementResult.ContractViolation -> internalFailureNotice()
}

private fun ExactOperationHostTransportResult.toManagementProcessNotice(): ManagementProcessNotice = when (this) {
    is ExactOperationHostTransportResult.Connected -> internalFailureNotice()
    ExactOperationHostTransportResult.WaitForNetwork -> ManagementProcessNotice.WaitingForNetwork
    ExactOperationHostTransportResult.StaleConnectivityGeneration,
    ExactOperationHostTransportResult.AlreadyScheduledForGeneration,
    ExactOperationHostTransportResult.AdmissionLost,
    ExactOperationHostTransportResult.RetryPermitAlreadyConsumed,
    -> ManagementProcessNotice.BusyOrSuperseded
    is ExactOperationHostTransportResult.RecoveryBlocked -> reason.toManagementProcessNotice()
    is ExactOperationHostTransportResult.PreparationFailed -> kind.toManagementProcessNotice()
    is ExactOperationHostTransportResult.RetryPermitted -> internalFailureNotice()
    is ExactOperationHostTransportResult.Failed -> failure.toManagementProcessNotice()
    is ExactOperationHostTransportResult.ContractViolation -> internalFailureNotice()
}

private fun RecoveryBlockReason.toManagementProcessNotice(): ManagementProcessNotice = when (this) {
    RecoveryBlockReason.EXACT_ACCESS_MISSING -> failureNotice(ManagementFailureKind.EXACT_ACCESS_UNAVAILABLE)
    RecoveryBlockReason.REQUIRED_SECRET_MISSING -> failureNotice(ManagementFailureKind.SECRET_UNAVAILABLE)
    RecoveryBlockReason.HOST_IDENTITY_MISMATCH -> failureNotice(ManagementFailureKind.HOST_IDENTITY_MISMATCH)
    RecoveryBlockReason.AUTHENTICATION_REJECTED -> failureNotice(ManagementFailureKind.AUTHENTICATION_REJECTED)
    RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT -> ManagementProcessNotice.DurableStateUnavailable
}

private fun ReconnectPreparationFailureKind.toManagementProcessNotice(): ManagementProcessNotice = when (this) {
    ReconnectPreparationFailureKind.ACCESS_STORAGE_FAILURE ->
        failureNotice(ManagementFailureKind.EXACT_ACCESS_UNAVAILABLE)
    ReconnectPreparationFailureKind.ACCESS_CORRUPTION,
    ReconnectPreparationFailureKind.ACCESS_CONTRACT_VIOLATION,
    ReconnectPreparationFailureKind.TRANSPORT_CONTRACT_VIOLATION,
    ReconnectPreparationFailureKind.SESSION_ID_COLLISION,
    -> internalFailureNotice()
}

private fun SshConnectFailure.toManagementProcessNotice(): ManagementProcessNotice = when (this) {
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
    SshConnectFailure.Cancelled -> ManagementProcessNotice.HostInterrupted
    is SshConnectFailure.InvalidConfiguration -> internalFailureNotice()
}

private fun failureNotice(failure: ManagementFailureKind): ManagementProcessNotice =
    ManagementProcessNotice.Failure(failure)

private fun internalFailureNotice(): ManagementProcessNotice =
    failureNotice(ManagementFailureKind.INTERNAL_INVARIANT_FAILURE)
