package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.runtime.ServiceLogRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.UpdatePreflightRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.DatabaseBackupRuntimeResult
import com.velumtegra.xuimobile.core.runtime.InstallationBackupRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RestoreCheckRuntimeResult
import com.velumtegra.xuimobile.core.runtime.WorkingDatabaseRestoreRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RestoredPanelStartRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RestoreCompatibilityRuntimeResult
import com.velumtegra.xuimobile.core.model.DatabaseBackupFailure
import com.velumtegra.xuimobile.core.model.InstallationBackupFailure
import com.velumtegra.xuimobile.core.model.RestoreCheckFailure
import com.velumtegra.xuimobile.core.model.WorkingDatabaseRestoreFailure
import com.velumtegra.xuimobile.core.model.RestoredPanelStartFailure

import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.ExactReconnectResult
import com.velumtegra.xuimobile.core.runtime.ExactReconnectRetryPermit
import com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.DiscoveryRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.ExactRuntimeSessionCloseResult
import com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimePreparationResult
import com.velumtegra.xuimobile.core.runtime.ExistingInstallationRestartPreparationResult
import com.velumtegra.xuimobile.core.runtime.ExistingInstallationRestartRuntimeResult
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.ReconnectPreparationFailureKind
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.runtime.RetryDecision
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure

/**
 * Exact Android-host handoff from an already-admitted runtime binding into Phase 4.4C transport.
 *
 * The host cannot invent a RecoveryRuntimeAdmission, reconnect permit, target, access or credential.
 * It only carries opaque tokens produced by the admission/coordinator path. Each generation attempt
 * uses a host-captured connectivity observation that the coordinator must still accept as current,
 * and every retry remains bound to the exact one-shot permit returned by the coordinator.
 *
 * This bridge owns no policy and never accepts caller-supplied remote commands. It carries opaque
 * admission/session identities into the typed Discovery/Management/DeepDiagnostic consumers and,
 * in Phase 8.7, the separately gated Installer runtime consumer. Journal mutation/reconciliation
 * remains inside core:runtime; this bridge still never waits for connectivity or schedules a new
 * Android host, and bounded supersession remains owned by the live host sequence.
 */
internal class ExactOperationHostRuntimeTransportBridge(
    private val port: ExactOperationHostRuntimeTransportPort,
) {
    constructor(coordinator: OperationRuntimeCoordinator) : this(
        CoordinatorExactOperationHostRuntimeTransportPort(coordinator),
    )

    fun connectivitySnapshot(): ConnectivityObservation = port.connectivitySnapshot()

    suspend fun begin(
        binding: ExactOperationHostRuntimeBinding,
        budget: RetryBudget,
    ): ExactOperationHostTransportResult = begin(
        binding = binding,
        observation = connectivitySnapshot(),
        budget = budget,
    )

    suspend fun begin(
        binding: ExactOperationHostRuntimeBinding,
        observation: ConnectivityObservation,
        budget: RetryBudget,
    ): ExactOperationHostTransportResult {
        if (binding.operationId.value.isBlank()) {
            return ExactOperationHostTransportResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        return mapResult(
            expectedOperationId = binding.operationId,
            result = port.begin(binding.token, observation, budget),
        )
    }

    suspend fun retry(
        permit: ExactOperationHostReconnectRetryPermit,
    ): ExactOperationHostTransportResult {
        if (permit.operationId.value.isBlank()) {
            return ExactOperationHostTransportResult.ContractViolation(
                "Reconnect retry permit OperationId cannot be blank",
            )
        }
        return mapResult(
            expectedOperationId = permit.operationId,
            result = port.retry(permit.token),
        )
    }

    /**
     * Give an already-connected exact session to the typed read-only feature consumers.
     * The coordinator remains the authority for durable operation type/target and every consumer
     * returns a typed not-applicable result for operations outside its exact contract.
     */
    suspend fun executeDiscovery(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding,
    ): ExactOperationHostDiscoveryResult {
        if (runtimeBinding.operationId.value.isBlank()) {
            return ExactOperationHostDiscoveryResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        if (sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId)) {
            return ExactOperationHostDiscoveryResult.ContractViolation(
                "Discovery session belongs to a different OperationId",
            )
        }
        return port.executeDiscovery(runtimeBinding.token, sessionBinding).toHostDiscoveryResult()
    }

    suspend fun executeManagementQuickInspect(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding,
    ): ExactOperationHostManagementResult {
        if (runtimeBinding.operationId.value.isBlank()) {
            return ExactOperationHostManagementResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        if (sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId)) {
            return ExactOperationHostManagementResult.ContractViolation(
                "QUICK_INSPECT session belongs to a different OperationId",
            )
        }
        return port.executeManagementQuickInspect(runtimeBinding.token, sessionBinding).toHostManagementResult()
    }


    suspend fun executeDeepDiagnostic(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding,
    ): ExactOperationHostDeepDiagnosticResult {
        if (runtimeBinding.operationId.value.isBlank()) {
            return ExactOperationHostDeepDiagnosticResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        if (sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId)) {
            return ExactOperationHostDeepDiagnosticResult.ContractViolation(
                "DEEP_DIAGNOSTIC session belongs to a different OperationId",
            )
        }
        return port.executeDeepDiagnostic(runtimeBinding.token, sessionBinding).toHostDeepDiagnosticResult()
    }

    suspend fun executeServiceLogs(runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding): ServiceLogRuntimeExecutionResult {
        if (runtimeBinding.operationId.value.isBlank() || sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId))
            return ServiceLogRuntimeExecutionResult.ContractViolation("Service logs require exact operation owner")
        return port.executeServiceLogs(runtimeBinding.token, sessionBinding)
    }
    suspend fun executeUpdatePreflight(runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding): UpdatePreflightRuntimeExecutionResult {
        if (runtimeBinding.operationId.value.isBlank() || sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId))
            return UpdatePreflightRuntimeExecutionResult.ContractViolation("Update preflight require exact operation owner")
        return port.executeUpdatePreflight(runtimeBinding.token, sessionBinding)
    }

    suspend fun prepareDatabaseBackup(runtimeBinding: ExactOperationHostRuntimeBinding): DatabaseBackupRuntimeResult =
        if (runtimeBinding.operationId.value.isBlank()) DatabaseBackupRuntimeResult.Rejected(DatabaseBackupFailure.EXACT_TARGET)
        else port.prepareDatabaseBackup(runtimeBinding.token)
    suspend fun executeDatabaseBackup(runtimeBinding: ExactOperationHostRuntimeBinding, binding: SessionBinding): DatabaseBackupRuntimeResult =
        if (binding.owner != SessionOwner.Operation(runtimeBinding.operationId)) DatabaseBackupRuntimeResult.Rejected(DatabaseBackupFailure.EXACT_TARGET)
        else port.executeDatabaseBackup(runtimeBinding.token, binding)

    suspend fun prepareInstallationBackup(runtimeBinding: ExactOperationHostRuntimeBinding): InstallationBackupRuntimeResult =
        if (runtimeBinding.operationId.value.isBlank()) InstallationBackupRuntimeResult.Rejected(InstallationBackupFailure.EXACT_TARGET)
        else port.prepareInstallationBackup(runtimeBinding.token)
    suspend fun executeInstallationBackup(runtimeBinding: ExactOperationHostRuntimeBinding, binding: SessionBinding): InstallationBackupRuntimeResult =
        if (binding.owner != SessionOwner.Operation(runtimeBinding.operationId)) InstallationBackupRuntimeResult.Rejected(InstallationBackupFailure.EXACT_TARGET)
        else port.executeInstallationBackup(runtimeBinding.token, binding)
    suspend fun prepareRestoreCheck(runtimeBinding: ExactOperationHostRuntimeBinding): RestoreCheckRuntimeResult =
        if (runtimeBinding.operationId.value.isBlank()) RestoreCheckRuntimeResult.Rejected(RestoreCheckFailure.EXACT_TARGET)
        else port.prepareRestoreCheck(runtimeBinding.token)
    suspend fun executeRestoreCheck(runtimeBinding: ExactOperationHostRuntimeBinding, binding: SessionBinding): RestoreCheckRuntimeResult =
        if (binding.owner != SessionOwner.Operation(runtimeBinding.operationId)) RestoreCheckRuntimeResult.Rejected(RestoreCheckFailure.EXACT_TARGET)
        else port.executeRestoreCheck(runtimeBinding.token, binding)
    suspend fun prepareWorkingDatabaseRestore(runtimeBinding: ExactOperationHostRuntimeBinding): WorkingDatabaseRestoreRuntimeResult =
        if (runtimeBinding.operationId.value.isBlank()) WorkingDatabaseRestoreRuntimeResult.Rejected(WorkingDatabaseRestoreFailure.EXACT_TARGET)
        else port.prepareWorkingDatabaseRestore(runtimeBinding.token)
    suspend fun executeWorkingDatabaseRestore(runtimeBinding: ExactOperationHostRuntimeBinding, binding: SessionBinding): WorkingDatabaseRestoreRuntimeResult =
        if (binding.owner != SessionOwner.Operation(runtimeBinding.operationId)) WorkingDatabaseRestoreRuntimeResult.Rejected(WorkingDatabaseRestoreFailure.EXACT_TARGET)
        else port.executeWorkingDatabaseRestore(runtimeBinding.token, binding)
    suspend fun prepareRestoredPanelStart(runtimeBinding: ExactOperationHostRuntimeBinding): RestoredPanelStartRuntimeResult =
        if (runtimeBinding.operationId.value.isBlank()) RestoredPanelStartRuntimeResult.Rejected(RestoredPanelStartFailure.EXACT_TARGET)
        else port.prepareRestoredPanelStart(runtimeBinding.token)
    suspend fun executeRestoredPanelStart(runtimeBinding: ExactOperationHostRuntimeBinding, binding: SessionBinding): RestoredPanelStartRuntimeResult =
        if (binding.owner != SessionOwner.Operation(runtimeBinding.operationId)) RestoredPanelStartRuntimeResult.Rejected(RestoredPanelStartFailure.EXACT_TARGET)
        else port.executeRestoredPanelStart(runtimeBinding.token, binding)
    suspend fun prepareRestoreCompatibility(runtimeBinding: ExactOperationHostRuntimeBinding): RestoreCompatibilityRuntimeResult =
        if (runtimeBinding.operationId.value.isBlank()) RestoreCompatibilityRuntimeResult.Rejected(RestoreCheckFailure.EXACT_TARGET)
        else port.prepareRestoreCompatibility(runtimeBinding.token)
    suspend fun executeRestoreCompatibility(runtimeBinding: ExactOperationHostRuntimeBinding, binding: SessionBinding): RestoreCompatibilityRuntimeResult =
        if (binding.owner != SessionOwner.Operation(runtimeBinding.operationId)) RestoreCompatibilityRuntimeResult.Rejected(RestoreCheckFailure.EXACT_TARGET)
        else port.executeRestoreCompatibility(runtimeBinding.token, binding)

    suspend fun prepareRestart(runtimeBinding: ExactOperationHostRuntimeBinding): ExistingInstallationRestartPreparationResult {
        if (runtimeBinding.operationId.value.isBlank()) return ExistingInstallationRestartPreparationResult.ContractViolation("Blank OperationId")
        return port.prepareRestart(runtimeBinding.token)
    }
    suspend fun executeRestart(runtimeBinding: ExactOperationHostRuntimeBinding, sessionBinding: SessionBinding): ExistingInstallationRestartRuntimeResult {
        if (runtimeBinding.operationId.value.isBlank() || sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId))
            return ExistingInstallationRestartRuntimeResult.ContractViolation("Restart requires the exact operation-owned session")
        return port.executeRestart(runtimeBinding.token, sessionBinding)
    }

    /**
     * Local-only Installer preparation before transport. Non-Installer operations simply continue
     * through the existing read-only feature chain.
     */
    suspend fun prepareInstaller(
        runtimeBinding: ExactOperationHostRuntimeBinding,
    ): InstallerRuntimePreparationResult {
        if (runtimeBinding.operationId.value.isBlank()) {
            return InstallerRuntimePreparationResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        return port.prepareInstaller(runtimeBinding.token)
    }

    suspend fun executeInstaller(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding,
    ): InstallerRuntimeExecutionResult {
        if (runtimeBinding.operationId.value.isBlank()) {
            return InstallerRuntimeExecutionResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        if (sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId)) {
            return InstallerRuntimeExecutionResult.ContractViolation(
                "Installer session belongs to a different OperationId",
            )
        }
        return port.executeInstaller(runtimeBinding.token, sessionBinding)
    }

    /**
     * Close only the exact SessionId produced for this admitted host runtime.
     * A stale host cannot remove a replacement because the coordinator cleanup is SessionId-guarded.
     */
    fun closeSession(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        sessionBinding: SessionBinding,
    ): ExactOperationHostSessionCloseResult {
        if (runtimeBinding.operationId.value.isBlank()) {
            return ExactOperationHostSessionCloseResult.ContractViolation(
                "Runtime binding OperationId cannot be blank",
            )
        }
        if (sessionBinding.owner != SessionOwner.Operation(runtimeBinding.operationId)) {
            return ExactOperationHostSessionCloseResult.ContractViolation(
                "Session cleanup binding belongs to a different OperationId",
            )
        }
        return when (val result = port.closeSession(runtimeBinding.token, sessionBinding)) {
            ExactOperationHostSessionClosePortResult.Closed -> ExactOperationHostSessionCloseResult.Closed
            ExactOperationHostSessionClosePortResult.StaleOrAlreadyClosed ->
                ExactOperationHostSessionCloseResult.StaleOrAlreadyClosed
            is ExactOperationHostSessionClosePortResult.ContractViolation ->
                ExactOperationHostSessionCloseResult.ContractViolation(result.reason)
        }
    }

    private fun mapResult(
        expectedOperationId: OperationId,
        result: ExactOperationHostTransportPortResult,
    ): ExactOperationHostTransportResult = when (result) {
        is ExactOperationHostTransportPortResult.Connected ->
            ExactOperationHostTransportResult.Connected(
                binding = result.binding,
                attemptNumber = result.attemptNumber,
                installation = result.installation,
            )

        ExactOperationHostTransportPortResult.WaitForNetwork ->
            ExactOperationHostTransportResult.WaitForNetwork

        ExactOperationHostTransportPortResult.StaleConnectivityGeneration ->
            ExactOperationHostTransportResult.StaleConnectivityGeneration

        ExactOperationHostTransportPortResult.AlreadyScheduledForGeneration ->
            ExactOperationHostTransportResult.AlreadyScheduledForGeneration

        ExactOperationHostTransportPortResult.AdmissionLost ->
            ExactOperationHostTransportResult.AdmissionLost

        ExactOperationHostTransportPortResult.RetryPermitAlreadyConsumed ->
            ExactOperationHostTransportResult.RetryPermitAlreadyConsumed

        is ExactOperationHostTransportPortResult.RecoveryBlocked ->
            ExactOperationHostTransportResult.RecoveryBlocked(
                reason = result.reason,
                transportFailure = result.transportFailure,
            )

        is ExactOperationHostTransportPortResult.PreparationFailed ->
            ExactOperationHostTransportResult.PreparationFailed(
                kind = result.kind,
                reason = result.reason,
            )

        is ExactOperationHostTransportPortResult.RetryPermitted -> {
            if (result.operationId != expectedOperationId) {
                ExactOperationHostTransportResult.ContractViolation(
                    "Reconnect retry permit belongs to a different OperationId",
                )
            } else {
                ExactOperationHostTransportResult.RetryPermitted(
                    failure = result.failure,
                    permit = ExactOperationHostReconnectRetryPermit(
                        operationId = result.operationId,
                        generation = result.generation,
                        nextAttemptNumber = result.nextAttemptNumber,
                        token = result.token,
                    ),
                )
            }
        }

        is ExactOperationHostTransportPortResult.Failed ->
            ExactOperationHostTransportResult.Failed(
                failure = result.failure,
                retryDecision = result.retryDecision,
            )
    }
}

internal data class ExactOperationHostReconnectRetryPermit(
    val operationId: OperationId,
    val generation: Long,
    val nextAttemptNumber: Int,
    internal val token: ExactOperationHostReconnectRetryToken,
) {
    init {
        require(operationId.value.isNotBlank()) { "OperationId cannot be blank" }
        require(generation >= 0L) { "Connectivity generation cannot be negative" }
        require(nextAttemptNumber > 1) { "Retry permit must represent an attempt after the initial attempt" }
    }
}

internal sealed interface ExactOperationHostTransportResult {
    data class Connected(
        val binding: SessionBinding,
        val attemptNumber: Int,
        val installation: SessionInstallResult,
    ) : ExactOperationHostTransportResult

    data object WaitForNetwork : ExactOperationHostTransportResult
    data object StaleConnectivityGeneration : ExactOperationHostTransportResult
    data object AlreadyScheduledForGeneration : ExactOperationHostTransportResult
    data object AdmissionLost : ExactOperationHostTransportResult
    data object RetryPermitAlreadyConsumed : ExactOperationHostTransportResult

    data class RecoveryBlocked(
        val reason: RecoveryBlockReason,
        val transportFailure: SshConnectFailure? = null,
    ) : ExactOperationHostTransportResult

    data class PreparationFailed(
        val kind: ReconnectPreparationFailureKind,
        val reason: String,
    ) : ExactOperationHostTransportResult

    data class RetryPermitted(
        val failure: SshConnectFailure,
        val permit: ExactOperationHostReconnectRetryPermit,
    ) : ExactOperationHostTransportResult

    data class Failed(
        val failure: SshConnectFailure,
        val retryDecision: RetryDecision.Denied,
    ) : ExactOperationHostTransportResult

    data class ContractViolation(val reason: String) : ExactOperationHostTransportResult
}

internal sealed interface ExactOperationHostDiscoveryResult {
    data class Completed(val result: com.velumtegra.xuimobile.core.model.DiscoveryResult) : ExactOperationHostDiscoveryResult
    data class NotDiscoveryOperation(val operationType: com.velumtegra.xuimobile.core.model.OperationType) : ExactOperationHostDiscoveryResult
    data object AdmissionLost : ExactOperationHostDiscoveryResult
    data object SessionUnavailable : ExactOperationHostDiscoveryResult
    data class StaleSession(val expected: com.velumtegra.xuimobile.core.model.SessionId, val actual: com.velumtegra.xuimobile.core.model.SessionId?) : ExactOperationHostDiscoveryResult
    data class StalePlan(val expectedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision, val actualRevision: com.velumtegra.xuimobile.core.domain.OperationRevision) : ExactOperationHostDiscoveryResult
    data class Failed(val failure: com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapFailure) : ExactOperationHostDiscoveryResult
    data class ContractViolation(val reason: String) : ExactOperationHostDiscoveryResult
}

private fun DiscoveryRuntimeExecutionResult.toHostDiscoveryResult(): ExactOperationHostDiscoveryResult = when (this) {
    is DiscoveryRuntimeExecutionResult.Completed -> ExactOperationHostDiscoveryResult.Completed(result)
    is DiscoveryRuntimeExecutionResult.NotDiscoveryOperation -> ExactOperationHostDiscoveryResult.NotDiscoveryOperation(operationType)
    DiscoveryRuntimeExecutionResult.AdmissionLost -> ExactOperationHostDiscoveryResult.AdmissionLost
    DiscoveryRuntimeExecutionResult.SessionUnavailable -> ExactOperationHostDiscoveryResult.SessionUnavailable
    is DiscoveryRuntimeExecutionResult.StaleSession -> ExactOperationHostDiscoveryResult.StaleSession(expectedSessionId, actualSessionId)
    is DiscoveryRuntimeExecutionResult.StalePlan -> ExactOperationHostDiscoveryResult.StalePlan(expectedRevision, actualRevision)
    is DiscoveryRuntimeExecutionResult.Failed -> ExactOperationHostDiscoveryResult.Failed(failure)
    is DiscoveryRuntimeExecutionResult.ContractViolation -> ExactOperationHostDiscoveryResult.ContractViolation(reason)
}

internal sealed interface ExactOperationHostSessionCloseResult {
    data object Closed : ExactOperationHostSessionCloseResult
    data object StaleOrAlreadyClosed : ExactOperationHostSessionCloseResult
    data class ContractViolation(val reason: String) : ExactOperationHostSessionCloseResult
}

internal sealed interface ExactOperationHostSessionClosePortResult {
    data object Closed : ExactOperationHostSessionClosePortResult
    data object StaleOrAlreadyClosed : ExactOperationHostSessionClosePortResult
    data class ContractViolation(val reason: String) : ExactOperationHostSessionClosePortResult
}

internal interface ExactOperationHostReconnectRetryToken

internal interface ExactOperationHostRuntimeTransportPort {
    fun connectivitySnapshot(): ConnectivityObservation

    suspend fun begin(
        runtimeToken: ExactOperationHostRuntimeToken,
        observation: ConnectivityObservation,
        budget: RetryBudget,
    ): ExactOperationHostTransportPortResult

    suspend fun retry(
        retryToken: ExactOperationHostReconnectRetryToken,
    ): ExactOperationHostTransportPortResult

    suspend fun executeDiscovery(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): DiscoveryRuntimeExecutionResult

    suspend fun executeManagementQuickInspect(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): ManagementRuntimeExecutionResult

    suspend fun executeDeepDiagnostic(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): DeepDiagnosticRuntimeExecutionResult

    suspend fun executeServiceLogs(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): ServiceLogRuntimeExecutionResult =
        ServiceLogRuntimeExecutionResult.NotServiceLogOperation

    suspend fun executeUpdatePreflight(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): UpdatePreflightRuntimeExecutionResult =
        UpdatePreflightRuntimeExecutionResult.NotUpdatePreflightOperation

    suspend fun prepareDatabaseBackup(runtimeToken: ExactOperationHostRuntimeToken): DatabaseBackupRuntimeResult =
        DatabaseBackupRuntimeResult.NotDatabaseBackupOperation
    suspend fun executeDatabaseBackup(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): DatabaseBackupRuntimeResult =
        DatabaseBackupRuntimeResult.NotDatabaseBackupOperation

    suspend fun prepareInstallationBackup(runtimeToken: ExactOperationHostRuntimeToken): InstallationBackupRuntimeResult =
        InstallationBackupRuntimeResult.NotInstallationBackupOperation
    suspend fun executeInstallationBackup(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): InstallationBackupRuntimeResult =
        InstallationBackupRuntimeResult.NotInstallationBackupOperation
    suspend fun prepareRestoreCheck(runtimeToken: ExactOperationHostRuntimeToken): RestoreCheckRuntimeResult =
        RestoreCheckRuntimeResult.NotRestoreCheckOperation
    suspend fun executeRestoreCheck(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): RestoreCheckRuntimeResult =
        RestoreCheckRuntimeResult.NotRestoreCheckOperation
    suspend fun prepareWorkingDatabaseRestore(runtimeToken: ExactOperationHostRuntimeToken): WorkingDatabaseRestoreRuntimeResult =
        WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation
    suspend fun executeWorkingDatabaseRestore(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): WorkingDatabaseRestoreRuntimeResult =
        WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation
    suspend fun prepareRestoredPanelStart(runtimeToken: ExactOperationHostRuntimeToken): RestoredPanelStartRuntimeResult =
        RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation
    suspend fun executeRestoredPanelStart(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): RestoredPanelStartRuntimeResult =
        RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation
    suspend fun prepareRestoreCompatibility(runtimeToken: ExactOperationHostRuntimeToken): RestoreCompatibilityRuntimeResult =
        RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation
    suspend fun executeRestoreCompatibility(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): RestoreCompatibilityRuntimeResult =
        RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation

    suspend fun prepareInstaller(
        runtimeToken: ExactOperationHostRuntimeToken,
    ): InstallerRuntimePreparationResult = InstallerRuntimePreparationResult.NotInstallerOperation

    suspend fun executeInstaller(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): InstallerRuntimeExecutionResult = InstallerRuntimeExecutionResult.NotInstallerOperation

    suspend fun prepareRestart(runtimeToken: ExactOperationHostRuntimeToken): ExistingInstallationRestartPreparationResult =
        ExistingInstallationRestartPreparationResult.NotRestartOperation
    suspend fun executeRestart(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): ExistingInstallationRestartRuntimeResult =
        ExistingInstallationRestartRuntimeResult.NotRestartOperation

    fun closeSession(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): ExactOperationHostSessionClosePortResult
}

internal sealed interface ExactOperationHostTransportPortResult {
    data class Connected(
        val binding: SessionBinding,
        val attemptNumber: Int,
        val installation: SessionInstallResult,
    ) : ExactOperationHostTransportPortResult

    data object WaitForNetwork : ExactOperationHostTransportPortResult
    data object StaleConnectivityGeneration : ExactOperationHostTransportPortResult
    data object AlreadyScheduledForGeneration : ExactOperationHostTransportPortResult
    data object AdmissionLost : ExactOperationHostTransportPortResult
    data object RetryPermitAlreadyConsumed : ExactOperationHostTransportPortResult

    data class RecoveryBlocked(
        val reason: RecoveryBlockReason,
        val transportFailure: SshConnectFailure? = null,
    ) : ExactOperationHostTransportPortResult

    data class PreparationFailed(
        val kind: ReconnectPreparationFailureKind,
        val reason: String,
    ) : ExactOperationHostTransportPortResult

    data class RetryPermitted(
        val failure: SshConnectFailure,
        val operationId: OperationId,
        val generation: Long,
        val nextAttemptNumber: Int,
        val token: ExactOperationHostReconnectRetryToken,
    ) : ExactOperationHostTransportPortResult

    data class Failed(
        val failure: SshConnectFailure,
        val retryDecision: RetryDecision.Denied,
    ) : ExactOperationHostTransportPortResult
}

private data class CoordinatorReconnectRetryToken(
    val permit: ExactReconnectRetryPermit,
) : ExactOperationHostReconnectRetryToken

private class CoordinatorExactOperationHostRuntimeTransportPort(
    private val coordinator: OperationRuntimeCoordinator,
) : ExactOperationHostRuntimeTransportPort {
    override fun connectivitySnapshot(): ConnectivityObservation = coordinator.connectivitySnapshot()
    override suspend fun prepareRestart(runtimeToken: ExactOperationHostRuntimeToken): ExistingInstallationRestartPreparationResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareExistingInstallationRestartTransport(runtimeToken.admission)
    }
    override suspend fun executeRestart(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): ExistingInstallationRestartRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeExistingInstallationRestart(runtimeToken.admission, binding)
    }

    override suspend fun begin(
        runtimeToken: ExactOperationHostRuntimeToken,
        observation: ConnectivityObservation,
        budget: RetryBudget,
    ): ExactOperationHostTransportPortResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return coordinator.beginReconnect(
            admission = runtimeToken.admission,
            observation = observation,
            budget = budget,
        ).toHostPortResult()
    }

    override suspend fun retry(
        retryToken: ExactOperationHostReconnectRetryToken,
    ): ExactOperationHostTransportPortResult {
        require(retryToken is CoordinatorReconnectRetryToken) {
            "Reconnect retry token did not originate from coordinator transport port"
        }
        return coordinator.retryReconnect(retryToken.permit).toHostPortResult()
    }

    override suspend fun executeDiscovery(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): DiscoveryRuntimeExecutionResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return coordinator.executeDiscovery(runtimeToken.admission, binding)
    }

    override suspend fun executeManagementQuickInspect(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): ManagementRuntimeExecutionResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return coordinator.executeManagementQuickInspect(runtimeToken.admission, binding)
    }

    override suspend fun executeDeepDiagnostic(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): DeepDiagnosticRuntimeExecutionResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return coordinator.executeDeepDiagnostic(runtimeToken.admission, binding)
    }

    override suspend fun executeServiceLogs(runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding): ServiceLogRuntimeExecutionResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeServiceLogs(runtimeToken.admission, binding)
    }
    override suspend fun executeUpdatePreflight(runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding): UpdatePreflightRuntimeExecutionResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeUpdatePreflight(runtimeToken.admission, binding)
    }

    override suspend fun prepareDatabaseBackup(runtimeToken: ExactOperationHostRuntimeToken): DatabaseBackupRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareDatabaseBackup(runtimeToken.admission)
    }
    override suspend fun executeDatabaseBackup(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): DatabaseBackupRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeDatabaseBackup(runtimeToken.admission, binding)
    }

    override suspend fun prepareInstallationBackup(runtimeToken: ExactOperationHostRuntimeToken): InstallationBackupRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareInstallationBackup(runtimeToken.admission)
    }
    override suspend fun executeInstallationBackup(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): InstallationBackupRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeInstallationBackup(runtimeToken.admission, binding)
    }
    override suspend fun prepareRestoreCheck(runtimeToken: ExactOperationHostRuntimeToken): RestoreCheckRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareRestoreCheck(runtimeToken.admission)
    }
    override suspend fun executeRestoreCheck(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): RestoreCheckRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeRestoreCheck(runtimeToken.admission, binding)
    }
    override suspend fun prepareWorkingDatabaseRestore(runtimeToken: ExactOperationHostRuntimeToken): WorkingDatabaseRestoreRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareWorkingDatabaseRestore(runtimeToken.admission)
    }
    override suspend fun executeWorkingDatabaseRestore(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): WorkingDatabaseRestoreRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeWorkingDatabaseRestore(runtimeToken.admission, binding)
    }
    override suspend fun prepareRestoredPanelStart(runtimeToken: ExactOperationHostRuntimeToken): RestoredPanelStartRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareRestoredPanelStart(runtimeToken.admission)
    }
    override suspend fun executeRestoredPanelStart(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): RestoredPanelStartRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeRestoredPanelStart(runtimeToken.admission, binding)
    }
    override suspend fun prepareRestoreCompatibility(runtimeToken: ExactOperationHostRuntimeToken): RestoreCompatibilityRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.prepareRestoreCompatibility(runtimeToken.admission)
    }
    override suspend fun executeRestoreCompatibility(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): RestoreCompatibilityRuntimeResult {
        require(runtimeToken is CoordinatorAdmissionToken)
        return coordinator.executeRestoreCompatibility(runtimeToken.admission, binding)
    }

    override suspend fun prepareInstaller(
        runtimeToken: ExactOperationHostRuntimeToken,
    ): InstallerRuntimePreparationResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return coordinator.prepareInstallerTransport(runtimeToken.admission)
    }

    override suspend fun executeInstaller(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): InstallerRuntimeExecutionResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return coordinator.executeInstaller(runtimeToken.admission, binding)
    }

    override fun closeSession(
        runtimeToken: ExactOperationHostRuntimeToken,
        binding: SessionBinding,
    ): ExactOperationHostSessionClosePortResult {
        require(runtimeToken is CoordinatorAdmissionToken) {
            "Runtime token did not originate from coordinator admission port"
        }
        return when (val result = coordinator.closeExactSession(runtimeToken.admission, binding)) {
            ExactRuntimeSessionCloseResult.Closed -> ExactOperationHostSessionClosePortResult.Closed
            ExactRuntimeSessionCloseResult.StaleOrAlreadyClosed ->
                ExactOperationHostSessionClosePortResult.StaleOrAlreadyClosed
            is ExactRuntimeSessionCloseResult.ContractViolation ->
                ExactOperationHostSessionClosePortResult.ContractViolation(result.reason)
        }
    }

    private fun ExactReconnectResult.toHostPortResult(): ExactOperationHostTransportPortResult = when (this) {
        is ExactReconnectResult.Connected -> ExactOperationHostTransportPortResult.Connected(
            binding = binding,
            attemptNumber = attemptNumber,
            installation = installation,
        )

        ExactReconnectResult.WaitForNetwork -> ExactOperationHostTransportPortResult.WaitForNetwork
        ExactReconnectResult.StaleConnectivityGeneration ->
            ExactOperationHostTransportPortResult.StaleConnectivityGeneration
        ExactReconnectResult.AlreadyScheduledForGeneration ->
            ExactOperationHostTransportPortResult.AlreadyScheduledForGeneration
        ExactReconnectResult.AdmissionLost -> ExactOperationHostTransportPortResult.AdmissionLost
        ExactReconnectResult.RetryPermitAlreadyConsumed ->
            ExactOperationHostTransportPortResult.RetryPermitAlreadyConsumed

        is ExactReconnectResult.RecoveryBlocked -> ExactOperationHostTransportPortResult.RecoveryBlocked(
            reason = reason,
            transportFailure = transportFailure,
        )

        is ExactReconnectResult.PreparationFailed -> ExactOperationHostTransportPortResult.PreparationFailed(
            kind = kind,
            reason = reason,
        )

        is ExactReconnectResult.RetryPermitted -> ExactOperationHostTransportPortResult.RetryPermitted(
            failure = failure,
            operationId = permit.operationId,
            generation = permit.generation,
            nextAttemptNumber = permit.nextAttemptNumber,
            token = CoordinatorReconnectRetryToken(permit),
        )

        is ExactReconnectResult.Failed -> ExactOperationHostTransportPortResult.Failed(
            failure = failure,
            retryDecision = retryDecision,
        )
    }
}

internal sealed interface ExactOperationHostManagementResult {
    data class Completed(
        val snapshot: com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot,
        val committedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
    ) : ExactOperationHostManagementResult
    data class ReadbackFailed(
        val kind: com.velumtegra.xuimobile.core.model.ManagementFailureKind,
        val committedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
    ) : ExactOperationHostManagementResult
    data class NotQuickInspectOperation(val operationType: com.velumtegra.xuimobile.core.model.OperationType) : ExactOperationHostManagementResult
    data object AdmissionLost : ExactOperationHostManagementResult
    data object SessionUnavailable : ExactOperationHostManagementResult
    data class StaleSession(val expected: com.velumtegra.xuimobile.core.model.SessionId, val actual: com.velumtegra.xuimobile.core.model.SessionId?) : ExactOperationHostManagementResult
    data class StalePlan(val expectedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision, val actualRevision: com.velumtegra.xuimobile.core.domain.OperationRevision) : ExactOperationHostManagementResult
    data class Failed(val failure: com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapFailure) : ExactOperationHostManagementResult
    data class ContractViolation(val reason: String) : ExactOperationHostManagementResult
}

private fun ManagementRuntimeExecutionResult.toHostManagementResult(): ExactOperationHostManagementResult = when (this) {
    is ManagementRuntimeExecutionResult.Completed -> ExactOperationHostManagementResult.Completed(snapshot, committedRevision)
    is ManagementRuntimeExecutionResult.ReadbackFailed -> ExactOperationHostManagementResult.ReadbackFailed(kind, committedRevision)
    is ManagementRuntimeExecutionResult.NotQuickInspectOperation -> ExactOperationHostManagementResult.NotQuickInspectOperation(operationType)
    ManagementRuntimeExecutionResult.AdmissionLost -> ExactOperationHostManagementResult.AdmissionLost
    ManagementRuntimeExecutionResult.SessionUnavailable -> ExactOperationHostManagementResult.SessionUnavailable
    is ManagementRuntimeExecutionResult.StaleSession -> ExactOperationHostManagementResult.StaleSession(expectedSessionId, actualSessionId)
    is ManagementRuntimeExecutionResult.StalePlan -> ExactOperationHostManagementResult.StalePlan(expectedRevision, actualRevision)
    is ManagementRuntimeExecutionResult.Failed -> ExactOperationHostManagementResult.Failed(failure)
    is ManagementRuntimeExecutionResult.ContractViolation -> ExactOperationHostManagementResult.ContractViolation(reason)
}

internal sealed interface ExactOperationHostDeepDiagnosticResult {
    data class Completed(
        val snapshot: com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot,
        val committedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
    ) : ExactOperationHostDeepDiagnosticResult
    data class ReadbackFailed(
        val kind: com.velumtegra.xuimobile.core.model.ManagementFailureKind,
        val committedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
    ) : ExactOperationHostDeepDiagnosticResult
    data class NotDeepDiagnosticOperation(
        val operationType: com.velumtegra.xuimobile.core.model.OperationType,
    ) : ExactOperationHostDeepDiagnosticResult
    data object AdmissionLost : ExactOperationHostDeepDiagnosticResult
    data object SessionUnavailable : ExactOperationHostDeepDiagnosticResult
    data class StaleSession(
        val expected: com.velumtegra.xuimobile.core.model.SessionId,
        val actual: com.velumtegra.xuimobile.core.model.SessionId?,
    ) : ExactOperationHostDeepDiagnosticResult
    data class StalePlan(
        val expectedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
        val actualRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
    ) : ExactOperationHostDeepDiagnosticResult
    data class Failed(
        val failure: com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapFailure,
    ) : ExactOperationHostDeepDiagnosticResult
    data class ContractViolation(val reason: String) : ExactOperationHostDeepDiagnosticResult
}

private fun DeepDiagnosticRuntimeExecutionResult.toHostDeepDiagnosticResult(): ExactOperationHostDeepDiagnosticResult = when (this) {
    is DeepDiagnosticRuntimeExecutionResult.Completed -> ExactOperationHostDeepDiagnosticResult.Completed(snapshot, committedRevision)
    is DeepDiagnosticRuntimeExecutionResult.ReadbackFailed -> ExactOperationHostDeepDiagnosticResult.ReadbackFailed(kind, committedRevision)
    is DeepDiagnosticRuntimeExecutionResult.NotDeepDiagnosticOperation -> ExactOperationHostDeepDiagnosticResult.NotDeepDiagnosticOperation(operationType)
    DeepDiagnosticRuntimeExecutionResult.AdmissionLost -> ExactOperationHostDeepDiagnosticResult.AdmissionLost
    DeepDiagnosticRuntimeExecutionResult.SessionUnavailable -> ExactOperationHostDeepDiagnosticResult.SessionUnavailable
    is DeepDiagnosticRuntimeExecutionResult.StaleSession -> ExactOperationHostDeepDiagnosticResult.StaleSession(expectedSessionId, actualSessionId)
    is DeepDiagnosticRuntimeExecutionResult.StalePlan -> ExactOperationHostDeepDiagnosticResult.StalePlan(expectedRevision, actualRevision)
    is DeepDiagnosticRuntimeExecutionResult.Failed -> ExactOperationHostDeepDiagnosticResult.Failed(failure)
    is DeepDiagnosticRuntimeExecutionResult.ContractViolation -> ExactOperationHostDeepDiagnosticResult.ContractViolation(reason)
}

