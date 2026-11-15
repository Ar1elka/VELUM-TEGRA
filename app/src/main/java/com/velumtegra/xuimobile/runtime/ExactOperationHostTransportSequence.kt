package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.runtime.ServiceLogRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.UpdatePreflightRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.DatabaseBackupRuntimeResult
import com.velumtegra.xuimobile.core.runtime.InstallationBackupRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RestoreCheckRuntimeResult
import com.velumtegra.xuimobile.core.runtime.WorkingDatabaseRestoreRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RestoredPanelStartRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RestoreCompatibilityRuntimeResult
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimePreparationResult
import com.velumtegra.xuimobile.core.runtime.ExistingInstallationRestartPreparationResult
import com.velumtegra.xuimobile.core.runtime.ExistingInstallationRestartRuntimeResult
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult

/**
 * Bounded exact-host transport plus typed read-only feature consumption.
 *
 * Transport establishment remains owned by Phase 4. Once connected, the same exact operation-owned
 * SessionId may be offered in order to Discovery, QUICK_INSPECT, DEEP_DIAGNOSTIC and Installer
 * consumers and exact RESTART. Mutation consumers require process-local fresh
 * authority + durable/process mutation barriers inside core:runtime. Unsafe mutation recovery is
 * read-only only. The exact SessionId is always closed before the host returns.
 *
 * Retry continuations are consumed only when the coordinator explicitly returns an opaque permit.
 * Host-side guards also require monotonically increasing attempt numbers, one stable connectivity
 * generation per retry chain and the caller's finite [RetryBudget], so a malformed port cannot create
 * a tight loop. A live host may additionally continue across only a caller-bounded number of already
 * observed newer connectivity generations; it never waits here for a future network callback.
 */
internal class ExactOperationHostTransportSequence(
    private val bridge: ExactOperationHostRuntimeTransportBridge,
) {
    suspend fun run(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        budget: RetryBudget,
        maxConnectivityGenerations: Int = 1,
    ): ExactOperationHostTransportSequenceResult {
        require(maxConnectivityGenerations > 0) {
            "Host connectivity generation budget must be positive"
        }

        when (val comparison = bridge.prepareRestoreCompatibility(runtimeBinding)) {
            RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation, RestoreCompatibilityRuntimeResult.TransportRequired -> Unit
            else -> return ExactOperationHostTransportSequenceResult.RestoreCompatibilityPrepared(comparison)
        }
        when (val restoredStart = bridge.prepareRestoredPanelStart(runtimeBinding)) {
            RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation, RestoredPanelStartRuntimeResult.TransportRequired -> Unit
            else -> return ExactOperationHostTransportSequenceResult.RestoredPanelStartPrepared(restoredStart)
        }
        when (val workingRestore = bridge.prepareWorkingDatabaseRestore(runtimeBinding)) {
            WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation, WorkingDatabaseRestoreRuntimeResult.TransportRequired -> Unit
            else -> return ExactOperationHostTransportSequenceResult.WorkingDatabaseRestorePrepared(workingRestore)
        }
        when (val restore = bridge.prepareRestoreCheck(runtimeBinding)) {
            RestoreCheckRuntimeResult.NotRestoreCheckOperation, RestoreCheckRuntimeResult.TransportRequired -> Unit
            else -> return ExactOperationHostTransportSequenceResult.RestoreCheckPrepared(restore)
        }
        when (val archive = bridge.prepareInstallationBackup(runtimeBinding)) {
            InstallationBackupRuntimeResult.NotInstallationBackupOperation, InstallationBackupRuntimeResult.TransportRequired -> Unit
            else -> return ExactOperationHostTransportSequenceResult.InstallationBackupPrepared(archive)
        }
        when (val backup = bridge.prepareDatabaseBackup(runtimeBinding)) {
            DatabaseBackupRuntimeResult.NotDatabaseBackupOperation, DatabaseBackupRuntimeResult.TransportRequired -> Unit
            else -> return ExactOperationHostTransportSequenceResult.DatabaseBackupPrepared(backup)
        }
        when (val installerPreparation = bridge.prepareInstaller(runtimeBinding)) {
            InstallerRuntimePreparationResult.NotInstallerOperation,
            InstallerRuntimePreparationResult.TransportRequired,
            -> Unit

            else -> return ExactOperationHostTransportSequenceResult.InstallerPrepared(installerPreparation)
        }

        when (val restart = bridge.prepareRestart(runtimeBinding)) {
            ExistingInstallationRestartPreparationResult.NotRestartOperation,
            ExistingInstallationRestartPreparationResult.TransportRequired,
            -> Unit
            else -> return ExactOperationHostTransportSequenceResult.RestartPrepared(restart)
        }
        var observation = bridge.connectivitySnapshot()
        var generationsStarted = 0

        while (true) {
            generationsStarted += 1
            val result = runGeneration(
                runtimeBinding = runtimeBinding,
                budget = budget,
                observation = observation,
            )

            if (!result.mayContinueOnNewerConnectivity()) {
                return result
            }
            if (generationsStarted >= maxConnectivityGenerations) {
                return result
            }

            val nextObservation = bridge.connectivitySnapshot()
            if (nextObservation.generation < observation.generation) {
                return ExactOperationHostTransportSequenceResult.ContractViolation(
                    "Connectivity generation regressed inside one host transport sequence",
                )
            }
            if (nextObservation.generation == observation.generation) {
                return result
            }
            if (nextObservation.state == ConnectivityState.OFFLINE) {
                return ExactOperationHostTransportSequenceResult.Ended(
                    ExactOperationHostTransportResult.WaitForNetwork,
                )
            }

            observation = nextObservation
        }
    }

    private suspend fun runGeneration(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        budget: RetryBudget,
        observation: ConnectivityObservation,
    ): ExactOperationHostTransportSequenceResult {
        var result = bridge.begin(runtimeBinding, observation, budget)
        var lastAttemptNumber = 1
        var retryGeneration: Long? = null

        while (result is ExactOperationHostTransportResult.RetryPermitted) {
            val permit = result.permit
            if (permit.operationId != runtimeBinding.operationId) {
                return ExactOperationHostTransportSequenceResult.ContractViolation(
                    "Reconnect retry permit belongs to a different OperationId",
                )
            }
            if (permit.nextAttemptNumber != lastAttemptNumber + 1) {
                return ExactOperationHostTransportSequenceResult.ContractViolation(
                    "Reconnect retry permit attempt number is not the next exact attempt",
                )
            }
            if (permit.nextAttemptNumber > budget.maxAttempts) {
                return ExactOperationHostTransportSequenceResult.ContractViolation(
                    "Reconnect retry permit exceeds the host retry budget",
                )
            }
            if (retryGeneration != null && permit.generation != retryGeneration) {
                return ExactOperationHostTransportSequenceResult.ContractViolation(
                    "Reconnect retry permit changed connectivity generation",
                )
            }

            retryGeneration = permit.generation
            lastAttemptNumber = permit.nextAttemptNumber
            result = bridge.retry(permit)
        }

        return when (result) {
            is ExactOperationHostTransportResult.Connected -> consumeAndCloseConnectedSession(
                runtimeBinding = runtimeBinding,
                connected = result,
            )

            else -> ExactOperationHostTransportSequenceResult.Ended(result)
        }
    }

    private fun ExactOperationHostTransportSequenceResult.mayContinueOnNewerConnectivity(): Boolean {
        val ended = this as? ExactOperationHostTransportSequenceResult.Ended ?: return false
        return when (ended.transportResult) {
            ExactOperationHostTransportResult.WaitForNetwork,
            ExactOperationHostTransportResult.StaleConnectivityGeneration,
            -> true

            else -> false
        }
    }

    private suspend fun consumeAndCloseConnectedSession(
        runtimeBinding: ExactOperationHostRuntimeBinding,
        connected: ExactOperationHostTransportResult.Connected,
    ): ExactOperationHostTransportSequenceResult {
        val discovery = bridge.executeDiscovery(runtimeBinding, connected.binding)
        val management = if (discovery is ExactOperationHostDiscoveryResult.NotDiscoveryOperation) {
            bridge.executeManagementQuickInspect(runtimeBinding, connected.binding)
        } else {
            null
        }
        val deepDiagnostic = if (management is ExactOperationHostManagementResult.NotQuickInspectOperation) {
            bridge.executeDeepDiagnostic(runtimeBinding, connected.binding)
        } else {
            null
        }
        val logs = if (deepDiagnostic is ExactOperationHostDeepDiagnosticResult.NotDeepDiagnosticOperation) {
            bridge.executeServiceLogs(runtimeBinding, connected.binding)
        } else null
        val preflight = if (logs == ServiceLogRuntimeExecutionResult.NotServiceLogOperation) {
            bridge.executeUpdatePreflight(runtimeBinding, connected.binding)
        } else null
        val backup = if (preflight == UpdatePreflightRuntimeExecutionResult.NotUpdatePreflightOperation)
            bridge.executeDatabaseBackup(runtimeBinding, connected.binding) else null
        val archive = if (backup == DatabaseBackupRuntimeResult.NotDatabaseBackupOperation)
            bridge.executeInstallationBackup(runtimeBinding, connected.binding) else null
        val restore = if (archive == InstallationBackupRuntimeResult.NotInstallationBackupOperation)
            bridge.executeRestoreCheck(runtimeBinding, connected.binding) else null
        val comparison = if (restore == RestoreCheckRuntimeResult.NotRestoreCheckOperation)
            bridge.executeRestoreCompatibility(runtimeBinding, connected.binding) else null
        val workingRestore = if (comparison == RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation)
            bridge.executeWorkingDatabaseRestore(runtimeBinding, connected.binding) else null
        val restoredStart = if (workingRestore == WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation)
            bridge.executeRestoredPanelStart(runtimeBinding, connected.binding) else null
        val installer = if (restoredStart == RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation) {
            bridge.executeInstaller(runtimeBinding, connected.binding)
        } else {
            null
        }
        val restart = if (installer == InstallerRuntimeExecutionResult.NotInstallerOperation)
            bridge.executeRestart(runtimeBinding, connected.binding) else null
        return when (val cleanup = bridge.closeSession(runtimeBinding, connected.binding)) {
            ExactOperationHostSessionCloseResult.Closed,
            ExactOperationHostSessionCloseResult.StaleOrAlreadyClosed,
            -> when {
                discovery is ExactOperationHostDiscoveryResult.Completed ->
                    ExactOperationHostTransportSequenceResult.DiscoveryCompleted(
                        binding = connected.binding,
                        result = discovery.result,
                        cleanup = cleanup,
                    )

                discovery !is ExactOperationHostDiscoveryResult.NotDiscoveryOperation ->
                    ExactOperationHostTransportSequenceResult.DiscoveryEnded(
                        binding = connected.binding,
                        discovery = discovery,
                        cleanup = cleanup,
                    )

                management is ExactOperationHostManagementResult.Completed ->
                    ExactOperationHostTransportSequenceResult.ManagementCompleted(
                        binding = connected.binding,
                        snapshot = management.snapshot,
                        committedRevision = management.committedRevision,
                        cleanup = cleanup,
                    )

                management !is ExactOperationHostManagementResult.NotQuickInspectOperation ->
                    ExactOperationHostTransportSequenceResult.ManagementEnded(
                        binding = connected.binding,
                        management = requireNotNull(management),
                        cleanup = cleanup,
                    )

                deepDiagnostic is ExactOperationHostDeepDiagnosticResult.Completed ->
                    ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted(
                        binding = connected.binding,
                        snapshot = deepDiagnostic.snapshot,
                        committedRevision = deepDiagnostic.committedRevision,
                        cleanup = cleanup,
                    )

                logs != null && logs != ServiceLogRuntimeExecutionResult.NotServiceLogOperation ->
                    ExactOperationHostTransportSequenceResult.ServiceLogsEnded(connected.binding, logs, cleanup)

                preflight != null && preflight != UpdatePreflightRuntimeExecutionResult.NotUpdatePreflightOperation ->
                    ExactOperationHostTransportSequenceResult.UpdatePreflightEnded(connected.binding, preflight, cleanup)

                comparison != null && comparison != RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation ->
                    ExactOperationHostTransportSequenceResult.RestoreCompatibilityEnded(connected.binding, comparison, cleanup)

                restoredStart != null && restoredStart != RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation ->
                    ExactOperationHostTransportSequenceResult.RestoredPanelStartEnded(connected.binding, restoredStart, cleanup)

                workingRestore != null && workingRestore != WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation ->
                    ExactOperationHostTransportSequenceResult.WorkingDatabaseRestoreEnded(connected.binding, workingRestore, cleanup)

                restore != null && restore != RestoreCheckRuntimeResult.NotRestoreCheckOperation ->
                    ExactOperationHostTransportSequenceResult.RestoreCheckEnded(connected.binding, restore, cleanup)

                archive != null && archive != InstallationBackupRuntimeResult.NotInstallationBackupOperation ->
                    ExactOperationHostTransportSequenceResult.InstallationBackupEnded(connected.binding, archive, cleanup)

                backup != null && backup != DatabaseBackupRuntimeResult.NotDatabaseBackupOperation ->
                    ExactOperationHostTransportSequenceResult.DatabaseBackupEnded(connected.binding, backup, cleanup)

                deepDiagnostic is ExactOperationHostDeepDiagnosticResult.NotDeepDiagnosticOperation &&
                    installer != InstallerRuntimeExecutionResult.NotInstallerOperation ->
                    ExactOperationHostTransportSequenceResult.InstallerEnded(
                        binding = connected.binding,
                        installer = requireNotNull(installer),
                        cleanup = cleanup,
                    )

                restart != null && restart != ExistingInstallationRestartRuntimeResult.NotRestartOperation ->
                    ExactOperationHostTransportSequenceResult.RestartEnded(connected.binding, restart, cleanup)

                deepDiagnostic is ExactOperationHostDeepDiagnosticResult.NotDeepDiagnosticOperation ->
                    ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned(
                        binding = connected.binding,
                        attemptNumber = connected.attemptNumber,
                        installation = connected.installation,
                        cleanup = cleanup,
                    )

                else -> ExactOperationHostTransportSequenceResult.DeepDiagnosticEnded(
                    binding = connected.binding,
                    deepDiagnostic = requireNotNull(deepDiagnostic),
                    cleanup = cleanup,
                )
            }

            is ExactOperationHostSessionCloseResult.ContractViolation ->
                ExactOperationHostTransportSequenceResult.ContractViolation(cleanup.reason)
        }
    }
}

internal sealed interface ExactOperationHostTransportSequenceResult {
    data class InstallationBackupPrepared(val backup: InstallationBackupRuntimeResult) : ExactOperationHostTransportSequenceResult
    data class InstallationBackupEnded(val binding: SessionBinding, val backup: InstallationBackupRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class RestoreCheckPrepared(val restore: RestoreCheckRuntimeResult) : ExactOperationHostTransportSequenceResult
    data class RestoreCheckEnded(val binding: SessionBinding, val restore: RestoreCheckRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class WorkingDatabaseRestorePrepared(val restore: WorkingDatabaseRestoreRuntimeResult) : ExactOperationHostTransportSequenceResult
    data class WorkingDatabaseRestoreEnded(val binding: SessionBinding, val restore: WorkingDatabaseRestoreRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class RestoredPanelStartPrepared(val restore: RestoredPanelStartRuntimeResult) : ExactOperationHostTransportSequenceResult
    data class RestoredPanelStartEnded(val binding: SessionBinding, val restore: RestoredPanelStartRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class RestoreCompatibilityPrepared(val restore: RestoreCompatibilityRuntimeResult) : ExactOperationHostTransportSequenceResult
    data class RestoreCompatibilityEnded(val binding: SessionBinding, val restore: RestoreCompatibilityRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class DatabaseBackupPrepared(val backup: DatabaseBackupRuntimeResult) : ExactOperationHostTransportSequenceResult
    data class DatabaseBackupEnded(val binding: SessionBinding, val backup: DatabaseBackupRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class ServiceLogsEnded(val binding: SessionBinding, val logs: ServiceLogRuntimeExecutionResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class UpdatePreflightEnded(val binding: SessionBinding, val preflight: UpdatePreflightRuntimeExecutionResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    data class RestartPrepared(val restart: ExistingInstallationRestartPreparationResult) : ExactOperationHostTransportSequenceResult
    data class RestartEnded(val binding: SessionBinding, val restart: ExistingInstallationRestartRuntimeResult,
        val cleanup: ExactOperationHostSessionCloseResult) : ExactOperationHostTransportSequenceResult
    /** Transport was established, then exact SessionId cleanup completed or was already stale. */
    data class ConnectedSessionCleaned(
        val binding: SessionBinding,
        val attemptNumber: Int,
        val installation: SessionInstallResult,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    data class DiscoveryCompleted(
        val binding: SessionBinding,
        val result: com.velumtegra.xuimobile.core.model.DiscoveryResult,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    data class DiscoveryEnded(
        val binding: SessionBinding,
        val discovery: ExactOperationHostDiscoveryResult,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult


    data class ManagementCompleted(
        val binding: SessionBinding,
        val snapshot: com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot,
        val committedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    data class ManagementEnded(
        val binding: SessionBinding,
        val management: ExactOperationHostManagementResult,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    data class DeepDiagnosticCompleted(
        val binding: SessionBinding,
        val snapshot: com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot,
        val committedRevision: com.velumtegra.xuimobile.core.domain.OperationRevision,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    data class DeepDiagnosticEnded(
        val binding: SessionBinding,
        val deepDiagnostic: ExactOperationHostDeepDiagnosticResult,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    /** Installer completed a local-only pre-transport decision (including COMMIT_VERIFIED). */
    data class InstallerPrepared(
        val installer: InstallerRuntimePreparationResult,
    ) : ExactOperationHostTransportSequenceResult

    /** Connected exact session was offered to the Phase 8.7 Installer runtime consumer. */
    data class InstallerEnded(
        val binding: SessionBinding,
        val installer: InstallerRuntimeExecutionResult,
        val cleanup: ExactOperationHostSessionCloseResult,
    ) : ExactOperationHostTransportSequenceResult

    /** Any non-connected typed coordinator outcome. Durable operation truth remains untouched. */
    data class Ended(
        val transportResult: ExactOperationHostTransportResult,
    ) : ExactOperationHostTransportSequenceResult

    data class ContractViolation(
        val reason: String,
    ) : ExactOperationHostTransportSequenceResult
}
