package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher
import java.time.Instant
import java.util.UUID

/** Explicit visible-user entry boundary for one exact bounded read-only DEEP_DIAGNOSTIC operation. */
internal class VisibleDeepDiagnosticOperationLauncher(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val managementAccessRepository: ManagementAccessRepository,
    private val hostStart: DeepDiagnosticHostStartPort,
    private val resultRegistry: DeepDiagnosticResultRegistry = DeepDiagnosticResultRegistry(),
    private val now: () -> Instant = Instant::now,
    private val operationIdFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) },
) {
    constructor(
        activity: Activity,
        journal: OperationJournal,
        installationRepository: XuiInstallationRepository,
        managementAccessRepository: ManagementAccessRepository,
        resultRegistry: DeepDiagnosticResultRegistry,
    ) : this(
        journal = journal,
        installationRepository = installationRepository,
        managementAccessRepository = managementAccessRepository,
        hostStart = DeepDiagnosticHostStartPort { operationId ->
            VisibleExactOperationHostLauncher(activity).start(operationId)
        },
        resultRegistry = resultRegistry,
    )

    suspend fun start(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): DeepDiagnosticOperationStartResult {
        val exact = when (val validation = validateExactTarget(installationId, serverAccessId)) {
            is TargetValidation.Valid -> validation.scopeWithoutOperation
            is TargetValidation.Result -> return validation.result.toStartResult()
        }
        val operationId = operationIdFactory()
        if (operationId.value.isBlank()) {
            return DeepDiagnosticOperationStartResult.ContractViolation(
                "DEEP_DIAGNOSTIC OperationId factory returned a blank id",
            )
        }
        val startedAt = now()
        val scope = DeepDiagnosticScope(
            operationId = operationId,
            serverId = exact.serverId,
            serverAccessId = serverAccessId,
            installationId = installationId,
        )
        val initial = OperationSnapshot(
            operationId = operationId,
            type = OperationType.DEEP_DIAGNOSTIC,
            target = OperationTarget.InstallationTarget(
                serverId = exact.serverId,
                serverAccessId = serverAccessId,
                installationId = installationId,
            ),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "DEEP_DIAGNOSTIC",
                semantics = CheckpointSemantics.READ_ONLY,
                recordedAt = startedAt,
            ),
            startedAt = startedAt,
            updatedAt = startedAt,
        )

        val created = when (val result = journal.create(initial)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.AlreadyExists -> return DeepDiagnosticOperationStartResult.OperationIdCollision(operationId)
            is OperationJournalResult.InvalidTransition -> return DeepDiagnosticOperationStartResult.ContractViolation(result.reason)
            is OperationJournalResult.Corruption -> return DeepDiagnosticOperationStartResult.LocalFailure(
                DeepDiagnosticLocalFailureKind.CORRUPTION,
            )
            is OperationJournalResult.StorageFailure -> return DeepDiagnosticOperationStartResult.LocalFailure(
                DeepDiagnosticLocalFailureKind.STORAGE,
            )
            else -> return DeepDiagnosticOperationStartResult.ContractViolation(
                "DEEP_DIAGNOSTIC OperationJournal create returned ${result::class.simpleName}",
            )
        }

        resultRegistry.beginAttempt(operationId)
        return when (val platform = hostStart.start(operationId)) {
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED -> DeepDiagnosticOperationStartResult.Started(
                scope = scope,
                revision = created.revision,
            )
            else -> {
                resultRegistry.publishNotice(operationId, DeepDiagnosticProcessNotice.HostStartRejected)
                DeepDiagnosticOperationStartResult.HostStartNotAccepted(
                    scope = scope,
                    revision = created.revision,
                    reason = platform,
                )
            }
        }
    }

    suspend fun resume(operationId: OperationId): DeepDiagnosticOperationResumeResult {
        if (operationId.value.isBlank()) return DeepDiagnosticOperationResumeResult.InvalidOperationId
        val current = when (val read = journal.get(operationId)) {
            is OperationJournalResult.Success -> read.value.snapshot
            OperationJournalResult.NotFound -> return DeepDiagnosticOperationResumeResult.NotFound
            is OperationJournalResult.Corruption -> return DeepDiagnosticOperationResumeResult.LocalFailure(
                DeepDiagnosticLocalFailureKind.CORRUPTION,
            )
            is OperationJournalResult.StorageFailure -> return DeepDiagnosticOperationResumeResult.LocalFailure(
                DeepDiagnosticLocalFailureKind.STORAGE,
            )
            else -> return DeepDiagnosticOperationResumeResult.ContractViolation(
                "DEEP_DIAGNOSTIC OperationJournal get returned ${read::class.simpleName}",
            )
        }
        val target = current.target as? OperationTarget.InstallationTarget
        if (current.type != OperationType.DEEP_DIAGNOSTIC || target == null) {
            return DeepDiagnosticOperationResumeResult.NotRelaunchable(
                DeepDiagnosticOperationRelaunchBlock.NOT_DEEP_DIAGNOSTIC_CONTRACT,
            )
        }
        if (current.status in TERMINAL_STATUSES || current.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return DeepDiagnosticOperationResumeResult.NotRelaunchable(DeepDiagnosticOperationRelaunchBlock.TERMINAL)
        }
        if (current.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return DeepDiagnosticOperationResumeResult.NotRelaunchable(
                DeepDiagnosticOperationRelaunchBlock.NOT_DEEP_DIAGNOSTIC_CONTRACT,
            )
        }
        when (val validation = validateExactTarget(target.installationId, target.serverAccessId)) {
            is TargetValidation.Valid -> if (validation.scopeWithoutOperation.serverId != target.serverId) {
                return DeepDiagnosticOperationResumeResult.NotRelaunchable(
                    DeepDiagnosticOperationRelaunchBlock.EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
                )
            }
            is TargetValidation.Result -> return validation.result.toResumeResult()
        }

        resultRegistry.beginAttempt(operationId)
        return when (val platform = hostStart.start(operationId)) {
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED -> DeepDiagnosticOperationResumeResult.StartRequestAccepted
            else -> {
                resultRegistry.publishNotice(operationId, DeepDiagnosticProcessNotice.HostStartRejected)
                DeepDiagnosticOperationResumeResult.HostStartNotAccepted(platform)
            }
        }
    }

    private suspend fun validateExactTarget(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): TargetValidation {
        val installation = when (val result = installationRepository.get(installationId)) {
            is RepositoryResult.Success -> result.value.value
            RepositoryResult.NotFound -> return TargetValidation.Result(TargetValidationResult.TargetUnavailable)
            is RepositoryResult.Corruption -> return TargetValidation.Result(
                TargetValidationResult.LocalFailure(DeepDiagnosticLocalFailureKind.CORRUPTION),
            )
            is RepositoryResult.StorageFailure -> return TargetValidation.Result(
                TargetValidationResult.LocalFailure(DeepDiagnosticLocalFailureKind.STORAGE),
            )
            else -> return TargetValidation.Result(
                TargetValidationResult.ContractViolation(
                    "DEEP_DIAGNOSTIC installation read returned ${result::class.simpleName}",
                ),
            )
        }
        if (installation.id != installationId) {
            return TargetValidation.Result(
                TargetValidationResult.ContractViolation("Installation repository returned a different id"),
            )
        }
        val access = when (val result = managementAccessRepository.get(installationId, serverAccessId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return TargetValidation.Result(TargetValidationResult.TargetUnavailable)
            is RepositoryResult.Corruption -> return TargetValidation.Result(
                TargetValidationResult.LocalFailure(DeepDiagnosticLocalFailureKind.CORRUPTION),
            )
            is RepositoryResult.StorageFailure -> return TargetValidation.Result(
                TargetValidationResult.LocalFailure(DeepDiagnosticLocalFailureKind.STORAGE),
            )
            else -> return TargetValidation.Result(
                TargetValidationResult.ContractViolation(
                    "DEEP_DIAGNOSTIC ManagementAccess read returned ${result::class.simpleName}",
                ),
            )
        }
        if (access.installationId != installationId || access.serverAccessId != serverAccessId) {
            return TargetValidation.Result(
                TargetValidationResult.ContractViolation("ManagementAccess repository returned a different exact relation"),
            )
        }
        return TargetValidation.Valid(TargetScope(installation.serverId))
    }

    private data class TargetScope(val serverId: com.velumtegra.xuimobile.core.model.ServerId)
    private sealed interface TargetValidation {
        data class Valid(val scopeWithoutOperation: TargetScope) : TargetValidation
        data class Result(val result: TargetValidationResult) : TargetValidation
    }
    private sealed interface TargetValidationResult {
        data object TargetUnavailable : TargetValidationResult
        data class LocalFailure(val kind: DeepDiagnosticLocalFailureKind) : TargetValidationResult
        data class ContractViolation(val reason: String) : TargetValidationResult
    }

    private fun TargetValidationResult.toStartResult(): DeepDiagnosticOperationStartResult = when (this) {
        TargetValidationResult.TargetUnavailable -> DeepDiagnosticOperationStartResult.TargetUnavailable
        is TargetValidationResult.LocalFailure -> DeepDiagnosticOperationStartResult.LocalFailure(kind)
        is TargetValidationResult.ContractViolation -> DeepDiagnosticOperationStartResult.ContractViolation(reason)
    }

    private fun TargetValidationResult.toResumeResult(): DeepDiagnosticOperationResumeResult = when (this) {
        TargetValidationResult.TargetUnavailable -> DeepDiagnosticOperationResumeResult.NotRelaunchable(
            DeepDiagnosticOperationRelaunchBlock.EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
        )
        is TargetValidationResult.LocalFailure -> DeepDiagnosticOperationResumeResult.LocalFailure(kind)
        is TargetValidationResult.ContractViolation -> DeepDiagnosticOperationResumeResult.ContractViolation(reason)
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

internal fun interface DeepDiagnosticHostStartPort {
    fun start(operationId: OperationId): ExactOperationHostStartResult
}

internal enum class DeepDiagnosticLocalFailureKind {
    CORRUPTION,
    STORAGE,
}

internal sealed interface DeepDiagnosticOperationStartResult {
    data class Started(
        val scope: DeepDiagnosticScope,
        val revision: OperationRevision,
    ) : DeepDiagnosticOperationStartResult

    data class HostStartNotAccepted(
        val scope: DeepDiagnosticScope,
        val revision: OperationRevision,
        val reason: ExactOperationHostStartResult,
    ) : DeepDiagnosticOperationStartResult

    data class OperationIdCollision(val operationId: OperationId) : DeepDiagnosticOperationStartResult
    data object TargetUnavailable : DeepDiagnosticOperationStartResult
    data class LocalFailure(val kind: DeepDiagnosticLocalFailureKind) : DeepDiagnosticOperationStartResult
    data class ContractViolation(val reason: String) : DeepDiagnosticOperationStartResult
}

internal enum class DeepDiagnosticOperationRelaunchBlock {
    TERMINAL,
    NOT_DEEP_DIAGNOSTIC_CONTRACT,
    EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
}

internal sealed interface DeepDiagnosticOperationResumeResult {
    data object StartRequestAccepted : DeepDiagnosticOperationResumeResult
    data class HostStartNotAccepted(val reason: ExactOperationHostStartResult) : DeepDiagnosticOperationResumeResult
    data class NotRelaunchable(val block: DeepDiagnosticOperationRelaunchBlock) : DeepDiagnosticOperationResumeResult
    data class LocalFailure(val kind: DeepDiagnosticLocalFailureKind) : DeepDiagnosticOperationResumeResult
    data class ContractViolation(val reason: String) : DeepDiagnosticOperationResumeResult
    data object InvalidOperationId : DeepDiagnosticOperationResumeResult
    data object NotFound : DeepDiagnosticOperationResumeResult
}
