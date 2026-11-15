package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ManagementScope
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

/**
 * Explicit visible-user entry boundary for one exact read-only Management QUICK_INSPECT operation.
 *
 * The exact XuiInstallation and exact ManagementAccess relation are re-read before durable operation
 * creation and again before resume. Android never receives an OperationId until this feature boundary
 * has proven the local Management tuple. There is no first/latest/active installation/access fallback.
 */
internal class VisibleManagementQuickInspectOperationLauncher(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val managementAccessRepository: ManagementAccessRepository,
    private val hostStart: ManagementHostStartPort,
    private val resultRegistry: ManagementResultRegistry = ManagementResultRegistry(),
    private val now: () -> Instant = Instant::now,
    private val operationIdFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) },
) {
    constructor(
        activity: Activity,
        journal: OperationJournal,
        installationRepository: XuiInstallationRepository,
        managementAccessRepository: ManagementAccessRepository,
        resultRegistry: ManagementResultRegistry,
    ) : this(
        journal = journal,
        installationRepository = installationRepository,
        managementAccessRepository = managementAccessRepository,
        hostStart = ManagementHostStartPort { operationId ->
            VisibleExactOperationHostLauncher(activity).start(operationId)
        },
        resultRegistry = resultRegistry,
    )

    suspend fun start(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): ManagementOperationStartResult {
        val exact = when (val validation = validateExactTarget(installationId, serverAccessId)) {
            is TargetValidation.Valid -> validation.scopeWithoutOperation
            is TargetValidation.Result -> return validation.result.toStartResult()
        }
        val operationId = operationIdFactory()
        if (operationId.value.isBlank()) {
            return ManagementOperationStartResult.ContractViolation(
                "QUICK_INSPECT OperationId factory returned a blank id",
            )
        }
        val startedAt = now()
        val scope = ManagementScope(
            operationId = operationId,
            serverId = exact.serverId,
            serverAccessId = serverAccessId,
            installationId = installationId,
        )
        val initial = OperationSnapshot(
            operationId = operationId,
            type = OperationType.QUICK_INSPECT,
            target = OperationTarget.InstallationTarget(
                serverId = exact.serverId,
                serverAccessId = serverAccessId,
                installationId = installationId,
            ),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "QUICK_INSPECT",
                semantics = CheckpointSemantics.READ_ONLY,
                recordedAt = startedAt,
            ),
            startedAt = startedAt,
            updatedAt = startedAt,
        )

        val created = when (val result = journal.create(initial)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.AlreadyExists -> {
                return ManagementOperationStartResult.OperationIdCollision(operationId)
            }
            is OperationJournalResult.InvalidTransition -> {
                return ManagementOperationStartResult.ContractViolation(result.reason)
            }
            is OperationJournalResult.Corruption -> {
                return ManagementOperationStartResult.LocalFailure(
                    ManagementLocalFailureKind.CORRUPTION,
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return ManagementOperationStartResult.LocalFailure(
                    ManagementLocalFailureKind.STORAGE,
                )
            }
            else -> {
                return ManagementOperationStartResult.ContractViolation(
                    "QUICK_INSPECT OperationJournal create returned ${result::class.simpleName}",
                )
            }
        }

        resultRegistry.beginAttempt(operationId)
        return when (val platform = hostStart.start(operationId)) {
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED -> ManagementOperationStartResult.Started(
                scope = scope,
                revision = created.revision,
            )
            else -> {
                resultRegistry.publishNotice(operationId, ManagementProcessNotice.HostStartRejected)
                ManagementOperationStartResult.HostStartNotAccepted(
                    scope = scope,
                    revision = created.revision,
                    reason = platform,
                )
            }
        }
    }

    suspend fun resume(operationId: OperationId): ManagementOperationResumeResult {
        if (operationId.value.isBlank()) return ManagementOperationResumeResult.InvalidOperationId
        val current = when (val read = journal.get(operationId)) {
            is OperationJournalResult.Success -> read.value.snapshot
            OperationJournalResult.NotFound -> return ManagementOperationResumeResult.NotFound
            is OperationJournalResult.Corruption -> {
                return ManagementOperationResumeResult.LocalFailure(ManagementLocalFailureKind.CORRUPTION)
            }
            is OperationJournalResult.StorageFailure -> {
                return ManagementOperationResumeResult.LocalFailure(ManagementLocalFailureKind.STORAGE)
            }
            else -> {
                return ManagementOperationResumeResult.ContractViolation(
                    "QUICK_INSPECT OperationJournal get returned ${read::class.simpleName}",
                )
            }
        }
        val target = current.target as? OperationTarget.InstallationTarget
        if (current.type != OperationType.QUICK_INSPECT || target == null) {
            return ManagementOperationResumeResult.NotRelaunchable(
                ManagementOperationRelaunchBlock.NOT_QUICK_INSPECT_CONTRACT,
            )
        }
        if (current.status in TERMINAL_STATUSES || current.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return ManagementOperationResumeResult.NotRelaunchable(ManagementOperationRelaunchBlock.TERMINAL)
        }
        if (current.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return ManagementOperationResumeResult.NotRelaunchable(
                ManagementOperationRelaunchBlock.NOT_QUICK_INSPECT_CONTRACT,
            )
        }
        when (val validation = validateExactTarget(target.installationId, target.serverAccessId)) {
            is TargetValidation.Valid -> if (validation.scopeWithoutOperation.serverId != target.serverId) {
                return ManagementOperationResumeResult.NotRelaunchable(
                    ManagementOperationRelaunchBlock.EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
                )
            }
            is TargetValidation.Result -> return validation.result.toResumeResult()
        }

        resultRegistry.beginAttempt(operationId)
        return when (val platform = hostStart.start(operationId)) {
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED -> ManagementOperationResumeResult.StartRequestAccepted
            else -> {
                resultRegistry.publishNotice(operationId, ManagementProcessNotice.HostStartRejected)
                ManagementOperationResumeResult.HostStartNotAccepted(platform)
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
                TargetValidationResult.LocalFailure(ManagementLocalFailureKind.CORRUPTION),
            )
            is RepositoryResult.StorageFailure -> return TargetValidation.Result(
                TargetValidationResult.LocalFailure(ManagementLocalFailureKind.STORAGE),
            )
            else -> return TargetValidation.Result(
                TargetValidationResult.ContractViolation(
                    "QUICK_INSPECT installation read returned ${result::class.simpleName}",
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
                TargetValidationResult.LocalFailure(ManagementLocalFailureKind.CORRUPTION),
            )
            is RepositoryResult.StorageFailure -> return TargetValidation.Result(
                TargetValidationResult.LocalFailure(ManagementLocalFailureKind.STORAGE),
            )
            else -> return TargetValidation.Result(
                TargetValidationResult.ContractViolation(
                    "QUICK_INSPECT ManagementAccess read returned ${result::class.simpleName}",
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
        data class LocalFailure(val kind: ManagementLocalFailureKind) : TargetValidationResult
        data class ContractViolation(val reason: String) : TargetValidationResult
    }

    private fun TargetValidationResult.toStartResult(): ManagementOperationStartResult = when (this) {
        TargetValidationResult.TargetUnavailable -> ManagementOperationStartResult.TargetUnavailable
        is TargetValidationResult.LocalFailure -> ManagementOperationStartResult.LocalFailure(kind)
        is TargetValidationResult.ContractViolation -> ManagementOperationStartResult.ContractViolation(reason)
    }

    private fun TargetValidationResult.toResumeResult(): ManagementOperationResumeResult = when (this) {
        TargetValidationResult.TargetUnavailable -> ManagementOperationResumeResult.NotRelaunchable(
            ManagementOperationRelaunchBlock.EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
        )
        is TargetValidationResult.LocalFailure -> ManagementOperationResumeResult.LocalFailure(kind)
        is TargetValidationResult.ContractViolation -> ManagementOperationResumeResult.ContractViolation(reason)
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

internal fun interface ManagementHostStartPort {
    fun start(operationId: OperationId): ExactOperationHostStartResult
}

internal enum class ManagementLocalFailureKind {
    CORRUPTION,
    STORAGE,
}

internal sealed interface ManagementOperationStartResult {
    data class Started(
        val scope: ManagementScope,
        val revision: OperationRevision,
    ) : ManagementOperationStartResult

    data class HostStartNotAccepted(
        val scope: ManagementScope,
        val revision: OperationRevision,
        val reason: ExactOperationHostStartResult,
    ) : ManagementOperationStartResult

    data class OperationIdCollision(val operationId: OperationId) : ManagementOperationStartResult
    data object TargetUnavailable : ManagementOperationStartResult
    data class LocalFailure(val kind: ManagementLocalFailureKind) : ManagementOperationStartResult
    data class ContractViolation(val reason: String) : ManagementOperationStartResult
}

internal enum class ManagementOperationRelaunchBlock {
    TERMINAL,
    NOT_QUICK_INSPECT_CONTRACT,
    EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
}

internal sealed interface ManagementOperationResumeResult {
    data object StartRequestAccepted : ManagementOperationResumeResult
    data class HostStartNotAccepted(val reason: ExactOperationHostStartResult) : ManagementOperationResumeResult
    data class NotRelaunchable(val block: ManagementOperationRelaunchBlock) : ManagementOperationResumeResult
    data class LocalFailure(val kind: ManagementLocalFailureKind) : ManagementOperationResumeResult
    data class ContractViolation(val reason: String) : ManagementOperationResumeResult
    data object InvalidOperationId : ManagementOperationResumeResult
    data object NotFound : ManagementOperationResumeResult
}
