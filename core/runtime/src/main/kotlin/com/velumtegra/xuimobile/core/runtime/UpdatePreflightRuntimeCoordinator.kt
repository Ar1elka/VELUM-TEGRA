package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.ManagementReadbackPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.UpdatePreflightSnapshot
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.UpdatePreflightFailure
import com.velumtegra.xuimobile.core.ssh.UpdatePreflightSshReader
import com.velumtegra.xuimobile.core.ssh.UpdatePreflightSshResult
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant
import java.util.UUID

sealed interface UpdatePreflightRuntimeExecutionResult {
    data class Completed(
        val snapshot: UpdatePreflightSnapshot,
        val committedRevision: OperationRevision,
        val installationRecord: com.velumtegra.xuimobile.core.domain.VersionedRecord<XuiInstallation>,
        val access: ServerAccess,
    ) : UpdatePreflightRuntimeExecutionResult

    data class ReadbackFailed(
        val kind: UpdatePreflightFailure,
        val committedRevision: OperationRevision,
    ) : UpdatePreflightRuntimeExecutionResult

    data object NotUpdatePreflightOperation : UpdatePreflightRuntimeExecutionResult
    data object AdmissionLost : UpdatePreflightRuntimeExecutionResult
    data object SessionUnavailable : UpdatePreflightRuntimeExecutionResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : UpdatePreflightRuntimeExecutionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : UpdatePreflightRuntimeExecutionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : UpdatePreflightRuntimeExecutionResult
    data class ContractViolation(val reason: String) : UpdatePreflightRuntimeExecutionResult
}

/** Read-only update preflight consumer on the shared runtime/session/journal; checks exact ownership after suspensions. */
class UpdatePreflightRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val managementAccessRepository: ManagementAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val managementExecutor: ManagementSshProbeExecutor = ManagementSshProbeExecutor(),
    private val preflightReader: UpdatePreflightSshReader = UpdatePreflightSshReader(),
    private val accessRepository: ServerAccessRepository,
    private val now: () -> Instant = Instant::now,
    private val proofIdFactory: () -> TargetProofId = { TargetProofId(UUID.randomUUID().toString()) },
) {
    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): UpdatePreflightRuntimeExecutionResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return UpdatePreflightRuntimeExecutionResult.AdmissionLost
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }

        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.UPDATE_PREFLIGHT) {
            return UpdatePreflightRuntimeExecutionResult.NotUpdatePreflightOperation
        }
        if (before.snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT durable checkpoint must remain READ_ONLY until terminal result",
            )
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT must target one exact InstallationTarget",
            )

        val installationBefore = when (val result = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT target installation does not exist",
            )
            is RepositoryResult.Corruption -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(result.reason, true))
            is RepositoryResult.StorageFailure -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(result.reason, false))
            else -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT installation read returned ${result::class.simpleName}",
            )
        }
        val installation = installationBefore.value
        if (installation.id != target.installationId || installation.serverId != target.serverId) {
            return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT installation belongs to a different ServerId",
            )
        }
        when (val access = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> if (access.value.installationId != target.installationId ||
                access.value.serverAccessId != target.serverAccessId) return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                    "ManagementAccess returned a different exact relation")
            RepositoryResult.NotFound -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT exact ManagementAccess is unavailable",
            )
            is RepositoryResult.Corruption -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(access.reason, true))
            is RepositoryResult.StorageFailure -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(access.reason, false))
            else -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT ManagementAccess read returned ${access::class.simpleName}",
            )
        }

        val accessBefore = (accessRepository.get(target.serverAccessId) as? RepositoryResult.Success)?.value
            ?: return UpdatePreflightRuntimeExecutionResult.ContractViolation("Exact SSH access unavailable")
        if (accessBefore.id != target.serverAccessId || accessBefore.serverId != target.serverId)
            return UpdatePreflightRuntimeExecutionResult.ContractViolation("Exact SSH access ownership mismatch")

        val managementScope = ManagementScope(
            operationId = before.snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            installationId = target.installationId,
        )
        val managementRun = managementExecutor.executeQuickInspect(managementScope, installation, session)
        revalidateAfterRemote(admission, sessionBinding, before, installationBefore.revision, installation, accessBefore)?.let {
            return it
        }
        val managementObservedAt = now()
        val managementSnapshot = when (managementRun) {
            is ManagementSshProbeRunResult.Completed -> ManagementReadbackPolicy.quickInspect(
                installation = installation,
                evidence = managementRun.evidence,
                proofId = proofIdFactory(),
                now = managementObservedAt,
            )
            is ManagementSshProbeRunResult.Failed -> {
                return commitTerminal(
                    before = before,
                    status = OperationStatus.FAILED,
                    phaseName = "UPDATE_PREFLIGHT_FAILED",
                    at = managementObservedAt,
                ) { revision ->
                    UpdatePreflightRuntimeExecutionResult.ReadbackFailed(
                        kind = UpdatePreflightFailure.TARGET_NOT_VERIFIED,
                        committedRevision = revision,
                    )
                }
            }
        }

        if (managementSnapshot.identityStatus != ManagementIdentityStatus.Matched) {
            return commitTerminal(before, OperationStatus.FAILED, "UPDATE_PREFLIGHT_FAILED", now()) {
                UpdatePreflightRuntimeExecutionResult.ReadbackFailed(UpdatePreflightFailure.TARGET_NOT_VERIFIED, it)
            }
        }
        val preflightRun = preflightReader.read(managementScope, installation, session, managementSnapshot, includeRecoveryFiles = true)
        revalidateAfterRemote(admission, sessionBinding, before, installationBefore.revision, installation, accessBefore)?.let {
            return it
        }
        return when (preflightRun) {
            is UpdatePreflightSshResult.Completed -> commitTerminal(before, OperationStatus.SUCCEEDED,
                "UPDATE_PREFLIGHT_RESULT", now()) { UpdatePreflightRuntimeExecutionResult.Completed(preflightRun.snapshot, it, installationBefore, accessBefore) }
            is UpdatePreflightSshResult.Failed -> commitTerminal(before, OperationStatus.FAILED,
                "UPDATE_PREFLIGHT_FAILED", now()) { UpdatePreflightRuntimeExecutionResult.ReadbackFailed(preflightRun.kind, it) }
        }
    }

    private suspend fun revalidateAfterRemote(
        admission: RecoveryRuntimeAdmission,
        expectedSession: SessionBinding,
        before: VersionedOperationSnapshot,
        expectedInstallationRevision: com.velumtegra.xuimobile.core.domain.RecordRevision,
        expectedInstallation: XuiInstallation,
        expectedAccess: ServerAccess,
    ): UpdatePreflightRuntimeExecutionResult? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return UpdatePreflightRuntimeExecutionResult.AdmissionLost
        when (val current = currentSession(admission, expectedSession)) {
            is CurrentSession.Handle -> Unit
            is CurrentSession.Result -> return current.result
        }
        val after = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (after.revision != before.revision) {
            return UpdatePreflightRuntimeExecutionResult.StalePlan(
                admission.plan.operationId,
                before.revision,
                after.revision,
            )
        }
        if (after.snapshot != before.snapshot) return UpdatePreflightRuntimeExecutionResult.ContractViolation(
            "Operation snapshot changed without a revision advance")
        val currentAccess = (accessRepository.get(expectedAccess.id) as? RepositoryResult.Success)?.value
        if (currentAccess != expectedAccess) return UpdatePreflightRuntimeExecutionResult.ContractViolation(
            "Exact SSH access changed during update preflight")
        val target = before.snapshot.target as OperationTarget.InstallationTarget
        when (val latestInstallation = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> if (
                latestInstallation.value.revision != expectedInstallationRevision ||
                latestInstallation.value.value != expectedInstallation
            ) {
                return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                    "UPDATE_PREFLIGHT installation changed while read-back was suspended",
                )
            }
            RepositoryResult.NotFound -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT installation disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, true))
            is RepositoryResult.StorageFailure -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, false))
            else -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT post-read installation lookup returned ${latestInstallation::class.simpleName}",
            )
        }
        when (val latestAccess = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> if (latestAccess.value.installationId != target.installationId ||
                latestAccess.value.serverAccessId != target.serverAccessId) return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                    "ManagementAccess returned a different exact relation")
            RepositoryResult.NotFound -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT ManagementAccess disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, true))
            is RepositoryResult.StorageFailure -> return UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, false))
            else -> return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT post-read ManagementAccess lookup returned ${latestAccess::class.simpleName}",
            )
        }
        return null
    }

    private suspend fun commitTerminal(
        before: VersionedOperationSnapshot,
        status: OperationStatus,
        phaseName: String,
        at: Instant,
        completed: (OperationRevision) -> UpdatePreflightRuntimeExecutionResult,
    ): UpdatePreflightRuntimeExecutionResult {
        val terminal = before.snapshot.copy(
            status = status,
            checkpoint = OperationCheckpoint(phaseName, CheckpointSemantics.TERMINAL, at),
            updatedAt = at,
        )
        return when (val advance = journal.advance(before.snapshot.operationId, before.revision, terminal)) {
            is OperationJournalResult.Success -> completed(advance.value.revision)
            is OperationJournalResult.StaleRevision -> UpdatePreflightRuntimeExecutionResult.StalePlan(
                before.snapshot.operationId,
                advance.expected,
                advance.actual,
            )
            is OperationJournalResult.Corruption -> UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(advance.reason, true))
            is OperationJournalResult.StorageFailure -> UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(advance.reason, false))
            is OperationJournalResult.InvalidTransition -> UpdatePreflightRuntimeExecutionResult.Failed(
                contractFailure("UPDATE_PREFLIGHT terminal advance rejected: ${advance.reason}"),
            )
            else -> UpdatePreflightRuntimeExecutionResult.Failed(
                contractFailure("UPDATE_PREFLIGHT terminal advance returned ${advance::class.simpleName}"),
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): UpdatePreflightRuntimeExecutionResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT binding belongs to a different operation owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return UpdatePreflightRuntimeExecutionResult.ContractViolation(
                "UPDATE_PREFLIGHT binding uses a different ServerAccessId than the durable target",
            )
        }
        return null
    }

    private fun currentSession(admission: RecoveryRuntimeAdmission, expected: SessionBinding): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(UpdatePreflightRuntimeExecutionResult.SessionUnavailable)
        if (!current.isOpen) return CurrentSession.Result(UpdatePreflightRuntimeExecutionResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                UpdatePreflightRuntimeExecutionResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                UpdatePreflightRuntimeExecutionResult.ContractViolation(
                    "Live UPDATE_PREFLIGHT session binding changed exact owner/access identity",
                ),
            )
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.Failed(contractFailure("UPDATE_PREFLIGHT operation no longer exists")),
            )
            is OperationJournalResult.Corruption -> return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(result.reason, true)),
            )
            is OperationJournalResult.StorageFailure -> return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.Failed(storageFailure(result.reason, false)),
            )
            else -> return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.Failed(
                    contractFailure("UPDATE_PREFLIGHT exact journal read returned ${result::class.simpleName}"),
                ),
            )
        }
        if (current.snapshot.operationId != admission.plan.operationId || current.snapshot.target != admission.plan.target) {
            return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Operation identity/target changed during UPDATE_PREFLIGHT",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.StalePlan(
                    admission.plan.operationId,
                    admission.plan.expectedRevision,
                    current.revision,
                ),
            )
        }
        if (current.snapshot.status in terminalStatuses || current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return CurrentRead.Result(
                UpdatePreflightRuntimeExecutionResult.Failed(
                    contractFailure("UPDATE_PREFLIGHT admission points at terminal durable state"),
                ),
            )
        }
        return CurrentRead.Current(current)
    }

    private fun contractFailure(reason: String) = RecoveryBootstrapFailure(
        RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason,
    )

    private fun storageFailure(reason: String, corruption: Boolean) = RecoveryBootstrapFailure(
        if (corruption) RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION else RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
        reason,
    )

    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: UpdatePreflightRuntimeExecutionResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: UpdatePreflightRuntimeExecutionResult) : CurrentSession
    }

    private companion object {
        val terminalStatuses = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
    }
}
