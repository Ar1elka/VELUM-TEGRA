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
import com.velumtegra.xuimobile.core.model.ManagementFailureKind
import com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutionFailure
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeRunResult
import java.time.Instant
import java.util.UUID

sealed interface ManagementRuntimeExecutionResult {
    data class Completed(
        val snapshot: ManagementLiveSnapshot,
        val committedRevision: OperationRevision,
    ) : ManagementRuntimeExecutionResult

    data class ReadbackFailed(
        val kind: ManagementFailureKind,
        val committedRevision: OperationRevision,
    ) : ManagementRuntimeExecutionResult

    data class NotQuickInspectOperation(val operationType: OperationType) : ManagementRuntimeExecutionResult
    data object AdmissionLost : ManagementRuntimeExecutionResult
    data object SessionUnavailable : ManagementRuntimeExecutionResult
    data class StaleSession(val expectedSessionId: SessionId, val actualSessionId: SessionId?) : ManagementRuntimeExecutionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ManagementRuntimeExecutionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ManagementRuntimeExecutionResult
    data class ContractViolation(val reason: String) : ManagementRuntimeExecutionResult
}

/**
 * Phase 6 QUICK_INSPECT consumer for the already-open exact Phase 4 operation-owned SSH session.
 *
 * It rechecks the exact durable InstallationTarget, XuiInstallation revision, ManagementAccess and
 * exact SessionId before and after the bounded read-only Management executor. No baseline is
 * rewritten here and no second reconnect/session/runtime contour exists.
 */
class ManagementRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val managementAccessRepository: ManagementAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val executor: ManagementSshProbeExecutor = ManagementSshProbeExecutor(),
    private val now: () -> Instant = Instant::now,
    private val proofIdFactory: () -> TargetProofId = { TargetProofId(UUID.randomUUID().toString()) },
) {
    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ManagementRuntimeExecutionResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return ManagementRuntimeExecutionResult.AdmissionLost
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }

        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.QUICK_INSPECT) {
            return ManagementRuntimeExecutionResult.NotQuickInspectOperation(before.snapshot.type)
        }
        if (before.snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT durable checkpoint must remain READ_ONLY until terminal result",
            )
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT must target one exact InstallationTarget",
            )

        val installationBefore = when (val result = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT target installation does not exist",
            )
            is RepositoryResult.Corruption -> return ManagementRuntimeExecutionResult.Failed(storageFailure(result.reason, true))
            is RepositoryResult.StorageFailure -> return ManagementRuntimeExecutionResult.Failed(storageFailure(result.reason, false))
            else -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT installation read returned ${result::class.simpleName}",
            )
        }
        val installation = installationBefore.value
        if (installation.serverId != target.serverId) {
            return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT installation belongs to a different ServerId",
            )
        }
        when (val access = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> Unit
            RepositoryResult.NotFound -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT exact ManagementAccess is unavailable",
            )
            is RepositoryResult.Corruption -> return ManagementRuntimeExecutionResult.Failed(storageFailure(access.reason, true))
            is RepositoryResult.StorageFailure -> return ManagementRuntimeExecutionResult.Failed(storageFailure(access.reason, false))
            else -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT ManagementAccess read returned ${access::class.simpleName}",
            )
        }

        val scope = ManagementScope(
            operationId = before.snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            installationId = target.installationId,
        )
        val run = executor.executeQuickInspect(scope, installation, session)

        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return ManagementRuntimeExecutionResult.AdmissionLost
        when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> Unit
            is CurrentSession.Result -> return current.result
        }
        val after = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (after.revision != before.revision) {
            return ManagementRuntimeExecutionResult.StalePlan(
                admission.plan.operationId,
                before.revision,
                after.revision,
            )
        }
        when (val latestInstallation = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> if (latestInstallation.value.revision != installationBefore.revision || latestInstallation.value.value != installation) {
                return ManagementRuntimeExecutionResult.ContractViolation(
                    "QUICK_INSPECT installation changed while read-back was suspended",
                )
            }
            RepositoryResult.NotFound -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT installation disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return ManagementRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, true))
            is RepositoryResult.StorageFailure -> return ManagementRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, false))
            else -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT post-read installation lookup returned ${latestInstallation::class.simpleName}",
            )
        }
        when (val latestAccess = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> Unit
            RepositoryResult.NotFound -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT ManagementAccess disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return ManagementRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, true))
            is RepositoryResult.StorageFailure -> return ManagementRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, false))
            else -> return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT post-read ManagementAccess lookup returned ${latestAccess::class.simpleName}",
            )
        }

        val completedAt = now()
        return when (run) {
            is ManagementSshProbeRunResult.Completed -> {
                val snapshot = ManagementReadbackPolicy.quickInspect(
                    installation = installation,
                    evidence = run.evidence,
                    proofId = proofIdFactory(),
                    now = completedAt,
                )
                commitTerminal(before, OperationStatus.SUCCEEDED, "QUICK_INSPECT_RESULT", completedAt) { revision ->
                    ManagementRuntimeExecutionResult.Completed(snapshot, revision)
                }
            }
            is ManagementSshProbeRunResult.Failed -> {
                val kind = mapFailure(run.failure)
                commitTerminal(before, OperationStatus.FAILED, "QUICK_INSPECT_FAILED", completedAt) { revision ->
                    ManagementRuntimeExecutionResult.ReadbackFailed(kind, revision)
                }
            }
        }
    }

    private suspend fun commitTerminal(
        before: VersionedOperationSnapshot,
        status: OperationStatus,
        phaseName: String,
        at: Instant,
        completed: (OperationRevision) -> ManagementRuntimeExecutionResult,
    ): ManagementRuntimeExecutionResult {
        val terminal = before.snapshot.copy(
            status = status,
            checkpoint = OperationCheckpoint(phaseName, CheckpointSemantics.TERMINAL, at),
            updatedAt = at,
        )
        return when (val advance = journal.advance(before.snapshot.operationId, before.revision, terminal)) {
            is OperationJournalResult.Success -> completed(advance.value.revision)
            is OperationJournalResult.StaleRevision -> ManagementRuntimeExecutionResult.StalePlan(
                before.snapshot.operationId,
                advance.expected,
                advance.actual,
            )
            is OperationJournalResult.Corruption -> ManagementRuntimeExecutionResult.Failed(storageFailure(advance.reason, true))
            is OperationJournalResult.StorageFailure -> ManagementRuntimeExecutionResult.Failed(storageFailure(advance.reason, false))
            is OperationJournalResult.InvalidTransition -> ManagementRuntimeExecutionResult.Failed(
                contractFailure("QUICK_INSPECT terminal advance rejected: ${advance.reason}"),
            )
            else -> ManagementRuntimeExecutionResult.Failed(
                contractFailure("QUICK_INSPECT terminal advance returned ${advance::class.simpleName}"),
            )
        }
    }

    private fun mapFailure(failure: ManagementSshProbeExecutionFailure): ManagementFailureKind = when (failure) {
        ManagementSshProbeExecutionFailure.ScopeTargetMismatch,
        ManagementSshProbeExecutionFailure.ExactSessionBindingMismatch,
        ManagementSshProbeExecutionFailure.SessionClosed,
        ManagementSshProbeExecutionFailure.ProbeOutsideApprovedPolicy,
        -> ManagementFailureKind.INTERNAL_INVARIANT_FAILURE
        is ManagementSshProbeExecutionFailure.CommandUncertain -> ManagementFailureKind.TRANSPORT_UNAVAILABLE
        is ManagementSshProbeExecutionFailure.CommandFailed,
        ManagementSshProbeExecutionFailure.OutputTruncated,
        ManagementSshProbeExecutionFailure.MalformedProbeEvidence,
        -> ManagementFailureKind.MALFORMED_READBACK
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ManagementRuntimeExecutionResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT binding belongs to a different operation owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ManagementRuntimeExecutionResult.ContractViolation(
                "QUICK_INSPECT binding uses a different ServerAccessId than the durable target",
            )
        }
        return null
    }

    private fun currentSession(admission: RecoveryRuntimeAdmission, expected: SessionBinding): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(ManagementRuntimeExecutionResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                ManagementRuntimeExecutionResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                ManagementRuntimeExecutionResult.ContractViolation(
                    "Live QUICK_INSPECT session binding changed exact owner/access identity",
                ),
            )
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> return CurrentRead.Result(
                ManagementRuntimeExecutionResult.Failed(contractFailure("QUICK_INSPECT operation no longer exists")),
            )
            is OperationJournalResult.Corruption -> return CurrentRead.Result(
                ManagementRuntimeExecutionResult.Failed(storageFailure(result.reason, true)),
            )
            is OperationJournalResult.StorageFailure -> return CurrentRead.Result(
                ManagementRuntimeExecutionResult.Failed(storageFailure(result.reason, false)),
            )
            else -> return CurrentRead.Result(
                ManagementRuntimeExecutionResult.Failed(
                    contractFailure("QUICK_INSPECT exact journal read returned ${result::class.simpleName}"),
                ),
            )
        }
        if (current.snapshot.operationId != admission.plan.operationId || current.snapshot.target != admission.plan.target) {
            return CurrentRead.Result(
                ManagementRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Operation identity/target changed during QUICK_INSPECT",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                ManagementRuntimeExecutionResult.StalePlan(
                    admission.plan.operationId,
                    admission.plan.expectedRevision,
                    current.revision,
                ),
            )
        }
        if (current.snapshot.status in terminalStatuses || current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return CurrentRead.Result(
                ManagementRuntimeExecutionResult.Failed(contractFailure("QUICK_INSPECT admission points at terminal durable state")),
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
        data class Result(val result: ManagementRuntimeExecutionResult) : CurrentRead
    }
    private sealed interface CurrentSession {
        data class Handle(val handle: com.velumtegra.xuimobile.core.ssh.SshSessionHandle) : CurrentSession
        data class Result(val result: ManagementRuntimeExecutionResult) : CurrentSession
    }
    private companion object {
        val terminalStatuses = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
    }
}
