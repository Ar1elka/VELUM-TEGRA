package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.DeepDiagnosticPolicy
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.ManagementReadbackPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot
import com.velumtegra.xuimobile.core.model.ManagementFailureKind
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
import com.velumtegra.xuimobile.core.ssh.DeepDiagnosticSshProbeExecutionFailure
import com.velumtegra.xuimobile.core.ssh.DeepDiagnosticSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.DeepDiagnosticSshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutionFailure
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant
import java.util.UUID

sealed interface DeepDiagnosticRuntimeExecutionResult {
    data class Completed(
        val snapshot: DeepDiagnosticSnapshot,
        val committedRevision: OperationRevision,
    ) : DeepDiagnosticRuntimeExecutionResult

    data class ReadbackFailed(
        val kind: ManagementFailureKind,
        val committedRevision: OperationRevision,
    ) : DeepDiagnosticRuntimeExecutionResult

    data class NotDeepDiagnosticOperation(val operationType: OperationType) : DeepDiagnosticRuntimeExecutionResult
    data object AdmissionLost : DeepDiagnosticRuntimeExecutionResult
    data object SessionUnavailable : DeepDiagnosticRuntimeExecutionResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : DeepDiagnosticRuntimeExecutionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : DeepDiagnosticRuntimeExecutionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : DeepDiagnosticRuntimeExecutionResult
    data class ContractViolation(val reason: String) : DeepDiagnosticRuntimeExecutionResult
}

/**
 * Phase 6 DEEP_DIAGNOSTIC consumer for one already-open exact Phase 4 operation-owned session.
 *
 * The canonical Management read-back prelude and the deep-specific executor share the same exact
 * SessionId. Durable operation/installation/access/session identity is rechecked after each remote
 * suspend boundary. No baseline is rewritten, no WebPanel state is published and no mutation API is
 * reachable from this coordinator.
 */
class DeepDiagnosticRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val managementAccessRepository: ManagementAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val managementExecutor: ManagementSshProbeExecutor = ManagementSshProbeExecutor(),
    private val deepExecutor: DeepDiagnosticSshProbeExecutor = DeepDiagnosticSshProbeExecutor(),
    private val now: () -> Instant = Instant::now,
    private val proofIdFactory: () -> TargetProofId = { TargetProofId(UUID.randomUUID().toString()) },
) {
    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): DeepDiagnosticRuntimeExecutionResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return DeepDiagnosticRuntimeExecutionResult.AdmissionLost
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }

        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.DEEP_DIAGNOSTIC) {
            return DeepDiagnosticRuntimeExecutionResult.NotDeepDiagnosticOperation(before.snapshot.type)
        }
        if (before.snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC durable checkpoint must remain READ_ONLY until terminal result",
            )
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC must target one exact InstallationTarget",
            )

        val installationBefore = when (val result = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC target installation does not exist",
            )
            is RepositoryResult.Corruption -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(result.reason, true))
            is RepositoryResult.StorageFailure -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(result.reason, false))
            else -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC installation read returned ${result::class.simpleName}",
            )
        }
        val installation = installationBefore.value
        if (installation.serverId != target.serverId) {
            return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC installation belongs to a different ServerId",
            )
        }
        when (val access = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> Unit
            RepositoryResult.NotFound -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC exact ManagementAccess is unavailable",
            )
            is RepositoryResult.Corruption -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(access.reason, true))
            is RepositoryResult.StorageFailure -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(access.reason, false))
            else -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC ManagementAccess read returned ${access::class.simpleName}",
            )
        }

        val managementScope = ManagementScope(
            operationId = before.snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            installationId = target.installationId,
        )
        val deepScope = DeepDiagnosticScope(
            operationId = before.snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            installationId = target.installationId,
        )

        val managementRun = managementExecutor.executeQuickInspect(managementScope, installation, session)
        revalidateAfterRemote(admission, sessionBinding, before, installationBefore.revision, installation)?.let {
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
                    phaseName = "DEEP_DIAGNOSTIC_FAILED",
                    at = managementObservedAt,
                ) { revision ->
                    DeepDiagnosticRuntimeExecutionResult.ReadbackFailed(
                        kind = mapManagementFailure(managementRun.failure),
                        committedRevision = revision,
                    )
                }
            }
        }

        val deepRun = deepExecutor.execute(deepScope, installation, session)
        revalidateAfterRemote(admission, sessionBinding, before, installationBefore.revision, installation)?.let {
            return it
        }
        val completedAt = now()
        return when (deepRun) {
            is DeepDiagnosticSshProbeRunResult.Completed -> {
                val snapshot = DeepDiagnosticPolicy.evaluate(
                    scope = deepScope,
                    managementSnapshot = managementSnapshot,
                    evidence = deepRun.evidence,
                    now = completedAt,
                )
                commitTerminal(
                    before = before,
                    status = OperationStatus.SUCCEEDED,
                    phaseName = "DEEP_DIAGNOSTIC_RESULT",
                    at = completedAt,
                ) { revision ->
                    DeepDiagnosticRuntimeExecutionResult.Completed(snapshot, revision)
                }
            }
            is DeepDiagnosticSshProbeRunResult.Failed -> commitTerminal(
                before = before,
                status = OperationStatus.FAILED,
                phaseName = "DEEP_DIAGNOSTIC_FAILED",
                at = completedAt,
            ) { revision ->
                DeepDiagnosticRuntimeExecutionResult.ReadbackFailed(
                    kind = mapDeepFailure(deepRun.failure),
                    committedRevision = revision,
                )
            }
        }
    }

    private suspend fun revalidateAfterRemote(
        admission: RecoveryRuntimeAdmission,
        expectedSession: SessionBinding,
        before: VersionedOperationSnapshot,
        expectedInstallationRevision: com.velumtegra.xuimobile.core.domain.RecordRevision,
        expectedInstallation: XuiInstallation,
    ): DeepDiagnosticRuntimeExecutionResult? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return DeepDiagnosticRuntimeExecutionResult.AdmissionLost
        when (val current = currentSession(admission, expectedSession)) {
            is CurrentSession.Handle -> Unit
            is CurrentSession.Result -> return current.result
        }
        val after = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (after.revision != before.revision) {
            return DeepDiagnosticRuntimeExecutionResult.StalePlan(
                admission.plan.operationId,
                before.revision,
                after.revision,
            )
        }
        val target = before.snapshot.target as OperationTarget.InstallationTarget
        when (val latestInstallation = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> if (
                latestInstallation.value.revision != expectedInstallationRevision ||
                latestInstallation.value.value != expectedInstallation
            ) {
                return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                    "DEEP_DIAGNOSTIC installation changed while read-back was suspended",
                )
            }
            RepositoryResult.NotFound -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC installation disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, true))
            is RepositoryResult.StorageFailure -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, false))
            else -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC post-read installation lookup returned ${latestInstallation::class.simpleName}",
            )
        }
        when (val latestAccess = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> Unit
            RepositoryResult.NotFound -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC ManagementAccess disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, true))
            is RepositoryResult.StorageFailure -> return DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, false))
            else -> return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC post-read ManagementAccess lookup returned ${latestAccess::class.simpleName}",
            )
        }
        return null
    }

    private suspend fun commitTerminal(
        before: VersionedOperationSnapshot,
        status: OperationStatus,
        phaseName: String,
        at: Instant,
        completed: (OperationRevision) -> DeepDiagnosticRuntimeExecutionResult,
    ): DeepDiagnosticRuntimeExecutionResult {
        val terminal = before.snapshot.copy(
            status = status,
            checkpoint = OperationCheckpoint(phaseName, CheckpointSemantics.TERMINAL, at),
            updatedAt = at,
        )
        return when (val advance = journal.advance(before.snapshot.operationId, before.revision, terminal)) {
            is OperationJournalResult.Success -> completed(advance.value.revision)
            is OperationJournalResult.StaleRevision -> DeepDiagnosticRuntimeExecutionResult.StalePlan(
                before.snapshot.operationId,
                advance.expected,
                advance.actual,
            )
            is OperationJournalResult.Corruption -> DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(advance.reason, true))
            is OperationJournalResult.StorageFailure -> DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(advance.reason, false))
            is OperationJournalResult.InvalidTransition -> DeepDiagnosticRuntimeExecutionResult.Failed(
                contractFailure("DEEP_DIAGNOSTIC terminal advance rejected: ${advance.reason}"),
            )
            else -> DeepDiagnosticRuntimeExecutionResult.Failed(
                contractFailure("DEEP_DIAGNOSTIC terminal advance returned ${advance::class.simpleName}"),
            )
        }
    }

    private fun mapManagementFailure(failure: ManagementSshProbeExecutionFailure): ManagementFailureKind = when (failure) {
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

    private fun mapDeepFailure(failure: DeepDiagnosticSshProbeExecutionFailure): ManagementFailureKind = when (failure) {
        DeepDiagnosticSshProbeExecutionFailure.ScopeTargetMismatch,
        DeepDiagnosticSshProbeExecutionFailure.ExactSessionBindingMismatch,
        DeepDiagnosticSshProbeExecutionFailure.SessionClosed,
        DeepDiagnosticSshProbeExecutionFailure.ProbeOutsideApprovedPolicy,
        -> ManagementFailureKind.INTERNAL_INVARIANT_FAILURE
        is DeepDiagnosticSshProbeExecutionFailure.CommandUncertain -> ManagementFailureKind.TRANSPORT_UNAVAILABLE
        is DeepDiagnosticSshProbeExecutionFailure.CommandFailed,
        DeepDiagnosticSshProbeExecutionFailure.OutputTruncated,
        DeepDiagnosticSshProbeExecutionFailure.MalformedProbeEvidence,
        -> ManagementFailureKind.MALFORMED_READBACK
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): DeepDiagnosticRuntimeExecutionResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC binding belongs to a different operation owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                "DEEP_DIAGNOSTIC binding uses a different ServerAccessId than the durable target",
            )
        }
        return null
    }

    private fun currentSession(admission: RecoveryRuntimeAdmission, expected: SessionBinding): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(DeepDiagnosticRuntimeExecutionResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                DeepDiagnosticRuntimeExecutionResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                DeepDiagnosticRuntimeExecutionResult.ContractViolation(
                    "Live DEEP_DIAGNOSTIC session binding changed exact owner/access identity",
                ),
            )
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.Failed(contractFailure("DEEP_DIAGNOSTIC operation no longer exists")),
            )
            is OperationJournalResult.Corruption -> return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(result.reason, true)),
            )
            is OperationJournalResult.StorageFailure -> return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.Failed(storageFailure(result.reason, false)),
            )
            else -> return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.Failed(
                    contractFailure("DEEP_DIAGNOSTIC exact journal read returned ${result::class.simpleName}"),
                ),
            )
        }
        if (current.snapshot.operationId != admission.plan.operationId || current.snapshot.target != admission.plan.target) {
            return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Operation identity/target changed during DEEP_DIAGNOSTIC",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.StalePlan(
                    admission.plan.operationId,
                    admission.plan.expectedRevision,
                    current.revision,
                ),
            )
        }
        if (current.snapshot.status in terminalStatuses || current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return CurrentRead.Result(
                DeepDiagnosticRuntimeExecutionResult.Failed(
                    contractFailure("DEEP_DIAGNOSTIC admission points at terminal durable state"),
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
        data class Result(val result: DeepDiagnosticRuntimeExecutionResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: DeepDiagnosticRuntimeExecutionResult) : CurrentSession
    }

    private companion object {
        val terminalStatuses = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
    }
}
