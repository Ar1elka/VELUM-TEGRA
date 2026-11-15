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
import com.velumtegra.xuimobile.core.model.ServiceLogSnapshot
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
import com.velumtegra.xuimobile.core.model.ServiceLogFailure
import com.velumtegra.xuimobile.core.ssh.ServiceLogSshReader
import com.velumtegra.xuimobile.core.ssh.ServiceLogSshResult
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant
import java.util.UUID

sealed interface ServiceLogRuntimeExecutionResult {
    data class Completed(
        val snapshot: ServiceLogSnapshot,
        val committedRevision: OperationRevision,
    ) : ServiceLogRuntimeExecutionResult

    data class ReadbackFailed(
        val kind: ServiceLogFailure,
        val committedRevision: OperationRevision,
    ) : ServiceLogRuntimeExecutionResult

    data object NotServiceLogOperation : ServiceLogRuntimeExecutionResult
    data object AdmissionLost : ServiceLogRuntimeExecutionResult
    data object SessionUnavailable : ServiceLogRuntimeExecutionResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : ServiceLogRuntimeExecutionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ServiceLogRuntimeExecutionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ServiceLogRuntimeExecutionResult
    data class ContractViolation(val reason: String) : ServiceLogRuntimeExecutionResult
}

/** Read-only log consumer on the shared runtime/session/journal; checks exact ownership after suspensions. */
class ServiceLogRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val managementAccessRepository: ManagementAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val managementExecutor: ManagementSshProbeExecutor = ManagementSshProbeExecutor(),
    private val logReader: ServiceLogSshReader = ServiceLogSshReader(),
    private val accessRepository: ServerAccessRepository,
    private val now: () -> Instant = Instant::now,
    private val proofIdFactory: () -> TargetProofId = { TargetProofId(UUID.randomUUID().toString()) },
) {
    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ServiceLogRuntimeExecutionResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return ServiceLogRuntimeExecutionResult.AdmissionLost
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }

        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.SERVICE_LOG_READ) {
            return ServiceLogRuntimeExecutionResult.NotServiceLogOperation
        }
        if (before.snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ durable checkpoint must remain READ_ONLY until terminal result",
            )
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ must target one exact InstallationTarget",
            )

        val installationBefore = when (val result = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ target installation does not exist",
            )
            is RepositoryResult.Corruption -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(result.reason, true))
            is RepositoryResult.StorageFailure -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(result.reason, false))
            else -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ installation read returned ${result::class.simpleName}",
            )
        }
        val installation = installationBefore.value
        if (installation.id != target.installationId || installation.serverId != target.serverId) {
            return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ installation belongs to a different ServerId",
            )
        }
        when (val access = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> if (access.value.installationId != target.installationId ||
                access.value.serverAccessId != target.serverAccessId) return ServiceLogRuntimeExecutionResult.ContractViolation(
                    "ManagementAccess returned a different exact relation")
            RepositoryResult.NotFound -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ exact ManagementAccess is unavailable",
            )
            is RepositoryResult.Corruption -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(access.reason, true))
            is RepositoryResult.StorageFailure -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(access.reason, false))
            else -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ ManagementAccess read returned ${access::class.simpleName}",
            )
        }

        val accessBefore = (accessRepository.get(target.serverAccessId) as? RepositoryResult.Success)?.value
            ?: return ServiceLogRuntimeExecutionResult.ContractViolation("Exact SSH access unavailable")
        if (accessBefore.id != target.serverAccessId || accessBefore.serverId != target.serverId)
            return ServiceLogRuntimeExecutionResult.ContractViolation("Exact SSH access ownership mismatch")

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
                    phaseName = "SERVICE_LOG_READ_FAILED",
                    at = managementObservedAt,
                ) { revision ->
                    ServiceLogRuntimeExecutionResult.ReadbackFailed(
                        kind = ServiceLogFailure.TARGET_NOT_VERIFIED,
                        committedRevision = revision,
                    )
                }
            }
        }

        if (managementSnapshot.identityStatus != ManagementIdentityStatus.Matched) {
            return commitTerminal(before, OperationStatus.FAILED, "SERVICE_LOG_READ_FAILED", now()) {
                ServiceLogRuntimeExecutionResult.ReadbackFailed(ServiceLogFailure.TARGET_NOT_VERIFIED, it)
            }
        }
        val logRun = logReader.read(managementScope, installation, session)
        revalidateAfterRemote(admission, sessionBinding, before, installationBefore.revision, installation, accessBefore)?.let {
            return it
        }
        return when (logRun) {
            is ServiceLogSshResult.Completed -> commitTerminal(before, OperationStatus.SUCCEEDED,
                "SERVICE_LOG_READ_RESULT", now()) { ServiceLogRuntimeExecutionResult.Completed(logRun.snapshot, it) }
            is ServiceLogSshResult.Failed -> commitTerminal(before, OperationStatus.FAILED,
                "SERVICE_LOG_READ_FAILED", now()) { ServiceLogRuntimeExecutionResult.ReadbackFailed(logRun.kind, it) }
        }
    }

    private suspend fun revalidateAfterRemote(
        admission: RecoveryRuntimeAdmission,
        expectedSession: SessionBinding,
        before: VersionedOperationSnapshot,
        expectedInstallationRevision: com.velumtegra.xuimobile.core.domain.RecordRevision,
        expectedInstallation: XuiInstallation,
        expectedAccess: ServerAccess,
    ): ServiceLogRuntimeExecutionResult? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return ServiceLogRuntimeExecutionResult.AdmissionLost
        when (val current = currentSession(admission, expectedSession)) {
            is CurrentSession.Handle -> Unit
            is CurrentSession.Result -> return current.result
        }
        val after = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (after.revision != before.revision) {
            return ServiceLogRuntimeExecutionResult.StalePlan(
                admission.plan.operationId,
                before.revision,
                after.revision,
            )
        }
        if (after.snapshot != before.snapshot) return ServiceLogRuntimeExecutionResult.ContractViolation(
            "Operation snapshot changed without a revision advance")
        val currentAccess = (accessRepository.get(expectedAccess.id) as? RepositoryResult.Success)?.value
        if (currentAccess != expectedAccess) return ServiceLogRuntimeExecutionResult.ContractViolation(
            "Exact SSH access changed during service log read")
        val target = before.snapshot.target as OperationTarget.InstallationTarget
        when (val latestInstallation = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> if (
                latestInstallation.value.revision != expectedInstallationRevision ||
                latestInstallation.value.value != expectedInstallation
            ) {
                return ServiceLogRuntimeExecutionResult.ContractViolation(
                    "SERVICE_LOG_READ installation changed while read-back was suspended",
                )
            }
            RepositoryResult.NotFound -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ installation disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, true))
            is RepositoryResult.StorageFailure -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(latestInstallation.reason, false))
            else -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ post-read installation lookup returned ${latestInstallation::class.simpleName}",
            )
        }
        when (val latestAccess = managementAccessRepository.get(target.installationId, target.serverAccessId)) {
            is RepositoryResult.Success -> if (latestAccess.value.installationId != target.installationId ||
                latestAccess.value.serverAccessId != target.serverAccessId) return ServiceLogRuntimeExecutionResult.ContractViolation(
                    "ManagementAccess returned a different exact relation")
            RepositoryResult.NotFound -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ ManagementAccess disappeared while read-back was suspended",
            )
            is RepositoryResult.Corruption -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, true))
            is RepositoryResult.StorageFailure -> return ServiceLogRuntimeExecutionResult.Failed(storageFailure(latestAccess.reason, false))
            else -> return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ post-read ManagementAccess lookup returned ${latestAccess::class.simpleName}",
            )
        }
        return null
    }

    private suspend fun commitTerminal(
        before: VersionedOperationSnapshot,
        status: OperationStatus,
        phaseName: String,
        at: Instant,
        completed: (OperationRevision) -> ServiceLogRuntimeExecutionResult,
    ): ServiceLogRuntimeExecutionResult {
        val terminal = before.snapshot.copy(
            status = status,
            checkpoint = OperationCheckpoint(phaseName, CheckpointSemantics.TERMINAL, at),
            updatedAt = at,
        )
        return when (val advance = journal.advance(before.snapshot.operationId, before.revision, terminal)) {
            is OperationJournalResult.Success -> completed(advance.value.revision)
            is OperationJournalResult.StaleRevision -> ServiceLogRuntimeExecutionResult.StalePlan(
                before.snapshot.operationId,
                advance.expected,
                advance.actual,
            )
            is OperationJournalResult.Corruption -> ServiceLogRuntimeExecutionResult.Failed(storageFailure(advance.reason, true))
            is OperationJournalResult.StorageFailure -> ServiceLogRuntimeExecutionResult.Failed(storageFailure(advance.reason, false))
            is OperationJournalResult.InvalidTransition -> ServiceLogRuntimeExecutionResult.Failed(
                contractFailure("SERVICE_LOG_READ terminal advance rejected: ${advance.reason}"),
            )
            else -> ServiceLogRuntimeExecutionResult.Failed(
                contractFailure("SERVICE_LOG_READ terminal advance returned ${advance::class.simpleName}"),
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ServiceLogRuntimeExecutionResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ binding belongs to a different operation owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ServiceLogRuntimeExecutionResult.ContractViolation(
                "SERVICE_LOG_READ binding uses a different ServerAccessId than the durable target",
            )
        }
        return null
    }

    private fun currentSession(admission: RecoveryRuntimeAdmission, expected: SessionBinding): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(ServiceLogRuntimeExecutionResult.SessionUnavailable)
        if (!current.isOpen) return CurrentSession.Result(ServiceLogRuntimeExecutionResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                ServiceLogRuntimeExecutionResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                ServiceLogRuntimeExecutionResult.ContractViolation(
                    "Live SERVICE_LOG_READ session binding changed exact owner/access identity",
                ),
            )
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.Failed(contractFailure("SERVICE_LOG_READ operation no longer exists")),
            )
            is OperationJournalResult.Corruption -> return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.Failed(storageFailure(result.reason, true)),
            )
            is OperationJournalResult.StorageFailure -> return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.Failed(storageFailure(result.reason, false)),
            )
            else -> return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.Failed(
                    contractFailure("SERVICE_LOG_READ exact journal read returned ${result::class.simpleName}"),
                ),
            )
        }
        if (current.snapshot.operationId != admission.plan.operationId || current.snapshot.target != admission.plan.target) {
            return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Operation identity/target changed during SERVICE_LOG_READ",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.StalePlan(
                    admission.plan.operationId,
                    admission.plan.expectedRevision,
                    current.revision,
                ),
            )
        }
        if (current.snapshot.status in terminalStatuses || current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return CurrentRead.Result(
                ServiceLogRuntimeExecutionResult.Failed(
                    contractFailure("SERVICE_LOG_READ admission points at terminal durable state"),
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
        data class Result(val result: ServiceLogRuntimeExecutionResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: ServiceLogRuntimeExecutionResult) : CurrentSession
    }

    private companion object {
        val terminalStatuses = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
    }
}
