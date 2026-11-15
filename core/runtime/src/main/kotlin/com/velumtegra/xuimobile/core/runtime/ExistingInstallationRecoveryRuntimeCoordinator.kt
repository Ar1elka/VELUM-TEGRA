package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.ExistingInstallationRecoveryRepairPolicyResult
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationRecoveryRepair
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRecoveryDiagnosisResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRecoveryRepairResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartPostVerifyResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant

internal fun interface ExistingInstallationRecoveryDiagnosisPort {
    suspend fun diagnose(
        preflight: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryDiagnosisResult
}

internal fun interface ExistingInstallationRecoveryRepairPort {
    suspend fun dispatch(
        repair: VerifiedExistingInstallationRecoveryRepair,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryRepairResult
}

internal fun interface ExistingInstallationRecoveryPostVerifyPort {
    suspend fun verify(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRestartPostVerifyResult
}

/**
 * Phase 9.5 runtime path for RECOVERY. Diagnosis is read-only. The only mutation admitted by this
 * slice is the exact start of an inactive proven x-ui.service. MUTATION_IN_FLIGHT is durable before
 * dispatch, and recovery from that checkpoint can only advance to read-only post-verification.
 */
class ExistingInstallationRecoveryRuntimeCoordinator internal constructor(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val serverMutationRegistry: ServerMutationLeaseRegistry,
    private val entryRegistry: ExistingInstallationRecoveryEntryRegistry,
    private val diagnosisPort: ExistingInstallationRecoveryDiagnosisPort,
    private val repairPort: ExistingInstallationRecoveryRepairPort,
    private val postVerifyPort: ExistingInstallationRecoveryPostVerifyPort,
    private val now: () -> Instant = Instant::now,
) {
    fun registerPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationRecoveryEntryRegistrationResult = entryRegistry.register(preflight)

    fun discardPreflight(operationId: OperationId): Boolean = entryRegistry.discard(operationId)

    suspend fun prepareTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationRecoveryPreparationResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationRecoveryPreparationResult.AdmissionLost
        }
        val current = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result.toPreparationResult()
        }
        if (current.snapshot.type != OperationType.RECOVERY) {
            return ExistingInstallationRecoveryPreparationResult.NotRecoveryOperation
        }
        current.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRecoveryPreparationResult.ContractViolation(
                "RECOVERY runtime requires exact InstallationTarget",
            )

        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            entryRegistry.discard(current.snapshot.operationId)
        }

        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> when (val entry = entryRegistry.inspect(current, now())) {
                ExistingInstallationRecoveryEntryInspection.Available -> ExistingInstallationRecoveryPreparationResult.TransportRequired
                ExistingInstallationRecoveryEntryInspection.Missing -> ExistingInstallationRecoveryPreparationResult.FreshPreflightRequired
                ExistingInstallationRecoveryEntryInspection.Expired -> {
                    entryRegistry.discard(current.snapshot.operationId)
                    ExistingInstallationRecoveryPreparationResult.FreshPreflightExpired
                }
                is ExistingInstallationRecoveryEntryInspection.ContractViolation ->
                    ExistingInstallationRecoveryPreparationResult.ContractViolation(entry.reason)
            }
            CheckpointSemantics.MUTATION_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
            -> ExistingInstallationRecoveryPreparationResult.TransportRequired
            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationRecoveryPreparationResult.Completed(finishCommitted(current))
            CheckpointSemantics.TERMINAL -> ExistingInstallationRecoveryPreparationResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL recovery checkpoint",
            )
            else -> ExistingInstallationRecoveryPreparationResult.ContractViolation(
                "Recovery durable checkpoint ${current.snapshot.checkpoint.semantics} is outside Phase 9.5 runtime contract",
            )
        }
    }

    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationRecoveryRuntimeResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return ExistingInstallationRecoveryRuntimeResult.AdmissionLost
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }
        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.RECOVERY) return ExistingInstallationRecoveryRuntimeResult.NotRecoveryOperation
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRecoveryRuntimeResult.ContractViolation("RECOVERY runtime requires exact InstallationTarget")

        return when (before.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> executeFreshRecovery(before, target, session)
            CheckpointSemantics.MUTATION_IN_FLIGHT -> {
                val post = when (val promoted = promoteMutationToPostVerify(before)) {
                    is PromoteResult.Promoted -> promoted.current
                    is PromoteResult.Result -> return promoted.result
                }
                verifyAndCommit(post, target, session)
            }
            CheckpointSemantics.POST_VERIFY_REQUIRED -> verifyAndCommit(before, target, session)
            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationRecoveryRuntimeResult.Completed(finishCommitted(before))
            CheckpointSemantics.TERMINAL -> ExistingInstallationRecoveryRuntimeResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL recovery checkpoint",
            )
            else -> ExistingInstallationRecoveryRuntimeResult.ContractViolation(
                "Recovery durable checkpoint ${before.snapshot.checkpoint.semantics} is outside Phase 9.5 runtime contract",
            )
        }
    }

    private suspend fun executeFreshRecovery(
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryRuntimeResult {
        val installation = when (val loaded = loadInstallation(target)) {
            is InstallationRead.Value -> loaded.installation
            is InstallationRead.Result -> return loaded.result
        }
        val preflight = when (val entry = entryRegistry.consume(current, now())) {
            is ExistingInstallationRecoveryEntryConsumeResult.Consumed -> entry.preflight
            ExistingInstallationRecoveryEntryConsumeResult.Missing -> return ExistingInstallationRecoveryRuntimeResult.FreshPreflightRequired
            ExistingInstallationRecoveryEntryConsumeResult.Expired -> return ExistingInstallationRecoveryRuntimeResult.FreshPreflightExpired
            is ExistingInstallationRecoveryEntryConsumeResult.ContractViolation ->
                return ExistingInstallationRecoveryRuntimeResult.ContractViolation(entry.reason)
        }

        val diagnosis = diagnosisPort.diagnose(preflight, current, installation, session)
        val diagnosed = diagnosis as? ExistingInstallationRecoveryDiagnosisResult.Diagnosed
            ?: return ExistingInstallationRecoveryRuntimeResult.Diagnosis(diagnosis)

        return when (val decision = diagnosed.repairDecision) {
            is ExistingInstallationRecoveryRepairPolicyResult.NoRepairRequired -> {
                val committed = when (val commit = advanceCommitVerified(current, decision.evidence.observedAt, "RECOVERY_HEALTHY_COMMIT_VERIFIED")) {
                    is CommitResult.Committed -> commit.current
                    is CommitResult.Result -> return commit.result
                }
                ExistingInstallationRecoveryRuntimeResult.Completed(finishCommitted(committed))
            }
            is ExistingInstallationRecoveryRepairPolicyResult.Blocked -> ExistingInstallationRecoveryRuntimeResult.Diagnosis(diagnosis)
            is ExistingInstallationRecoveryRepairPolicyResult.Verified -> executeRepairWithBarriers(current, target, decision.repair, session)
        }
    }

    private suspend fun executeRepairWithBarriers(
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        repair: VerifiedExistingInstallationRecoveryRepair,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryRuntimeResult {
        val lease = when (val acquired = serverMutationRegistry.tryAcquire(target.serverId, current.snapshot.operationId)) {
            is ServerMutationAcquireResult.Acquired -> acquired.lease
            ServerMutationAcquireResult.AlreadyOwned -> return ExistingInstallationRecoveryRuntimeResult.ServerMutationAlreadyOwned
        }
        try {
            val durable = when (val list = journal.listNonTerminal()) {
                is OperationJournalResult.Success -> list.value
                is OperationJournalResult.Corruption -> return ExistingInstallationRecoveryRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, list.reason),
                )
                is OperationJournalResult.StorageFailure -> return ExistingInstallationRecoveryRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, list.reason),
                )
                else -> return ExistingInstallationRecoveryRuntimeResult.Failed(contractFailure("Recovery listNonTerminal returned ${list::class.simpleName}"))
            }
            when (val barrier = DurableServerMutationBarrierPolicy.evaluate(target.serverId, durable.map { it.snapshot })) {
                ServerMutationBarrierDecision.Allowed -> Unit
                is ServerMutationBarrierDecision.BlockedByUncertainMutation ->
                    return ExistingInstallationRecoveryRuntimeResult.BlockedByDurableMutation(barrier.blockers)
            }
            return ExistingInstallationRecoveryRuntimeResult.Repair(repairPort.dispatch(repair, current, session))
        } finally {
            serverMutationRegistry.release(lease)
        }
    }

    private suspend fun promoteMutationToPostVerify(current: VersionedOperationSnapshot): PromoteResult {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return PromoteResult.Result(ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery runtime clock moved before durable operation time"))
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint("RECOVERY_POST_VERIFY_REQUIRED", CheckpointSemantics.POST_VERIFY_REQUIRED, at),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> PromoteResult.Promoted(advanced.value)
            is OperationJournalResult.StaleRevision -> PromoteResult.Result(
                ExistingInstallationRecoveryRuntimeResult.StalePlan(current.snapshot.operationId, advanced.expected, advanced.actual),
            )
            is OperationJournalResult.Corruption -> PromoteResult.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason)),
            )
            is OperationJournalResult.StorageFailure -> PromoteResult.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason)),
            )
            else -> PromoteResult.Result(ExistingInstallationRecoveryRuntimeResult.Failed(contractFailure("Recovery post-verify advance rejected")))
        }
    }

    private suspend fun verifyAndCommit(
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryRuntimeResult {
        val installation = when (val loaded = loadInstallation(target)) {
            is InstallationRead.Value -> loaded.installation
            is InstallationRead.Result -> return loaded.result
        }
        return when (val verified = postVerifyPort.verify(current, installation, session)) {
            is ExistingInstallationRestartPostVerifyResult.Verified -> {
                val committed = when (val commit = advanceCommitVerified(current, verified.observedAt, "RECOVERY_COMMIT_VERIFIED")) {
                    is CommitResult.Committed -> commit.current
                    is CommitResult.Result -> return commit.result
                }
                ExistingInstallationRecoveryRuntimeResult.Completed(finishCommitted(committed))
            }
            else -> ExistingInstallationRecoveryRuntimeResult.Reconciliation(verified)
        }
    }

    private suspend fun advanceCommitVerified(
        current: VersionedOperationSnapshot,
        observedAt: Instant,
        phaseName: String,
    ): CommitResult {
        val at = maxOf(now(), observedAt)
        if (at.isBefore(current.snapshot.updatedAt)) {
            return CommitResult.Result(ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery verified observation predates durable operation time"))
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(phaseName, CheckpointSemantics.COMMIT_VERIFIED, at),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> CommitResult.Committed(advanced.value)
            is OperationJournalResult.StaleRevision -> CommitResult.Result(
                ExistingInstallationRecoveryRuntimeResult.StalePlan(current.snapshot.operationId, advanced.expected, advanced.actual),
            )
            is OperationJournalResult.Corruption -> CommitResult.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason)),
            )
            is OperationJournalResult.StorageFailure -> CommitResult.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason)),
            )
            else -> CommitResult.Result(ExistingInstallationRecoveryRuntimeResult.Failed(contractFailure("Recovery COMMIT_VERIFIED advance rejected")))
        }
    }

    private suspend fun finishCommitted(current: VersionedOperationSnapshot): ExistingInstallationRecoveryCompletionResult {
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.COMMIT_VERIFIED) {
            return ExistingInstallationRecoveryCompletionResult.ContractViolation("Recovery local completion requires COMMIT_VERIFIED")
        }
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return ExistingInstallationRecoveryCompletionResult.ContractViolation("Recovery local completion clock moved backward")
        val next = current.snapshot.copy(
            status = OperationStatus.SUCCEEDED,
            checkpoint = OperationCheckpoint("RECOVERY_SUCCEEDED", CheckpointSemantics.TERMINAL, at),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> ExistingInstallationRecoveryCompletionResult.Committed(advanced.value)
            is OperationJournalResult.StaleRevision -> ExistingInstallationRecoveryCompletionResult.StalePlan(current.snapshot.operationId, advanced.expected, advanced.actual)
            is OperationJournalResult.Corruption -> ExistingInstallationRecoveryCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
            )
            is OperationJournalResult.StorageFailure -> ExistingInstallationRecoveryCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
            )
            else -> ExistingInstallationRecoveryCompletionResult.Failed(contractFailure("Recovery terminal advance rejected"))
        }
    }

    private suspend fun loadInstallation(target: OperationTarget.InstallationTarget): InstallationRead {
        val installation = when (val read = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> read.value.value
            RepositoryResult.NotFound -> return InstallationRead.Result(
                ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery target installation no longer exists locally"),
            )
            is RepositoryResult.Corruption -> return InstallationRead.Result(
                ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery target installation storage is corrupt: ${read.reason}"),
            )
            is RepositoryResult.StorageFailure -> return InstallationRead.Result(
                ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery target installation storage failed: ${read.reason}"),
            )
            else -> return InstallationRead.Result(
                ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery installation lookup returned ${read::class.simpleName}"),
            )
        }
        if (installation.id != target.installationId || installation.serverId != target.serverId) {
            return InstallationRead.Result(ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery installation no longer matches durable target"))
        }
        return InstallationRead.Value(installation)
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ExistingInstallationRecoveryRuntimeResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery session belongs to a different OperationId")
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ExistingInstallationRecoveryRuntimeResult.ContractViolation("Recovery session uses a different ServerAccessId than durable target")
        }
        return null
    }

    private fun currentSession(admission: RecoveryRuntimeAdmission, expected: SessionBinding): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(ExistingInstallationRecoveryRuntimeResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(ExistingInstallationRecoveryRuntimeResult.StaleSession(expected.sessionId, current.binding.sessionId))
        }
        if (current.binding != expected) {
            return CurrentSession.Result(ExistingInstallationRecoveryRuntimeResult.ContractViolation("Live recovery session binding changed exact owner/access identity"))
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> return CurrentRead.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(contractFailure("Recovery operation no longer exists")),
            )
            is OperationJournalResult.Corruption -> return CurrentRead.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, result.reason)),
            )
            is OperationJournalResult.StorageFailure -> return CurrentRead.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, result.reason)),
            )
            else -> return CurrentRead.Result(
                ExistingInstallationRecoveryRuntimeResult.Failed(contractFailure("Recovery exact journal read returned ${result::class.simpleName}")),
            )
        }
        if (current.snapshot.operationId != admission.plan.operationId || current.snapshot.target != admission.plan.target) {
            return CurrentRead.Result(ExistingInstallationRecoveryRuntimeResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, "Recovery operation identity/target changed after runtime admission"),
            ))
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(ExistingInstallationRecoveryRuntimeResult.StalePlan(
                admission.plan.operationId, admission.plan.expectedRevision, current.revision,
            ))
        }
        if (current.snapshot.status in TERMINAL_STATUSES || current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return CurrentRead.Result(ExistingInstallationRecoveryRuntimeResult.Failed(contractFailure("Recovery admission points at terminal durable state")))
        }
        return CurrentRead.Current(current)
    }

    private fun contractFailure(reason: String) = RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION, reason)

    private sealed interface PromoteResult {
        data class Promoted(val current: VersionedOperationSnapshot) : PromoteResult
        data class Result(val result: ExistingInstallationRecoveryRuntimeResult) : PromoteResult
    }
    private sealed interface CommitResult {
        data class Committed(val current: VersionedOperationSnapshot) : CommitResult
        data class Result(val result: ExistingInstallationRecoveryRuntimeResult) : CommitResult
    }
    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: ExistingInstallationRecoveryRuntimeResult) : CurrentRead
    }
    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: ExistingInstallationRecoveryRuntimeResult) : CurrentSession
    }
    private sealed interface InstallationRead {
        data class Value(val installation: XuiInstallation) : InstallationRead
        data class Result(val result: ExistingInstallationRecoveryRuntimeResult) : InstallationRead
    }
    private companion object {
        val TERMINAL_STATUSES = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
    }
}

sealed interface ExistingInstallationRecoveryPreparationResult {
    data object NotRecoveryOperation : ExistingInstallationRecoveryPreparationResult
    data object TransportRequired : ExistingInstallationRecoveryPreparationResult
    data object FreshPreflightRequired : ExistingInstallationRecoveryPreparationResult
    data object FreshPreflightExpired : ExistingInstallationRecoveryPreparationResult
    data class Completed(val result: ExistingInstallationRecoveryCompletionResult) : ExistingInstallationRecoveryPreparationResult
    data object AdmissionLost : ExistingInstallationRecoveryPreparationResult
    data class StalePlan(val operationId: OperationId, val expectedRevision: OperationRevision, val actualRevision: OperationRevision) : ExistingInstallationRecoveryPreparationResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationRecoveryPreparationResult
    data class ContractViolation(val reason: String) : ExistingInstallationRecoveryPreparationResult
}

sealed interface ExistingInstallationRecoveryRuntimeResult {
    data object NotRecoveryOperation : ExistingInstallationRecoveryRuntimeResult
    data object AdmissionLost : ExistingInstallationRecoveryRuntimeResult
    data object SessionUnavailable : ExistingInstallationRecoveryRuntimeResult
    data class StaleSession(val expectedSessionId: SessionId, val actualSessionId: SessionId?) : ExistingInstallationRecoveryRuntimeResult
    data object FreshPreflightRequired : ExistingInstallationRecoveryRuntimeResult
    data object FreshPreflightExpired : ExistingInstallationRecoveryRuntimeResult
    data object ServerMutationAlreadyOwned : ExistingInstallationRecoveryRuntimeResult
    data class BlockedByDurableMutation(val blockers: List<UncertainMutationBlocker>) : ExistingInstallationRecoveryRuntimeResult
    data class Diagnosis(val result: ExistingInstallationRecoveryDiagnosisResult) : ExistingInstallationRecoveryRuntimeResult
    data class Repair(val result: ExistingInstallationRecoveryRepairResult) : ExistingInstallationRecoveryRuntimeResult
    data class Reconciliation(val result: ExistingInstallationRestartPostVerifyResult) : ExistingInstallationRecoveryRuntimeResult
    data class Completed(val result: ExistingInstallationRecoveryCompletionResult) : ExistingInstallationRecoveryRuntimeResult
    data class StalePlan(val operationId: OperationId, val expectedRevision: OperationRevision, val actualRevision: OperationRevision) : ExistingInstallationRecoveryRuntimeResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationRecoveryRuntimeResult
    data class ContractViolation(val reason: String) : ExistingInstallationRecoveryRuntimeResult
}

sealed interface ExistingInstallationRecoveryCompletionResult {
    data class Committed(val durable: VersionedOperationSnapshot) : ExistingInstallationRecoveryCompletionResult
    data class StalePlan(val operationId: OperationId, val expectedRevision: OperationRevision, val actualRevision: OperationRevision) : ExistingInstallationRecoveryCompletionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationRecoveryCompletionResult
    data class ContractViolation(val reason: String) : ExistingInstallationRecoveryCompletionResult
}

private fun ExistingInstallationRecoveryRuntimeResult.toPreparationResult(): ExistingInstallationRecoveryPreparationResult = when (this) {
    ExistingInstallationRecoveryRuntimeResult.NotRecoveryOperation -> ExistingInstallationRecoveryPreparationResult.NotRecoveryOperation
    ExistingInstallationRecoveryRuntimeResult.AdmissionLost -> ExistingInstallationRecoveryPreparationResult.AdmissionLost
    is ExistingInstallationRecoveryRuntimeResult.StalePlan -> ExistingInstallationRecoveryPreparationResult.StalePlan(operationId, expectedRevision, actualRevision)
    is ExistingInstallationRecoveryRuntimeResult.Failed -> ExistingInstallationRecoveryPreparationResult.Failed(failure)
    is ExistingInstallationRecoveryRuntimeResult.ContractViolation -> ExistingInstallationRecoveryPreparationResult.ContractViolation(reason)
    else -> ExistingInstallationRecoveryPreparationResult.ContractViolation(
        "Unexpected session-dependent recovery result during local preparation: ${this::class.simpleName}",
    )
}
