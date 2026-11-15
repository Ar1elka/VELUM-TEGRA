package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ReviewedExistingInstallationActionPlanPolicy
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
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
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationUninstallDispatchResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationUninstallAbsenceResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant

internal fun interface ExistingInstallationUninstallDispatchPort {
    suspend fun dispatch(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallDispatchResult
}

internal fun interface ExistingInstallationUninstallAbsencePort {
    suspend fun verify(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallAbsenceResult
}

/**
 * Phase 9.6 runtime integration for exact existing-installation UNINSTALL.
 *
 * It reuses the Phase 4 runtime lease, reconnect/session registry, durable same-server barrier and
 * process-local mutation lease. A fresh dispatch needs a one-shot process-local verified preflight.
 * After MUTATION_IN_FLIGHT, only a new recovery admission may reconnect and enter read-only verify;
 * no durable unsafe checkpoint can ever return to the uninstall dispatcher.
 */
class ExistingInstallationUninstallRuntimeCoordinator internal constructor(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val serverMutationRegistry: ServerMutationLeaseRegistry,
    private val entryRegistry: ExistingInstallationUninstallEntryRegistry,
    private val dispatchPort: ExistingInstallationUninstallDispatchPort,
    private val absencePort: ExistingInstallationUninstallAbsencePort,
    private val now: () -> Instant = Instant::now,
) {
    fun registerPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationUninstallEntryRegistrationResult = entryRegistry.register(preflight)

    fun discardPreflight(operationId: OperationId): Boolean = entryRegistry.discard(operationId)

    suspend fun prepareTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationUninstallPreparationResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationUninstallPreparationResult.AdmissionLost
        }
        val current = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result.toPreparationResult()
        }
        if (current.snapshot.type != OperationType.UNINSTALL) {
            return ExistingInstallationUninstallPreparationResult.NotUninstallOperation
        }
        current.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationUninstallPreparationResult.ContractViolation(
                "UNINSTALL runtime requires exact InstallationTarget",
            )

        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            entryRegistry.discard(current.snapshot.operationId)
        }

        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> when (val entry = entryRegistry.inspect(current, now())) {
                ExistingInstallationUninstallEntryInspection.Available ->
                    ExistingInstallationUninstallPreparationResult.TransportRequired

                ExistingInstallationUninstallEntryInspection.Missing ->
                    ExistingInstallationUninstallPreparationResult.FreshPreflightRequired

                ExistingInstallationUninstallEntryInspection.Expired -> {
                    entryRegistry.discard(current.snapshot.operationId)
                    ExistingInstallationUninstallPreparationResult.FreshPreflightExpired
                }

                is ExistingInstallationUninstallEntryInspection.ContractViolation ->
                    ExistingInstallationUninstallPreparationResult.ContractViolation(entry.reason)
            }

            CheckpointSemantics.MUTATION_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
            -> ExistingInstallationUninstallPreparationResult.TransportRequired

            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationUninstallPreparationResult.Completed(
                finishCommitted(current),
            )

            CheckpointSemantics.TERMINAL -> ExistingInstallationUninstallPreparationResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL uninstall checkpoint",
            )

            else -> ExistingInstallationUninstallPreparationResult.ContractViolation(
                "Uninstall durable checkpoint ${current.snapshot.checkpoint.semantics} is outside Phase 9.6 runtime contract",
            )
        }
    }

    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationUninstallRuntimeResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationUninstallRuntimeResult.AdmissionLost
        }
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }
        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.UNINSTALL) {
            return ExistingInstallationUninstallRuntimeResult.NotUninstallOperation
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                "UNINSTALL runtime requires exact InstallationTarget",
            )

        return when (before.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> executeFreshUninstall(
                admission = admission,
                current = before,
                target = target,
                session = session,
            )

            CheckpointSemantics.MUTATION_IN_FLIGHT -> {
                val postVerify = when (val promoted = promoteUninstallToPostVerify(before)) {
                    is PromoteResult.Promoted -> promoted.current
                    is PromoteResult.Result -> return promoted.result
                }
                verifyAndCommit(postVerify, target, session)
            }

            CheckpointSemantics.POST_VERIFY_REQUIRED -> verifyAndCommit(before, target, session)

            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationUninstallRuntimeResult.Completed(
                finishCommitted(before),
            )

            CheckpointSemantics.TERMINAL -> ExistingInstallationUninstallRuntimeResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL uninstall checkpoint",
            )

            else -> ExistingInstallationUninstallRuntimeResult.ContractViolation(
                "Uninstall durable checkpoint ${before.snapshot.checkpoint.semantics} is outside Phase 9.6 runtime contract",
            )
        }
    }

    private suspend fun executeFreshUninstall(
        admission: RecoveryRuntimeAdmission,
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallRuntimeResult {
        val lease = when (val acquired = serverMutationRegistry.tryAcquire(target.serverId, current.snapshot.operationId)) {
            is ServerMutationAcquireResult.Acquired -> acquired.lease
            ServerMutationAcquireResult.AlreadyOwned -> {
                return ExistingInstallationUninstallRuntimeResult.ServerMutationAlreadyOwned
            }
        }

        try {
            val durable = when (val list = journal.listNonTerminal()) {
                is OperationJournalResult.Success -> list.value
                is OperationJournalResult.Corruption -> {
                    return ExistingInstallationUninstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            list.reason,
                        ),
                    )
                }
                is OperationJournalResult.StorageFailure -> {
                    return ExistingInstallationUninstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            list.reason,
                        ),
                    )
                }
                else -> {
                    return ExistingInstallationUninstallRuntimeResult.Failed(
                        contractFailure("Uninstall listNonTerminal returned ${list::class.simpleName}"),
                    )
                }
            }
            when (
                val barrier = DurableServerMutationBarrierPolicy.evaluate(
                    serverId = target.serverId,
                    durableOperations = durable.map { it.snapshot },
                )
            ) {
                ServerMutationBarrierDecision.Allowed -> Unit
                is ServerMutationBarrierDecision.BlockedByUncertainMutation -> {
                    return ExistingInstallationUninstallRuntimeResult.BlockedByDurableMutation(barrier.blockers)
                }
            }

            val latest = when (val read = readCurrent(admission)) {
                is CurrentRead.Current -> read.value
                is CurrentRead.Result -> return read.result
            }
            if (latest.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
                return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Fresh uninstall lost MUTATION_NOT_STARTED before dispatch",
                )
            }

            val preflight = when (val entry = entryRegistry.consume(latest, now())) {
                is ExistingInstallationUninstallEntryConsumeResult.Consumed -> entry.preflight
                ExistingInstallationUninstallEntryConsumeResult.Missing -> {
                    return ExistingInstallationUninstallRuntimeResult.FreshPreflightRequired
                }
                ExistingInstallationUninstallEntryConsumeResult.Expired -> {
                    return ExistingInstallationUninstallRuntimeResult.FreshPreflightExpired
                }
                is ExistingInstallationUninstallEntryConsumeResult.ContractViolation -> {
                    return ExistingInstallationUninstallRuntimeResult.ContractViolation(entry.reason)
                }
            }
            val plan = runCatching { ReviewedExistingInstallationActionPlanPolicy.build(preflight) }
                .getOrElse {
                    return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                        "Verified uninstall preflight could not build the canonical reviewed plan",
                    )
                }

            return ExistingInstallationUninstallRuntimeResult.Dispatch(
                dispatchPort.dispatch(preflight, plan, latest, session),
            )
        } finally {
            serverMutationRegistry.release(lease)
        }
    }

    /** MUTATION_IN_FLIGHT may only move forward into read-only post-verification. */
    private suspend fun promoteUninstallToPostVerify(
        current: VersionedOperationSnapshot,
    ): PromoteResult {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return PromoteResult.Result(
                ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Uninstall runtime clock moved before durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "UNINSTALL_POST_VERIFY_REQUIRED",
                semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> PromoteResult.Promoted(advanced.value)
            is OperationJournalResult.StaleRevision -> PromoteResult.Result(
                ExistingInstallationUninstallRuntimeResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> PromoteResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
                ),
            )
            is OperationJournalResult.StorageFailure -> PromoteResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
                ),
            )
            is OperationJournalResult.InvalidTransition -> PromoteResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    contractFailure("Uninstall post-verify advance rejected: ${advanced.reason}"),
                ),
            )
            else -> PromoteResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    contractFailure("Uninstall post-verify advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private suspend fun verifyAndCommit(
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallRuntimeResult {
        val installation = when (val read = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> read.value.value
            RepositoryResult.NotFound -> {
                return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Uninstall target installation no longer exists locally",
                )
            }
            is RepositoryResult.Corruption -> {
                return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Uninstall target installation storage is corrupt: ${read.reason}",
                )
            }
            is RepositoryResult.StorageFailure -> {
                return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Uninstall target installation storage failed: ${read.reason}",
                )
            }
            else -> {
                return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Uninstall target installation lookup returned ${read::class.simpleName}",
                )
            }
        }
        if (installation.id != target.installationId || installation.serverId != target.serverId) {
            return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                "Uninstall target installation no longer matches durable target",
            )
        }

        return when (val verified = absencePort.verify(current, installation, session)) {
            is ExistingInstallationUninstallAbsenceResult.Verified -> {
                val committed = when (val commit = advanceCommitVerified(current, verified.observedAt)) {
                    is CommitResult.Committed -> commit.current
                    is CommitResult.Result -> return commit.result
                }
                ExistingInstallationUninstallRuntimeResult.Completed(finishCommitted(committed))
            }

            else -> ExistingInstallationUninstallRuntimeResult.Reconciliation(verified)
        }
    }

    private suspend fun advanceCommitVerified(
        current: VersionedOperationSnapshot,
        observedAt: Instant,
    ): CommitResult {
        val at = maxOf(now(), observedAt)
        if (at.isBefore(current.snapshot.updatedAt)) {
            return CommitResult.Result(
                ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Uninstall verified observation predates durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "UNINSTALL_REMOTE_ABSENCE_COMMIT_VERIFIED",
                semantics = CheckpointSemantics.COMMIT_VERIFIED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> CommitResult.Committed(advanced.value)
            is OperationJournalResult.StaleRevision -> CommitResult.Result(
                ExistingInstallationUninstallRuntimeResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> CommitResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
                ),
            )
            is OperationJournalResult.StorageFailure -> CommitResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
                ),
            )
            is OperationJournalResult.InvalidTransition -> CommitResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    contractFailure("Uninstall COMMIT_VERIFIED advance rejected: ${advanced.reason}"),
                ),
            )
            else -> CommitResult.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    contractFailure("Uninstall COMMIT_VERIFIED advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private suspend fun finishCommitted(
        current: VersionedOperationSnapshot,
    ): ExistingInstallationUninstallCompletionResult {
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.COMMIT_VERIFIED) {
            return ExistingInstallationUninstallCompletionResult.ContractViolation(
                "Uninstall local completion requires COMMIT_VERIFIED",
            )
        }
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return ExistingInstallationUninstallCompletionResult.ContractViolation(
                "Uninstall local completion clock moved backward",
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.SUCCEEDED,
            checkpoint = OperationCheckpoint(
                phaseName = "UNINSTALL_SUCCEEDED_REMOTE_ABSENCE_LOCAL_CLEANUP_DEFERRED",
                semantics = CheckpointSemantics.TERMINAL,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> ExistingInstallationUninstallCompletionResult.Committed(
                durable = advanced.value,
                localCleanup = ExistingInstallationUninstallLocalCleanupDisposition.DEFERRED_REFERENCES_RETAINED,
            )
            is OperationJournalResult.StaleRevision -> ExistingInstallationUninstallCompletionResult.StalePlan(
                current.snapshot.operationId,
                advanced.expected,
                advanced.actual,
            )
            is OperationJournalResult.Corruption -> ExistingInstallationUninstallCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
            )
            is OperationJournalResult.StorageFailure -> ExistingInstallationUninstallCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
            )
            is OperationJournalResult.InvalidTransition -> ExistingInstallationUninstallCompletionResult.Failed(
                contractFailure("Uninstall terminal advance rejected: ${advanced.reason}"),
            )
            else -> ExistingInstallationUninstallCompletionResult.Failed(
                contractFailure("Uninstall terminal advance returned ${advanced::class.simpleName}"),
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ExistingInstallationUninstallRuntimeResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                "Uninstall session belongs to a different OperationId",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ExistingInstallationUninstallRuntimeResult.ContractViolation(
                "Uninstall session uses a different ServerAccessId than durable target",
            )
        }
        return null
    }

    private fun currentSession(
        admission: RecoveryRuntimeAdmission,
        expected: SessionBinding,
    ): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(ExistingInstallationUninstallRuntimeResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                ExistingInstallationUninstallRuntimeResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                ExistingInstallationUninstallRuntimeResult.ContractViolation(
                    "Live uninstall session binding changed exact owner/access identity",
                ),
            )
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> {
                return CurrentRead.Result(
                    ExistingInstallationUninstallRuntimeResult.Failed(
                        contractFailure("Uninstall operation no longer exists"),
                    ),
                )
            }
            is OperationJournalResult.Corruption -> {
                return CurrentRead.Result(
                    ExistingInstallationUninstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, result.reason),
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return CurrentRead.Result(
                    ExistingInstallationUninstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, result.reason),
                    ),
                )
            }
            else -> {
                return CurrentRead.Result(
                    ExistingInstallationUninstallRuntimeResult.Failed(
                        contractFailure("Uninstall exact journal read returned ${result::class.simpleName}"),
                    ),
                )
            }
        }
        if (current.snapshot.operationId != admission.plan.operationId ||
            current.snapshot.target != admission.plan.target
        ) {
            return CurrentRead.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Uninstall operation identity/target changed after runtime admission",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                ExistingInstallationUninstallRuntimeResult.StalePlan(
                    admission.plan.operationId,
                    admission.plan.expectedRevision,
                    current.revision,
                ),
            )
        }
        if (current.snapshot.status in TERMINAL_STATUSES ||
            current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        ) {
            return CurrentRead.Result(
                ExistingInstallationUninstallRuntimeResult.Failed(
                    contractFailure("Uninstall admission points at terminal durable state"),
                ),
            )
        }
        return CurrentRead.Current(current)
    }

    private fun contractFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason,
    )

    private sealed interface PromoteResult {
        data class Promoted(val current: VersionedOperationSnapshot) : PromoteResult
        data class Result(val result: ExistingInstallationUninstallRuntimeResult) : PromoteResult
    }

    private sealed interface CommitResult {
        data class Committed(val current: VersionedOperationSnapshot) : CommitResult
        data class Result(val result: ExistingInstallationUninstallRuntimeResult) : CommitResult
    }

    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: ExistingInstallationUninstallRuntimeResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: ExistingInstallationUninstallRuntimeResult) : CurrentSession
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

sealed interface ExistingInstallationUninstallPreparationResult {
    data object NotUninstallOperation : ExistingInstallationUninstallPreparationResult
    data object TransportRequired : ExistingInstallationUninstallPreparationResult
    data object FreshPreflightRequired : ExistingInstallationUninstallPreparationResult
    data object FreshPreflightExpired : ExistingInstallationUninstallPreparationResult
    data class Completed(
        val result: ExistingInstallationUninstallCompletionResult,
    ) : ExistingInstallationUninstallPreparationResult
    data object AdmissionLost : ExistingInstallationUninstallPreparationResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationUninstallPreparationResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationUninstallPreparationResult
    data class ContractViolation(val reason: String) : ExistingInstallationUninstallPreparationResult
}

sealed interface ExistingInstallationUninstallRuntimeResult {
    data object NotUninstallOperation : ExistingInstallationUninstallRuntimeResult
    data object AdmissionLost : ExistingInstallationUninstallRuntimeResult
    data object SessionUnavailable : ExistingInstallationUninstallRuntimeResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : ExistingInstallationUninstallRuntimeResult
    data object FreshPreflightRequired : ExistingInstallationUninstallRuntimeResult
    data object FreshPreflightExpired : ExistingInstallationUninstallRuntimeResult
    data object ServerMutationAlreadyOwned : ExistingInstallationUninstallRuntimeResult
    data class BlockedByDurableMutation(
        val blockers: List<UncertainMutationBlocker>,
    ) : ExistingInstallationUninstallRuntimeResult
    data class Dispatch(
        val result: ExistingInstallationUninstallDispatchResult,
    ) : ExistingInstallationUninstallRuntimeResult
    data class Reconciliation(
        val result: ExistingInstallationUninstallAbsenceResult,
    ) : ExistingInstallationUninstallRuntimeResult
    data class Completed(
        val result: ExistingInstallationUninstallCompletionResult,
    ) : ExistingInstallationUninstallRuntimeResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationUninstallRuntimeResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationUninstallRuntimeResult
    data class ContractViolation(val reason: String) : ExistingInstallationUninstallRuntimeResult
}

enum class ExistingInstallationUninstallLocalCleanupDisposition {
    DEFERRED_REFERENCES_RETAINED,
}

sealed interface ExistingInstallationUninstallCompletionResult {
    data class Committed(
        val durable: VersionedOperationSnapshot,
        val localCleanup: ExistingInstallationUninstallLocalCleanupDisposition,
    ) : ExistingInstallationUninstallCompletionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationUninstallCompletionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationUninstallCompletionResult
    data class ContractViolation(val reason: String) : ExistingInstallationUninstallCompletionResult
}

private fun ExistingInstallationUninstallRuntimeResult.toPreparationResult(): ExistingInstallationUninstallPreparationResult =
    when (this) {
        ExistingInstallationUninstallRuntimeResult.NotUninstallOperation ->
            ExistingInstallationUninstallPreparationResult.NotUninstallOperation
        ExistingInstallationUninstallRuntimeResult.AdmissionLost ->
            ExistingInstallationUninstallPreparationResult.AdmissionLost
        is ExistingInstallationUninstallRuntimeResult.StalePlan -> ExistingInstallationUninstallPreparationResult.StalePlan(
            operationId,
            expectedRevision,
            actualRevision,
        )
        is ExistingInstallationUninstallRuntimeResult.Failed ->
            ExistingInstallationUninstallPreparationResult.Failed(failure)
        is ExistingInstallationUninstallRuntimeResult.ContractViolation ->
            ExistingInstallationUninstallPreparationResult.ContractViolation(reason)
        else -> ExistingInstallationUninstallPreparationResult.ContractViolation(
            "Unexpected session-dependent uninstall result during local preparation: ${this::class.simpleName}",
        )
    }
