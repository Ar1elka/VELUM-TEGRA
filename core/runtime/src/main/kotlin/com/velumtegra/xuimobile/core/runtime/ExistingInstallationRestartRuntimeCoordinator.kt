package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.ExistingInstallationRestartConfirmation
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ReviewedExistingInstallationActionPlanPolicy
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.ExistingInstallationServiceAction
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ExistingInstallationMutationBarrierState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartDispatchResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartPostVerifyResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartPreflightResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationRestartPreflightRejection
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant

internal fun interface ExistingInstallationRestartDispatchPort {
    suspend fun dispatch(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationRestartDispatchResult
}

internal fun interface ExistingInstallationRestartPostVerifyPort {
    suspend fun verify(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRestartPostVerifyResult
}

/**
 * Phase 9.4 runtime integration for exact existing-installation RESTART.
 *
 * It reuses the Phase 4 runtime lease, reconnect/session registry, durable same-server barrier and
 * process-local mutation lease. A fresh dispatch needs a one-shot process-local verified preflight.
 * After RESTART_IN_FLIGHT, only a new recovery admission may reconnect and enter read-only verify;
 * no durable unsafe checkpoint can ever return to the restart dispatcher.
 */
internal fun interface ExistingInstallationRestartPreflightPort {
    suspend fun verify(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        session: SshSessionHandle, barrier: ExistingInstallationMutationBarrierState): ExistingInstallationRestartPreflightResult
}

class ExistingInstallationRestartRuntimeCoordinator internal constructor(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val serverMutationRegistry: ServerMutationLeaseRegistry,
    private val entryRegistry: ExistingInstallationRestartEntryRegistry,
    private val dispatchPort: ExistingInstallationRestartDispatchPort,
    private val postVerifyPort: ExistingInstallationRestartPostVerifyPort,
    private val now: () -> Instant = Instant::now,
    private val accessRepository: ServerAccessRepository? = null,
    private val preflightPort: ExistingInstallationRestartPreflightPort? = null,
) {
    fun registerConfirmation(confirmation: ExistingInstallationRestartConfirmation): Boolean = entryRegistry.registerConfirmation(confirmation)
    fun registerPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationRestartEntryRegistrationResult = entryRegistry.register(preflight)

    fun discardPreflight(operationId: OperationId): Boolean = entryRegistry.discard(operationId)

    suspend fun prepareTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationRestartPreparationResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationRestartPreparationResult.AdmissionLost
        }
        val current = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result.toPreparationResult()
        }
        if (current.snapshot.type != OperationType.RESTART) {
            return ExistingInstallationRestartPreparationResult.NotRestartOperation
        }
        current.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRestartPreparationResult.ContractViolation(
                "RESTART runtime requires exact InstallationTarget",
            )

        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            entryRegistry.discard(current.snapshot.operationId)
        }

        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> when (val entry = entryRegistry.inspect(current, now())) {
                ExistingInstallationRestartEntryInspection.Available ->
                    ExistingInstallationRestartPreparationResult.TransportRequired

                ExistingInstallationRestartEntryInspection.Missing ->
                    if (entryRegistry.hasConfirmation(current, now())) ExistingInstallationRestartPreparationResult.TransportRequired
                    else ExistingInstallationRestartPreparationResult.FreshPreflightRequired

                ExistingInstallationRestartEntryInspection.Expired -> {
                    entryRegistry.discard(current.snapshot.operationId)
                    ExistingInstallationRestartPreparationResult.FreshPreflightExpired
                }

                is ExistingInstallationRestartEntryInspection.ContractViolation ->
                    ExistingInstallationRestartPreparationResult.ContractViolation(entry.reason)
            }

            CheckpointSemantics.RESTART_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
            -> ExistingInstallationRestartPreparationResult.TransportRequired

            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationRestartPreparationResult.Completed(
                finishCommitted(current),
            )

            CheckpointSemantics.TERMINAL -> ExistingInstallationRestartPreparationResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL restart checkpoint",
            )

            else -> ExistingInstallationRestartPreparationResult.ContractViolation(
                "Restart durable checkpoint ${current.snapshot.checkpoint.semantics} is outside Phase 9.4 runtime contract",
            )
        }
    }

    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationRestartRuntimeResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationRestartRuntimeResult.AdmissionLost
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
        if (before.snapshot.type != OperationType.RESTART) {
            return ExistingInstallationRestartRuntimeResult.NotRestartOperation
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRestartRuntimeResult.ContractViolation(
                "RESTART runtime requires exact InstallationTarget",
            )

        return when (before.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> executeFreshRestart(
                admission = admission,
                current = before,
                target = target,
                session = session,
            )

            CheckpointSemantics.RESTART_IN_FLIGHT -> {
                val postVerify = when (val promoted = promoteRestartToPostVerify(before)) {
                    is PromoteResult.Promoted -> promoted.current
                    is PromoteResult.Result -> return promoted.result
                }
                verifyAndCommit(postVerify, target, session)
            }

            CheckpointSemantics.POST_VERIFY_REQUIRED -> verifyAndCommit(before, target, session)

            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationRestartRuntimeResult.Completed(
                finishCommitted(before),
            )

            CheckpointSemantics.TERMINAL -> ExistingInstallationRestartRuntimeResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL restart checkpoint",
            )

            else -> ExistingInstallationRestartRuntimeResult.ContractViolation(
                "Restart durable checkpoint ${before.snapshot.checkpoint.semantics} is outside Phase 9.4 runtime contract",
            )
        }
    }

    private suspend fun executeFreshRestart(
        admission: RecoveryRuntimeAdmission,
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationRestartRuntimeResult {
        val lease = when (val acquired = serverMutationRegistry.tryAcquire(target.serverId, current.snapshot.operationId)) {
            is ServerMutationAcquireResult.Acquired -> acquired.lease
            ServerMutationAcquireResult.AlreadyOwned -> {
                return ExistingInstallationRestartRuntimeResult.ServerMutationAlreadyOwned
            }
        }

        try {
            val durable = when (val list = journal.listNonTerminal()) {
                is OperationJournalResult.Success -> list.value
                is OperationJournalResult.Corruption -> {
                    return ExistingInstallationRestartRuntimeResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            list.reason,
                        ),
                    )
                }
                is OperationJournalResult.StorageFailure -> {
                    return ExistingInstallationRestartRuntimeResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            list.reason,
                        ),
                    )
                }
                else -> {
                    return ExistingInstallationRestartRuntimeResult.Failed(
                        contractFailure("Restart listNonTerminal returned ${list::class.simpleName}"),
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
                    return ExistingInstallationRestartRuntimeResult.BlockedByDurableMutation(barrier.blockers)
                }
            }

            val latest = when (val read = readCurrent(admission)) {
                is CurrentRead.Current -> read.value
                is CurrentRead.Result -> return read.result
            }
            if (latest.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
                return ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Fresh restart lost MUTATION_NOT_STARTED before dispatch",
                )
            }

            if (entryRegistry.inspect(latest, now()) == ExistingInstallationRestartEntryInspection.Missing) {
                val confirmation = entryRegistry.consumeConfirmation(latest, now())
                    ?: return ExistingInstallationRestartRuntimeResult.FreshPreflightRequired
                if (!metadataMatches(confirmation)) return rejectPreflight(latest, ExistingInstallationRestartPreflightRejection.LOCAL_METADATA_CHANGED)
                val verifier = preflightPort ?: return rejectPreflight(latest, ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
                when (val observed = verifier.verify(latest, confirmation.expectedInstallation, confirmation.expectedAccess,
                    session, ExistingInstallationMutationBarrierState.PROVEN_CLEAR)) {
                    is ExistingInstallationRestartPreflightResult.Rejected -> return rejectPreflight(latest, observed.reason)
                    is ExistingInstallationRestartPreflightResult.Verified -> {
                        if (now().isAfter(confirmation.validUntil)) return rejectPreflight(latest, ExistingInstallationRestartPreflightRejection.CONFIRMATION_EXPIRED)
                        when (val reread = readCurrent(admission)) {
                            is CurrentRead.Result -> return reread.result
                            is CurrentRead.Current -> if (reread.value != latest)
                                return ExistingInstallationRestartRuntimeResult.ContractViolation("Restart preflight durable scope changed")
                        }
                        if (!metadataMatches(confirmation)) return rejectPreflight(latest, ExistingInstallationRestartPreflightRejection.LOCAL_METADATA_CHANGED)
                        if (entryRegistry.register(observed.preflight) != ExistingInstallationRestartEntryRegistrationResult.Registered)
                            return rejectPreflight(latest, ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
                    }
                }
            }
            val preflight = when (val entry = entryRegistry.consume(latest, now())) {
                is ExistingInstallationRestartEntryConsumeResult.Consumed -> entry.preflight
                ExistingInstallationRestartEntryConsumeResult.Missing -> {
                    return ExistingInstallationRestartRuntimeResult.FreshPreflightRequired
                }
                ExistingInstallationRestartEntryConsumeResult.Expired -> {
                    return ExistingInstallationRestartRuntimeResult.FreshPreflightExpired
                }
                is ExistingInstallationRestartEntryConsumeResult.ContractViolation -> {
                    return ExistingInstallationRestartRuntimeResult.ContractViolation(entry.reason)
                }
            }
            val plan = runCatching { ReviewedExistingInstallationActionPlanPolicy.build(preflight) }
                .getOrElse {
                    return ExistingInstallationRestartRuntimeResult.ContractViolation(
                        "Verified restart preflight could not build the canonical reviewed plan",
                    )
                }

            return ExistingInstallationRestartRuntimeResult.Dispatch(
                dispatchPort.dispatch(preflight, plan, latest, session),
            )
        } finally {
            serverMutationRegistry.release(lease)
        }
    }

    private suspend fun metadataMatches(c: ExistingInstallationRestartConfirmation): Boolean {
        val i = installationRepository.get(c.target.installationId)
        val a = accessRepository?.get(c.target.serverAccessId) ?: return false
        return i is RepositoryResult.Success && a is RepositoryResult.Success &&
            i.value.value == c.expectedInstallation && a.value == c.expectedAccess
    }
    private suspend fun rejectPreflight(current: VersionedOperationSnapshot,
        reason: ExistingInstallationRestartPreflightRejection): ExistingInstallationRestartRuntimeResult {
        entryRegistry.discard(current.snapshot.operationId)
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return ExistingInstallationRestartRuntimeResult.ContractViolation("Restart clock regressed")
        val next = current.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = OperationCheckpoint(current.servicePhaseName("RESTART_PREFLIGHT_" + reason.name), CheckpointSemantics.TERMINAL, at), updatedAt = at)
        return when (val write = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> ExistingInstallationRestartRuntimeResult.PreflightRejected(reason, write.value)
            is OperationJournalResult.StaleRevision -> ExistingInstallationRestartRuntimeResult.StalePlan(current.snapshot.operationId, write.expected, write.actual)
            else -> ExistingInstallationRestartRuntimeResult.Failed(contractFailure("Restart preflight result could not be recorded"))
        }
    }

    /** RESTART_IN_FLIGHT may only move forward into read-only post-verification. */
    private suspend fun promoteRestartToPostVerify(
        current: VersionedOperationSnapshot,
    ): PromoteResult {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return PromoteResult.Result(
                ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Restart runtime clock moved before durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = current.servicePhaseName("RESTART_POST_VERIFY_REQUIRED"),
                semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> PromoteResult.Promoted(advanced.value)
            is OperationJournalResult.StaleRevision -> PromoteResult.Result(
                ExistingInstallationRestartRuntimeResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> PromoteResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
                ),
            )
            is OperationJournalResult.StorageFailure -> PromoteResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
                ),
            )
            is OperationJournalResult.InvalidTransition -> PromoteResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    contractFailure("Restart post-verify advance rejected: ${advanced.reason}"),
                ),
            )
            else -> PromoteResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    contractFailure("Restart post-verify advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private suspend fun verifyAndCommit(
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationRestartRuntimeResult {
        val installation = when (val read = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> read.value.value
            RepositoryResult.NotFound -> {
                return ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Restart target installation no longer exists locally",
                )
            }
            is RepositoryResult.Corruption -> {
                return ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Restart target installation storage is corrupt: ${read.reason}",
                )
            }
            is RepositoryResult.StorageFailure -> {
                return ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Restart target installation storage failed: ${read.reason}",
                )
            }
            else -> {
                return ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Restart target installation lookup returned ${read::class.simpleName}",
                )
            }
        }
        if (installation.id != target.installationId || installation.serverId != target.serverId) {
            return ExistingInstallationRestartRuntimeResult.ContractViolation(
                "Restart target installation no longer matches durable target",
            )
        }

        return when (val verified = postVerifyPort.verify(current, installation, session)) {
            is ExistingInstallationRestartPostVerifyResult.Verified -> {
                val committed = when (val commit = advanceCommitVerified(current, verified.observedAt)) {
                    is CommitResult.Committed -> commit.current
                    is CommitResult.Result -> return commit.result
                }
                ExistingInstallationRestartRuntimeResult.Completed(finishCommitted(committed))
            }

            else -> ExistingInstallationRestartRuntimeResult.Reconciliation(verified)
        }
    }

    private suspend fun advanceCommitVerified(
        current: VersionedOperationSnapshot,
        observedAt: Instant,
    ): CommitResult {
        val at = maxOf(now(), observedAt)
        if (at.isBefore(current.snapshot.updatedAt)) {
            return CommitResult.Result(
                ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Restart verified observation predates durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = current.servicePhaseName("RESTART_COMMIT_VERIFIED"),
                semantics = CheckpointSemantics.COMMIT_VERIFIED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> CommitResult.Committed(advanced.value)
            is OperationJournalResult.StaleRevision -> CommitResult.Result(
                ExistingInstallationRestartRuntimeResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> CommitResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
                ),
            )
            is OperationJournalResult.StorageFailure -> CommitResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
                ),
            )
            is OperationJournalResult.InvalidTransition -> CommitResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    contractFailure("Restart COMMIT_VERIFIED advance rejected: ${advanced.reason}"),
                ),
            )
            else -> CommitResult.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    contractFailure("Restart COMMIT_VERIFIED advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private suspend fun finishCommitted(
        current: VersionedOperationSnapshot,
    ): ExistingInstallationRestartCompletionResult {
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.COMMIT_VERIFIED) {
            return ExistingInstallationRestartCompletionResult.ContractViolation(
                "Restart local completion requires COMMIT_VERIFIED",
            )
        }
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return ExistingInstallationRestartCompletionResult.ContractViolation(
                "Restart local completion clock moved backward",
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.SUCCEEDED,
            checkpoint = OperationCheckpoint(
                phaseName = current.servicePhaseName("RESTART_SUCCEEDED"),
                semantics = CheckpointSemantics.TERMINAL,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> ExistingInstallationRestartCompletionResult.Committed(advanced.value)
            is OperationJournalResult.StaleRevision -> ExistingInstallationRestartCompletionResult.StalePlan(
                current.snapshot.operationId,
                advanced.expected,
                advanced.actual,
            )
            is OperationJournalResult.Corruption -> ExistingInstallationRestartCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
            )
            is OperationJournalResult.StorageFailure -> ExistingInstallationRestartCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
            )
            is OperationJournalResult.InvalidTransition -> ExistingInstallationRestartCompletionResult.Failed(
                contractFailure("Restart terminal advance rejected: ${advanced.reason}"),
            )
            else -> ExistingInstallationRestartCompletionResult.Failed(
                contractFailure("Restart terminal advance returned ${advanced::class.simpleName}"),
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ExistingInstallationRestartRuntimeResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return ExistingInstallationRestartRuntimeResult.ContractViolation(
                "Restart session belongs to a different OperationId",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ExistingInstallationRestartRuntimeResult.ContractViolation(
                "Restart session uses a different ServerAccessId than durable target",
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
            ?: return CurrentSession.Result(ExistingInstallationRestartRuntimeResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                ExistingInstallationRestartRuntimeResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                ExistingInstallationRestartRuntimeResult.ContractViolation(
                    "Live restart session binding changed exact owner/access identity",
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
                    ExistingInstallationRestartRuntimeResult.Failed(
                        contractFailure("Restart operation no longer exists"),
                    ),
                )
            }
            is OperationJournalResult.Corruption -> {
                return CurrentRead.Result(
                    ExistingInstallationRestartRuntimeResult.Failed(
                        RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, result.reason),
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return CurrentRead.Result(
                    ExistingInstallationRestartRuntimeResult.Failed(
                        RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, result.reason),
                    ),
                )
            }
            else -> {
                return CurrentRead.Result(
                    ExistingInstallationRestartRuntimeResult.Failed(
                        contractFailure("Restart exact journal read returned ${result::class.simpleName}"),
                    ),
                )
            }
        }
        if (current.snapshot.operationId != admission.plan.operationId ||
            current.snapshot.target != admission.plan.target
        ) {
            return CurrentRead.Result(
                ExistingInstallationRestartRuntimeResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Restart operation identity/target changed after runtime admission",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                ExistingInstallationRestartRuntimeResult.StalePlan(
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
                ExistingInstallationRestartRuntimeResult.Failed(
                    contractFailure("Restart admission points at terminal durable state"),
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
        data class Result(val result: ExistingInstallationRestartRuntimeResult) : PromoteResult
    }

    private sealed interface CommitResult {
        data class Committed(val current: VersionedOperationSnapshot) : CommitResult
        data class Result(val result: ExistingInstallationRestartRuntimeResult) : CommitResult
    }

    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: ExistingInstallationRestartRuntimeResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: ExistingInstallationRestartRuntimeResult) : CurrentSession
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

sealed interface ExistingInstallationRestartPreparationResult {
    data object NotRestartOperation : ExistingInstallationRestartPreparationResult
    data object TransportRequired : ExistingInstallationRestartPreparationResult
    data object FreshPreflightRequired : ExistingInstallationRestartPreparationResult
    data object FreshPreflightExpired : ExistingInstallationRestartPreparationResult
    data class Completed(
        val result: ExistingInstallationRestartCompletionResult,
    ) : ExistingInstallationRestartPreparationResult
    data object AdmissionLost : ExistingInstallationRestartPreparationResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationRestartPreparationResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationRestartPreparationResult
    data class ContractViolation(val reason: String) : ExistingInstallationRestartPreparationResult
}

sealed interface ExistingInstallationRestartRuntimeResult {
    data object NotRestartOperation : ExistingInstallationRestartRuntimeResult
    data object AdmissionLost : ExistingInstallationRestartRuntimeResult
    data object SessionUnavailable : ExistingInstallationRestartRuntimeResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : ExistingInstallationRestartRuntimeResult
    data object FreshPreflightRequired : ExistingInstallationRestartRuntimeResult
    data object FreshPreflightExpired : ExistingInstallationRestartRuntimeResult
    data class PreflightRejected(val reason: ExistingInstallationRestartPreflightRejection,
        val durable: VersionedOperationSnapshot) : ExistingInstallationRestartRuntimeResult
    data object ServerMutationAlreadyOwned : ExistingInstallationRestartRuntimeResult
    data class BlockedByDurableMutation(
        val blockers: List<UncertainMutationBlocker>,
    ) : ExistingInstallationRestartRuntimeResult
    data class Dispatch(
        val result: ExistingInstallationRestartDispatchResult,
    ) : ExistingInstallationRestartRuntimeResult
    data class Reconciliation(
        val result: ExistingInstallationRestartPostVerifyResult,
    ) : ExistingInstallationRestartRuntimeResult
    data class Completed(
        val result: ExistingInstallationRestartCompletionResult,
    ) : ExistingInstallationRestartRuntimeResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationRestartRuntimeResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationRestartRuntimeResult
    data class ContractViolation(val reason: String) : ExistingInstallationRestartRuntimeResult
}

sealed interface ExistingInstallationRestartCompletionResult {
    data class Committed(
        val durable: VersionedOperationSnapshot,
    ) : ExistingInstallationRestartCompletionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationRestartCompletionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationRestartCompletionResult
    data class ContractViolation(val reason: String) : ExistingInstallationRestartCompletionResult
}

private fun ExistingInstallationRestartRuntimeResult.toPreparationResult(): ExistingInstallationRestartPreparationResult =
    when (this) {
        ExistingInstallationRestartRuntimeResult.NotRestartOperation ->
            ExistingInstallationRestartPreparationResult.NotRestartOperation
        ExistingInstallationRestartRuntimeResult.AdmissionLost ->
            ExistingInstallationRestartPreparationResult.AdmissionLost
        is ExistingInstallationRestartRuntimeResult.StalePlan -> ExistingInstallationRestartPreparationResult.StalePlan(
            operationId,
            expectedRevision,
            actualRevision,
        )
        is ExistingInstallationRestartRuntimeResult.Failed ->
            ExistingInstallationRestartPreparationResult.Failed(failure)
        is ExistingInstallationRestartRuntimeResult.ContractViolation ->
            ExistingInstallationRestartPreparationResult.ContractViolation(reason)
        else -> ExistingInstallationRestartPreparationResult.ContractViolation(
            "Unexpected session-dependent restart result during local preparation: ${this::class.simpleName}",
        )
    }


private fun VersionedOperationSnapshot.servicePhaseName(restartPhaseName: String): String =
    ExistingInstallationServiceAction.nextPhaseName(snapshot.checkpoint.phaseName, restartPhaseName)
