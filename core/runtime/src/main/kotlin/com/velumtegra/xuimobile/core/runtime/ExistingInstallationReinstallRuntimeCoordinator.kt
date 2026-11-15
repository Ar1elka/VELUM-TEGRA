package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.ExistingInstallationReinstallPublicationRequest
import com.velumtegra.xuimobile.core.domain.ExistingInstallationReinstallPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ReviewedExistingInstallationActionPlanPolicy
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.InstallationOwnership
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
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationReinstallDispatchResult
import com.velumtegra.xuimobile.core.ssh.ExistingInstallationReinstallPostVerifyResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant

internal fun interface ExistingInstallationReinstallDispatchPort {
    suspend fun dispatch(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallDispatchResult
}

internal fun interface ExistingInstallationReinstallPostVerifyPort {
    suspend fun verify(
        current: VersionedOperationSnapshot,
        managedInstallId: com.velumtegra.xuimobile.core.model.ManagedInstallId,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallPostVerifyResult
}

/**
 * Phase 9.7 runtime integration for exact existing-installation REINSTALL.
 *
 * It reuses the Phase 4 runtime lease, reconnect/session registry, durable same-server barrier and
 * process-local mutation lease. A fresh dispatch needs a one-shot process-local verified preflight.
 * After MUTATION_IN_FLIGHT, only a new recovery admission may reconnect and enter read-only verify;
 * no durable unsafe checkpoint can ever return to the reinstall dispatcher.
 */
class ExistingInstallationReinstallRuntimeCoordinator internal constructor(
    private val journal: OperationJournal,
    private val installationRepository: XuiInstallationRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val serverMutationRegistry: ServerMutationLeaseRegistry,
    private val entryRegistry: ExistingInstallationReinstallEntryRegistry,
    private val dispatchPort: ExistingInstallationReinstallDispatchPort,
    private val postVerifyPort: ExistingInstallationReinstallPostVerifyPort,
    private val publisher: ManagementEnrollmentPublisher,
    private val now: () -> Instant = Instant::now,
) {
    fun registerPreflight(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationReinstallEntryRegistrationResult = entryRegistry.register(preflight)

    fun discardPreflight(operationId: OperationId): Boolean = entryRegistry.discard(operationId)

    suspend fun prepareTransport(
        admission: RecoveryRuntimeAdmission,
    ): ExistingInstallationReinstallPreparationResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationReinstallPreparationResult.AdmissionLost
        }
        val current = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result.toPreparationResult()
        }
        if (current.snapshot.type != OperationType.REINSTALL) {
            return ExistingInstallationReinstallPreparationResult.NotReinstallOperation
        }
        current.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationReinstallPreparationResult.ContractViolation(
                "REINSTALL runtime requires exact InstallationTarget",
            )

        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            entryRegistry.discard(current.snapshot.operationId)
        }

        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> when (val entry = entryRegistry.inspect(current, now())) {
                ExistingInstallationReinstallEntryInspection.Available ->
                    ExistingInstallationReinstallPreparationResult.TransportRequired

                ExistingInstallationReinstallEntryInspection.Missing ->
                    ExistingInstallationReinstallPreparationResult.FreshPreflightRequired

                ExistingInstallationReinstallEntryInspection.Expired -> {
                    entryRegistry.discard(current.snapshot.operationId)
                    ExistingInstallationReinstallPreparationResult.FreshPreflightExpired
                }

                is ExistingInstallationReinstallEntryInspection.ContractViolation ->
                    ExistingInstallationReinstallPreparationResult.ContractViolation(entry.reason)
            }

            CheckpointSemantics.MUTATION_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
            -> ExistingInstallationReinstallPreparationResult.TransportRequired

            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationReinstallPreparationResult.Completed(
                finishCommitted(current),
            )

            CheckpointSemantics.TERMINAL -> ExistingInstallationReinstallPreparationResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL reinstall checkpoint",
            )

            else -> ExistingInstallationReinstallPreparationResult.ContractViolation(
                "Reinstall durable checkpoint ${current.snapshot.checkpoint.semantics} is outside Phase 9.7 runtime contract",
            )
        }
    }

    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): ExistingInstallationReinstallRuntimeResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExistingInstallationReinstallRuntimeResult.AdmissionLost
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
        if (before.snapshot.type != OperationType.REINSTALL) {
            return ExistingInstallationReinstallRuntimeResult.NotReinstallOperation
        }
        val target = before.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "REINSTALL runtime requires exact InstallationTarget",
            )

        return when (before.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> executeFreshReinstall(
                admission = admission,
                current = before,
                target = target,
                session = session,
            )

            CheckpointSemantics.MUTATION_IN_FLIGHT -> {
                val postVerify = when (val promoted = promoteReinstallToPostVerify(before)) {
                    is PromoteResult.Promoted -> promoted.current
                    is PromoteResult.Result -> return promoted.result
                }
                verifyAndCommit(postVerify, target, session)
            }

            CheckpointSemantics.POST_VERIFY_REQUIRED -> verifyAndCommit(before, target, session)

            CheckpointSemantics.COMMIT_VERIFIED -> ExistingInstallationReinstallRuntimeResult.Completed(
                finishCommitted(before),
            )

            CheckpointSemantics.TERMINAL -> ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL reinstall checkpoint",
            )

            else -> ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "Reinstall durable checkpoint ${before.snapshot.checkpoint.semantics} is outside Phase 9.7 runtime contract",
            )
        }
    }

    private suspend fun executeFreshReinstall(
        admission: RecoveryRuntimeAdmission,
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallRuntimeResult {
        val lease = when (val acquired = serverMutationRegistry.tryAcquire(target.serverId, current.snapshot.operationId)) {
            is ServerMutationAcquireResult.Acquired -> acquired.lease
            ServerMutationAcquireResult.AlreadyOwned -> {
                return ExistingInstallationReinstallRuntimeResult.ServerMutationAlreadyOwned
            }
        }

        try {
            val durable = when (val list = journal.listNonTerminal()) {
                is OperationJournalResult.Success -> list.value
                is OperationJournalResult.Corruption -> {
                    return ExistingInstallationReinstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            list.reason,
                        ),
                    )
                }
                is OperationJournalResult.StorageFailure -> {
                    return ExistingInstallationReinstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            list.reason,
                        ),
                    )
                }
                else -> {
                    return ExistingInstallationReinstallRuntimeResult.Failed(
                        contractFailure("Reinstall listNonTerminal returned ${list::class.simpleName}"),
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
                    return ExistingInstallationReinstallRuntimeResult.BlockedByDurableMutation(barrier.blockers)
                }
            }

            val latest = when (val read = readCurrent(admission)) {
                is CurrentRead.Current -> read.value
                is CurrentRead.Result -> return read.result
            }
            if (latest.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
                return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Fresh reinstall lost MUTATION_NOT_STARTED before dispatch",
                )
            }

            val preflight = when (val entry = entryRegistry.consume(latest, now())) {
                is ExistingInstallationReinstallEntryConsumeResult.Consumed -> entry.preflight
                ExistingInstallationReinstallEntryConsumeResult.Missing -> {
                    return ExistingInstallationReinstallRuntimeResult.FreshPreflightRequired
                }
                ExistingInstallationReinstallEntryConsumeResult.Expired -> {
                    return ExistingInstallationReinstallRuntimeResult.FreshPreflightExpired
                }
                is ExistingInstallationReinstallEntryConsumeResult.ContractViolation -> {
                    return ExistingInstallationReinstallRuntimeResult.ContractViolation(entry.reason)
                }
            }
            val plan = runCatching { ReviewedExistingInstallationActionPlanPolicy.build(preflight) }
                .getOrElse {
                    return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                        "Verified reinstall preflight could not build the canonical reviewed plan",
                    )
                }

            return ExistingInstallationReinstallRuntimeResult.Dispatch(
                dispatchPort.dispatch(preflight, plan, latest, session),
            )
        } finally {
            serverMutationRegistry.release(lease)
        }
    }

    /** MUTATION_IN_FLIGHT may only move forward into read-only post-verification. */
    private suspend fun promoteReinstallToPostVerify(
        current: VersionedOperationSnapshot,
    ): PromoteResult {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return PromoteResult.Result(
                ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Reinstall runtime clock moved before durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "REINSTALL_POST_VERIFY_REQUIRED",
                semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> PromoteResult.Promoted(advanced.value)
            is OperationJournalResult.StaleRevision -> PromoteResult.Result(
                ExistingInstallationReinstallRuntimeResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> PromoteResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
                ),
            )
            is OperationJournalResult.StorageFailure -> PromoteResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
                ),
            )
            is OperationJournalResult.InvalidTransition -> PromoteResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    contractFailure("Reinstall post-verify advance rejected: ${advanced.reason}"),
                ),
            )
            else -> PromoteResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    contractFailure("Reinstall post-verify advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private suspend fun verifyAndCommit(
        current: VersionedOperationSnapshot,
        target: OperationTarget.InstallationTarget,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallRuntimeResult {
        val installation = when (val read = installationRepository.get(target.installationId)) {
            is RepositoryResult.Success -> read.value
            RepositoryResult.NotFound -> {
                return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Reinstall target installation no longer exists locally",
                )
            }
            is RepositoryResult.Corruption -> {
                return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Reinstall target installation storage is corrupt: ${read.reason}",
                )
            }
            is RepositoryResult.StorageFailure -> {
                return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Reinstall target installation storage failed: ${read.reason}",
                )
            }
            else -> {
                return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Reinstall target installation lookup returned ${read::class.simpleName}",
                )
            }
        }
        val existing = installation.value
        if (existing.id != target.installationId || existing.serverId != target.serverId) {
            return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "Reinstall target installation no longer matches durable target",
            )
        }
        val managedInstallId = existing.identity.managedInstallId
        if (existing.ownership != InstallationOwnership.MANAGED || managedInstallId == null) {
            return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "Reinstall target must remain the exact MANAGED installation",
            )
        }

        return when (val verified = postVerifyPort.verify(current, managedInstallId, session)) {
            is ExistingInstallationReinstallPostVerifyResult.Verified -> {
                val publication = publisher.republishReinstall(
                    ExistingInstallationReinstallPublicationRequest(
                        operationId = current.snapshot.operationId,
                        serverId = target.serverId,
                        serverAccessId = target.serverAccessId,
                        installationId = target.installationId,
                        expectedRevision = installation.revision,
                        expectedIdentity = existing.identity,
                        verifiedBaseline = verified.verifiedBaseline,
                    ),
                )
                when (publication) {
                    is ExistingInstallationReinstallPublicationResult.Published -> {
                        if (publication.installation.value.id != target.installationId ||
                            publication.installation.value.serverId != target.serverId ||
                            publication.installation.value.identity != existing.identity ||
                            publication.managementAccess.installationId != target.installationId ||
                            publication.managementAccess.serverAccessId != target.serverAccessId
                        ) {
                            return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                                "Reinstall publisher changed exact installation/access ownership",
                            )
                        }
                        val committed = when (val commit = advanceCommitVerified(current, verified.facts.observedAt)) {
                            is CommitResult.Committed -> commit.current
                            is CommitResult.Result -> return commit.result
                        }
                        ExistingInstallationReinstallRuntimeResult.Completed(
                            finishCommitted(committed, publication),
                        )
                    }

                    else -> ExistingInstallationReinstallRuntimeResult.Reconciliation(
                        remote = verified,
                        publication = publication,
                    )
                }
            }

            else -> ExistingInstallationReinstallRuntimeResult.Reconciliation(
                remote = verified,
                publication = null,
            )
        }
    }

    private suspend fun advanceCommitVerified(
        current: VersionedOperationSnapshot,
        observedAt: Instant,
    ): CommitResult {
        val at = maxOf(now(), observedAt)
        if (at.isBefore(current.snapshot.updatedAt)) {
            return CommitResult.Result(
                ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Reinstall verified observation predates durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "REINSTALL_VERIFIED_REPUBLISHED_COMMIT",
                semantics = CheckpointSemantics.COMMIT_VERIFIED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> CommitResult.Committed(advanced.value)
            is OperationJournalResult.StaleRevision -> CommitResult.Result(
                ExistingInstallationReinstallRuntimeResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> CommitResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
                ),
            )
            is OperationJournalResult.StorageFailure -> CommitResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
                ),
            )
            is OperationJournalResult.InvalidTransition -> CommitResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    contractFailure("Reinstall COMMIT_VERIFIED advance rejected: ${advanced.reason}"),
                ),
            )
            else -> CommitResult.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    contractFailure("Reinstall COMMIT_VERIFIED advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private suspend fun finishCommitted(
        current: VersionedOperationSnapshot,
        publication: ExistingInstallationReinstallPublicationResult.Published? = null,
    ): ExistingInstallationReinstallCompletionResult {
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.COMMIT_VERIFIED) {
            return ExistingInstallationReinstallCompletionResult.ContractViolation(
                "Reinstall local completion requires COMMIT_VERIFIED",
            )
        }
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return ExistingInstallationReinstallCompletionResult.ContractViolation(
                "Reinstall local completion clock moved backward",
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.SUCCEEDED,
            checkpoint = OperationCheckpoint(
                phaseName = "REINSTALL_SUCCEEDED_VERIFIED_REPUBLISHED",
                semantics = CheckpointSemantics.TERMINAL,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> ExistingInstallationReinstallCompletionResult.Committed(
                durable = advanced.value,
                publication = publication,
            )
            is OperationJournalResult.StaleRevision -> ExistingInstallationReinstallCompletionResult.StalePlan(
                current.snapshot.operationId,
                advanced.expected,
                advanced.actual,
            )
            is OperationJournalResult.Corruption -> ExistingInstallationReinstallCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, advanced.reason),
            )
            is OperationJournalResult.StorageFailure -> ExistingInstallationReinstallCompletionResult.Failed(
                RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, advanced.reason),
            )
            is OperationJournalResult.InvalidTransition -> ExistingInstallationReinstallCompletionResult.Failed(
                contractFailure("Reinstall terminal advance rejected: ${advanced.reason}"),
            )
            else -> ExistingInstallationReinstallCompletionResult.Failed(
                contractFailure("Reinstall terminal advance returned ${advanced::class.simpleName}"),
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): ExistingInstallationReinstallRuntimeResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "Reinstall session belongs to a different OperationId",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return ExistingInstallationReinstallRuntimeResult.ContractViolation(
                "Reinstall session uses a different ServerAccessId than durable target",
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
            ?: return CurrentSession.Result(ExistingInstallationReinstallRuntimeResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                ExistingInstallationReinstallRuntimeResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                ExistingInstallationReinstallRuntimeResult.ContractViolation(
                    "Live reinstall session binding changed exact owner/access identity",
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
                    ExistingInstallationReinstallRuntimeResult.Failed(
                        contractFailure("Reinstall operation no longer exists"),
                    ),
                )
            }
            is OperationJournalResult.Corruption -> {
                return CurrentRead.Result(
                    ExistingInstallationReinstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION, result.reason),
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return CurrentRead.Result(
                    ExistingInstallationReinstallRuntimeResult.Failed(
                        RecoveryBootstrapFailure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE, result.reason),
                    ),
                )
            }
            else -> {
                return CurrentRead.Result(
                    ExistingInstallationReinstallRuntimeResult.Failed(
                        contractFailure("Reinstall exact journal read returned ${result::class.simpleName}"),
                    ),
                )
            }
        }
        if (current.snapshot.operationId != admission.plan.operationId ||
            current.snapshot.target != admission.plan.target
        ) {
            return CurrentRead.Result(
                ExistingInstallationReinstallRuntimeResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Reinstall operation identity/target changed after runtime admission",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                ExistingInstallationReinstallRuntimeResult.StalePlan(
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
                ExistingInstallationReinstallRuntimeResult.Failed(
                    contractFailure("Reinstall admission points at terminal durable state"),
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
        data class Result(val result: ExistingInstallationReinstallRuntimeResult) : PromoteResult
    }

    private sealed interface CommitResult {
        data class Committed(val current: VersionedOperationSnapshot) : CommitResult
        data class Result(val result: ExistingInstallationReinstallRuntimeResult) : CommitResult
    }

    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: ExistingInstallationReinstallRuntimeResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: ExistingInstallationReinstallRuntimeResult) : CurrentSession
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

sealed interface ExistingInstallationReinstallPreparationResult {
    data object NotReinstallOperation : ExistingInstallationReinstallPreparationResult
    data object TransportRequired : ExistingInstallationReinstallPreparationResult
    data object FreshPreflightRequired : ExistingInstallationReinstallPreparationResult
    data object FreshPreflightExpired : ExistingInstallationReinstallPreparationResult
    data class Completed(
        val result: ExistingInstallationReinstallCompletionResult,
    ) : ExistingInstallationReinstallPreparationResult
    data object AdmissionLost : ExistingInstallationReinstallPreparationResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationReinstallPreparationResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationReinstallPreparationResult
    data class ContractViolation(val reason: String) : ExistingInstallationReinstallPreparationResult
}

sealed interface ExistingInstallationReinstallRuntimeResult {
    data object NotReinstallOperation : ExistingInstallationReinstallRuntimeResult
    data object AdmissionLost : ExistingInstallationReinstallRuntimeResult
    data object SessionUnavailable : ExistingInstallationReinstallRuntimeResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : ExistingInstallationReinstallRuntimeResult
    data object FreshPreflightRequired : ExistingInstallationReinstallRuntimeResult
    data object FreshPreflightExpired : ExistingInstallationReinstallRuntimeResult
    data object ServerMutationAlreadyOwned : ExistingInstallationReinstallRuntimeResult
    data class BlockedByDurableMutation(
        val blockers: List<UncertainMutationBlocker>,
    ) : ExistingInstallationReinstallRuntimeResult
    data class Dispatch(
        val result: ExistingInstallationReinstallDispatchResult,
    ) : ExistingInstallationReinstallRuntimeResult
    data class Reconciliation(
        val remote: ExistingInstallationReinstallPostVerifyResult,
        val publication: ExistingInstallationReinstallPublicationResult?,
    ) : ExistingInstallationReinstallRuntimeResult
    data class Completed(
        val result: ExistingInstallationReinstallCompletionResult,
    ) : ExistingInstallationReinstallRuntimeResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationReinstallRuntimeResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationReinstallRuntimeResult
    data class ContractViolation(val reason: String) : ExistingInstallationReinstallRuntimeResult
}

sealed interface ExistingInstallationReinstallCompletionResult {
    data class Committed(
        val durable: VersionedOperationSnapshot,
        val publication: ExistingInstallationReinstallPublicationResult.Published?,
    ) : ExistingInstallationReinstallCompletionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExistingInstallationReinstallCompletionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExistingInstallationReinstallCompletionResult
    data class ContractViolation(val reason: String) : ExistingInstallationReinstallCompletionResult
}

private fun ExistingInstallationReinstallRuntimeResult.toPreparationResult(): ExistingInstallationReinstallPreparationResult =
    when (this) {
        ExistingInstallationReinstallRuntimeResult.NotReinstallOperation ->
            ExistingInstallationReinstallPreparationResult.NotReinstallOperation
        ExistingInstallationReinstallRuntimeResult.AdmissionLost ->
            ExistingInstallationReinstallPreparationResult.AdmissionLost
        is ExistingInstallationReinstallRuntimeResult.StalePlan -> ExistingInstallationReinstallPreparationResult.StalePlan(
            operationId,
            expectedRevision,
            actualRevision,
        )
        is ExistingInstallationReinstallRuntimeResult.Failed ->
            ExistingInstallationReinstallPreparationResult.Failed(failure)
        is ExistingInstallationReinstallRuntimeResult.ContractViolation ->
            ExistingInstallationReinstallPreparationResult.ContractViolation(reason)
        else -> ExistingInstallationReinstallPreparationResult.ContractViolation(
            "Unexpected session-dependent reinstall result during local preparation: ${this::class.simpleName}",
        )
    }
