package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.domain.DiscoveryProofAttempt
import com.velumtegra.xuimobile.core.domain.DiscoveryProver
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryFailureKind
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryResult
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.terminalKind
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeExecutionFailure
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import java.time.Instant
import java.util.UUID

sealed interface DiscoveryRuntimeExecutionResult {
    data class Completed(
        val result: DiscoveryResult,
        val committedRevision: OperationRevision,
    ) : DiscoveryRuntimeExecutionResult

    data class NotDiscoveryOperation(val operationType: OperationType) : DiscoveryRuntimeExecutionResult
    data object AdmissionLost : DiscoveryRuntimeExecutionResult
    data object SessionUnavailable : DiscoveryRuntimeExecutionResult

    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : DiscoveryRuntimeExecutionResult

    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : DiscoveryRuntimeExecutionResult

    data class Failed(val failure: RecoveryBootstrapFailure) : DiscoveryRuntimeExecutionResult
    data class ContractViolation(val reason: String) : DiscoveryRuntimeExecutionResult
}

/**
 * Exact Phase 5 Discovery consumer for the already-established Phase 4 operation-owned SSH session.
 *
 * This component creates no connection/retry/session lifecycle of its own. It verifies the same
 * process runtime lease, exact durable revision/target and exact live SessionId before and after the
 * read-only probe executor. Only after those checks still agree does it CAS one terminal generic
 * Operation checkpoint. Raw probe output is never persisted; the typed [DiscoveryResult] is returned
 * to the caller and a later reviewed Phase 5 slice may add normalized result persistence if needed.
 */
class DiscoveryRuntimeCoordinator(
    private val journal: OperationJournal,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val executor: DiscoverySshProbeExecutor = DiscoverySshProbeExecutor(),
    private val now: () -> Instant = Instant::now,
    private val proofIdFactory: () -> DiscoveryProofId = {
        DiscoveryProofId(UUID.randomUUID().toString())
    },
) {
    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): DiscoveryRuntimeExecutionResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return DiscoveryRuntimeExecutionResult.AdmissionLost
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
        if (before.snapshot.type != OperationType.DISCOVERY) {
            return DiscoveryRuntimeExecutionResult.NotDiscoveryOperation(before.snapshot.type)
        }
        if (before.snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return DiscoveryRuntimeExecutionResult.ContractViolation(
                "Discovery durable checkpoint must remain READ_ONLY until terminal RESULT",
            )
        }
        val serverTarget = before.snapshot.target as? OperationTarget.ServerTarget
            ?: return DiscoveryRuntimeExecutionResult.ContractViolation(
                "Discovery operation must target one exact ServerTarget",
            )
        val scope = DiscoveryScope(
            operationId = before.snapshot.operationId,
            serverId = serverTarget.serverId,
            serverAccessId = serverTarget.serverAccessId,
        )

        val probeRun = executor.executeInitialPlan(scope, session)

        // The feature call suspended for remote reads. Discard any result produced after ownership,
        // exact session identity or durable revision changed underneath it.
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return DiscoveryRuntimeExecutionResult.AdmissionLost
        }
        when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> Unit
            is CurrentSession.Result -> return current.result
        }
        val after = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (after.revision != before.revision) {
            return DiscoveryRuntimeExecutionResult.StalePlan(
                operationId = admission.plan.operationId,
                expectedRevision = before.revision,
                actualRevision = after.revision,
            )
        }

        val completedAt = now()
        val result = mapProbeRun(scope, probeRun, completedAt)
        val terminal = terminalSnapshot(before.snapshot, result, completedAt)
        return when (val advance = journal.advance(before.snapshot.operationId, before.revision, terminal)) {
            is OperationJournalResult.Success -> DiscoveryRuntimeExecutionResult.Completed(
                result = result,
                committedRevision = advance.value.revision,
            )

            is OperationJournalResult.StaleRevision -> DiscoveryRuntimeExecutionResult.StalePlan(
                operationId = before.snapshot.operationId,
                expectedRevision = advance.expected,
                actualRevision = advance.actual,
            )

            is OperationJournalResult.Corruption -> DiscoveryRuntimeExecutionResult.Failed(
                RecoveryBootstrapFailure(
                    kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                    reason = advance.reason,
                ),
            )

            is OperationJournalResult.StorageFailure -> DiscoveryRuntimeExecutionResult.Failed(
                RecoveryBootstrapFailure(
                    kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                    reason = advance.reason,
                ),
            )

            is OperationJournalResult.InvalidTransition -> DiscoveryRuntimeExecutionResult.Failed(
                contractFailure("Discovery terminal advance rejected: ${advance.reason}"),
            )

            else -> DiscoveryRuntimeExecutionResult.Failed(
                contractFailure("Discovery terminal advance returned ${advance::class.simpleName}"),
            )
        }
    }

    private fun mapProbeRun(
        scope: DiscoveryScope,
        run: DiscoverySshProbeRunResult,
        completedAt: Instant,
    ): DiscoveryResult = when (run) {
        is DiscoverySshProbeRunResult.Completed -> {
            val classification = DiscoveryClassifier.classify(run.evidence)
            when (classification) {
                is DiscoveryClassification.SupportedCandidate -> when (
                    val proof = DiscoveryProver.prove(
                        evidence = run.evidence,
                        classification = classification,
                        proofId = proofIdFactory(),
                    )
                ) {
                    is DiscoveryProofAttempt.Proven -> DiscoveryResult.ProvenSupportedInstallation(
                        proof = proof.proof,
                        completedAt = completedAt,
                    )

                    is DiscoveryProofAttempt.InsufficientEvidence -> DiscoveryResult.InsufficientEvidence(
                        scope = scope,
                        gaps = proof.gaps,
                        completedAt = completedAt,
                    )

                    is DiscoveryProofAttempt.NotApplicable -> classificationToResult(
                        scope = scope,
                        classification = proof.classification,
                        completedAt = completedAt,
                    )
                }

                else -> classificationToResult(scope, classification, completedAt)
            }
        }

        is DiscoverySshProbeRunResult.Failed -> DiscoveryResult.Failed(
            scope = scope,
            failure = mapProbeFailure(run.failure),
            completedAt = completedAt,
        )
    }

    private fun classificationToResult(
        scope: DiscoveryScope,
        classification: DiscoveryClassification,
        completedAt: Instant,
    ): DiscoveryResult = when (classification) {
        is DiscoveryClassification.SupportedCandidate -> DiscoveryResult.InsufficientEvidence(
            scope = scope,
            gaps = setOf(com.velumtegra.xuimobile.core.model.DiscoveryEvidenceGap.INSTALLATION_IDENTITY_INCOMPLETE),
            completedAt = completedAt,
        )
        DiscoveryClassification.NoSupportedInstallation -> DiscoveryResult.NoSupportedInstallation(scope, completedAt)
        is DiscoveryClassification.UnsupportedPlatform -> DiscoveryResult.UnsupportedPlatform(
            scope = scope,
            platform = classification.platform,
            completedAt = completedAt,
        )
        DiscoveryClassification.ForeignPanel -> DiscoveryResult.ForeignPanelDetected(scope, completedAt)
        is DiscoveryClassification.Ambiguous -> DiscoveryResult.AmbiguousEvidence(
            scope = scope,
            conflicts = classification.conflicts,
            completedAt = completedAt,
        )
        is DiscoveryClassification.InsufficientEvidence -> DiscoveryResult.InsufficientEvidence(
            scope = scope,
            gaps = classification.gaps,
            completedAt = completedAt,
        )
    }

    private fun mapProbeFailure(failure: DiscoverySshProbeExecutionFailure): DiscoveryFailureKind = when (failure) {
        DiscoverySshProbeExecutionFailure.ExactSessionBindingMismatch,
        DiscoverySshProbeExecutionFailure.SessionClosed,
        DiscoverySshProbeExecutionFailure.ProbeOutsideApprovedPolicy,
        -> DiscoveryFailureKind.INTERNAL_INVARIANT_FAILURE

        is DiscoverySshProbeExecutionFailure.CommandUncertain -> DiscoveryFailureKind.TRANSPORT_UNAVAILABLE
        is DiscoverySshProbeExecutionFailure.CommandFailed,
        DiscoverySshProbeExecutionFailure.OutputTruncated,
        DiscoverySshProbeExecutionFailure.MalformedProbeEvidence,
        -> DiscoveryFailureKind.MALFORMED_PROBE_EVIDENCE
    }

    private fun terminalSnapshot(
        previous: OperationSnapshot,
        result: DiscoveryResult,
        completedAt: Instant,
    ): OperationSnapshot {
        val status = when (result) {
            is DiscoveryResult.Failed -> OperationStatus.FAILED
            is DiscoveryResult.Cancelled -> OperationStatus.CANCELLED
            else -> OperationStatus.SUCCEEDED
        }
        return previous.copy(
            status = status,
            checkpoint = OperationCheckpoint(
                phaseName = result.terminalKind().phaseName,
                semantics = CheckpointSemantics.TERMINAL,
                recordedAt = completedAt,
            ),
            updatedAt = completedAt,
        )
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): DiscoveryRuntimeExecutionResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return DiscoveryRuntimeExecutionResult.ContractViolation(
                "Discovery binding belongs to a different operation owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return DiscoveryRuntimeExecutionResult.ContractViolation(
                "Discovery binding uses a different ServerAccessId than the durable target",
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
            ?: return CurrentSession.Result(DiscoveryRuntimeExecutionResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                DiscoveryRuntimeExecutionResult.StaleSession(
                    expectedSessionId = expected.sessionId,
                    actualSessionId = current.binding.sessionId,
                ),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                DiscoveryRuntimeExecutionResult.ContractViolation(
                    "Live Discovery session binding changed exact owner/access identity",
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
                    DiscoveryRuntimeExecutionResult.Failed(
                        contractFailure("Discovery operation no longer exists in OperationJournal"),
                    ),
                )
            }
            is OperationJournalResult.Corruption -> {
                return CurrentRead.Result(
                    DiscoveryRuntimeExecutionResult.Failed(
                        RecoveryBootstrapFailure(
                            kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            reason = result.reason,
                        ),
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return CurrentRead.Result(
                    DiscoveryRuntimeExecutionResult.Failed(
                        RecoveryBootstrapFailure(
                            kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            reason = result.reason,
                        ),
                    ),
                )
            }
            else -> {
                return CurrentRead.Result(
                    DiscoveryRuntimeExecutionResult.Failed(
                        contractFailure("Discovery exact journal read returned ${result::class.simpleName}"),
                    ),
                )
            }
        }

        if (current.snapshot.operationId != admission.plan.operationId) {
            return CurrentRead.Result(
                DiscoveryRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        reason = "OperationJournal returned a different OperationId for Discovery",
                    ),
                ),
            )
        }
        if (current.snapshot.target != admission.plan.target) {
            return CurrentRead.Result(
                DiscoveryRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        reason = "Operation target changed during Discovery",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                DiscoveryRuntimeExecutionResult.StalePlan(
                    operationId = admission.plan.operationId,
                    expectedRevision = admission.plan.expectedRevision,
                    actualRevision = current.revision,
                ),
            )
        }
        if (
            current.snapshot.status in terminalStatuses ||
            current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        ) {
            return CurrentRead.Result(
                DiscoveryRuntimeExecutionResult.Failed(
                    contractFailure("Discovery admission points at terminal durable state"),
                ),
            )
        }
        return CurrentRead.Current(current)
    }

    private fun contractFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        kind = RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason = reason,
    )

    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: DiscoveryRuntimeExecutionResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: com.velumtegra.xuimobile.core.ssh.SshSessionHandle) : CurrentSession
        data class Result(val result: DiscoveryRuntimeExecutionResult) : CurrentSession
    }

    private companion object {
        val terminalStatuses = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}
