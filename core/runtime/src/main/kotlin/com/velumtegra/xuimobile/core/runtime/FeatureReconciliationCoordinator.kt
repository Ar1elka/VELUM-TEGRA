package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry

/** Normalized feature-owned conclusion from read-only remote reconciliation. */
enum class FeatureReconciliationVerdict {
    VERIFIED,
    UNVERIFIED,
    CONTRADICTED,
}

/** Whether the feature observed all evidence required by its own proof algorithm. */
enum class FeatureReconciliationCompleteness {
    COMPLETE,
    TRUNCATED,
    AMBIGUOUS,
}

/**
 * Exact evidence envelope returned by a feature-specific reconciliation implementation.
 *
 * Strong conclusions require complete evidence. Truncated/ambiguous observations can only be
 * surfaced as UNVERIFIED and can never clear an uncertain-mutation barrier by themselves.
 */
data class FeatureReconciliationEvidence(
    val operationId: OperationId,
    val target: OperationTarget,
    val observedRevision: OperationRevision,
    val sessionBinding: SessionBinding,
    val verdict: FeatureReconciliationVerdict,
    val completeness: FeatureReconciliationCompleteness,
) {
    init {
        if (verdict != FeatureReconciliationVerdict.UNVERIFIED) {
            require(completeness == FeatureReconciliationCompleteness.COMPLETE) {
                "$verdict reconciliation evidence must be complete"
            }
        }
    }
}

/**
 * Exact read-only reconciliation input.
 *
 * The port must use the same exact SessionId/access identity represented by [sessionBinding]. It
 * must perform only read-only probes until remote truth is established. Phase 4.4 deliberately
 * provides no mutation-command surface through this contract.
 */
data class FeatureReconciliationRequest(
    val current: VersionedOperationSnapshot,
    val sessionBinding: SessionBinding,
) {
    init {
        val snapshot = current.snapshot
        require(sessionBinding.owner == SessionOwner.Operation(snapshot.operationId)) {
            "Reconciliation session must belong to the exact OperationId"
        }
        require(sessionBinding.serverAccessId == snapshot.target.serverAccessId) {
            "Reconciliation session must use the exact persisted ServerAccessId"
        }
    }
}

sealed interface FeatureReconciliationPortResult {
    data class Evidence(val evidence: FeatureReconciliationEvidence) : FeatureReconciliationPortResult
    data object Unsupported : FeatureReconciliationPortResult
    data class Failed(val reason: String) : FeatureReconciliationPortResult {
        init {
            require(reason.isNotBlank())
        }
    }
}

/**
 * Feature-owned read-only reconciliation algorithm.
 *
 * Generic runtime decides that reconciliation is required and guards exact identity/revision. The
 * feature owns how to prove remote truth. Implementations must not mutate remote state here and must
 * not advance OperationJournal state themselves.
 */
fun interface FeatureReconciliationPort {
    suspend fun reconcile(request: FeatureReconciliationRequest): FeatureReconciliationPortResult
}

sealed interface FeatureReconciliationResult {
    data class EvidenceAccepted(val evidence: FeatureReconciliationEvidence) : FeatureReconciliationResult
    data class NotReconciliationPlan(val action: RecoveryAction) : FeatureReconciliationResult
    data object AdmissionLost : FeatureReconciliationResult
    data object SessionUnavailable : FeatureReconciliationResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : FeatureReconciliationResult

    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : FeatureReconciliationResult

    data class Failed(val failure: RecoveryBootstrapFailure) : FeatureReconciliationResult
    data class Unsupported(val operationType: OperationType) : FeatureReconciliationResult
    data class PortFailed(val reason: String) : FeatureReconciliationResult
    data class ContractViolation(val reason: String) : FeatureReconciliationResult
}

/**
 * Phase 4.4 guarded boundary between generic runtime and feature-owned read-only reconciliation.
 *
 * It never executes a remote command and never advances OperationJournal. Before and after the
 * feature call it proves that the exact runtime admission, exact live SessionId/access and durable
 * operation revision still match the recovery plan. Evidence from a stale callback is discarded.
 */
class FeatureReconciliationCoordinator(
    private val journal: OperationJournal,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val port: FeatureReconciliationPort,
) {
    suspend fun reconcile(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): FeatureReconciliationResult {
        if (admission.plan.action != RecoveryAction.RECONCILE_READ_ONLY) {
            return FeatureReconciliationResult.NotReconciliationPlan(admission.plan.action)
        }
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return FeatureReconciliationResult.AdmissionLost
        }

        validateCallerBinding(admission, sessionBinding)?.let { return it }
        currentSessionResult(admission, sessionBinding)?.let { return it }

        val before = when (val read = readCurrent(admission)) {
            is CurrentReadResult.Current -> read.value
            is CurrentReadResult.Result -> return read.result
        }

        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return FeatureReconciliationResult.AdmissionLost
        }
        currentSessionResult(admission, sessionBinding)?.let { return it }

        val request = FeatureReconciliationRequest(
            current = before,
            sessionBinding = sessionBinding,
        )
        val portResult = port.reconcile(request)

        // Reconciliation may suspend for remote probes. Discard its evidence if local ownership or
        // exact session identity changed while it was running.
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return FeatureReconciliationResult.AdmissionLost
        }
        currentSessionResult(admission, sessionBinding)?.let { return it }

        val after = when (val read = readCurrent(admission)) {
            is CurrentReadResult.Current -> read.value
            is CurrentReadResult.Result -> return read.result
        }
        if (after.revision != before.revision) {
            return FeatureReconciliationResult.StalePlan(
                operationId = admission.plan.operationId,
                expectedRevision = before.revision,
                actualRevision = after.revision,
            )
        }

        return when (portResult) {
            FeatureReconciliationPortResult.Unsupported -> FeatureReconciliationResult.Unsupported(
                before.snapshot.type,
            )

            is FeatureReconciliationPortResult.Failed -> FeatureReconciliationResult.PortFailed(
                portResult.reason,
            )

            is FeatureReconciliationPortResult.Evidence -> validateEvidence(
                request = request,
                evidence = portResult.evidence,
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): FeatureReconciliationResult.ContractViolation? {
        val expectedOwner = SessionOwner.Operation(admission.plan.operationId)
        if (binding.owner != expectedOwner) {
            return FeatureReconciliationResult.ContractViolation(
                "Reconciliation binding belongs to a different session owner",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return FeatureReconciliationResult.ContractViolation(
                "Reconciliation binding uses a different ServerAccessId than the durable target",
            )
        }
        return null
    }

    /** Returns null only when the caller's exact SessionId is still the live exact session. */
    private fun currentSessionResult(
        admission: RecoveryRuntimeAdmission,
        expected: SessionBinding,
    ): FeatureReconciliationResult? {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return FeatureReconciliationResult.SessionUnavailable
        if (current.binding.sessionId != expected.sessionId) {
            return FeatureReconciliationResult.StaleSession(
                expectedSessionId = expected.sessionId,
                actualSessionId = current.binding.sessionId,
            )
        }
        if (current.binding != expected) {
            return FeatureReconciliationResult.ContractViolation(
                "Live reconciliation session binding changed exact owner/access identity",
            )
        }
        return null
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentReadResult {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> {
                return CurrentReadResult.Result(
                    FeatureReconciliationResult.Failed(
                        contractFailure("Reconciliation operation no longer exists in OperationJournal"),
                    ),
                )
            }
            is OperationJournalResult.Corruption -> {
                return CurrentReadResult.Result(
                    FeatureReconciliationResult.Failed(
                        RecoveryBootstrapFailure(
                            kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            reason = result.reason,
                        ),
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return CurrentReadResult.Result(
                    FeatureReconciliationResult.Failed(
                        RecoveryBootstrapFailure(
                            kind = RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            reason = result.reason,
                        ),
                    ),
                )
            }
            else -> {
                return CurrentReadResult.Result(
                    FeatureReconciliationResult.Failed(
                        contractFailure(
                            "get(${admission.plan.operationId.value}) returned ${result::class.simpleName}",
                        ),
                    ),
                )
            }
        }

        if (current.snapshot.operationId != admission.plan.operationId) {
            return CurrentReadResult.Result(
                FeatureReconciliationResult.Failed(
                    corruptionFailure("OperationJournal returned a different OperationId for reconciliation"),
                ),
            )
        }
        if (current.snapshot.target != admission.plan.target) {
            return CurrentReadResult.Result(
                FeatureReconciliationResult.Failed(
                    corruptionFailure("Operation target changed during reconciliation"),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentReadResult.Result(
                FeatureReconciliationResult.StalePlan(
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
            return CurrentReadResult.Result(
                FeatureReconciliationResult.Failed(
                    contractFailure("Read-only reconciliation plan points at terminal durable state"),
                ),
            )
        }

        return CurrentReadResult.Current(current)
    }

    private fun validateEvidence(
        request: FeatureReconciliationRequest,
        evidence: FeatureReconciliationEvidence,
    ): FeatureReconciliationResult {
        if (evidence.operationId != request.current.snapshot.operationId) {
            return FeatureReconciliationResult.ContractViolation(
                "Feature reconciliation evidence belongs to a different OperationId",
            )
        }
        if (evidence.target != request.current.snapshot.target) {
            return FeatureReconciliationResult.ContractViolation(
                "Feature reconciliation evidence belongs to a different operation target",
            )
        }
        if (evidence.observedRevision != request.current.revision) {
            return FeatureReconciliationResult.ContractViolation(
                "Feature reconciliation evidence was produced for a different durable revision",
            )
        }
        if (evidence.sessionBinding != request.sessionBinding) {
            return FeatureReconciliationResult.ContractViolation(
                "Feature reconciliation evidence was produced through a different exact session",
            )
        }
        return FeatureReconciliationResult.EvidenceAccepted(evidence)
    }

    private fun contractFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        kind = RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason = reason,
    )

    private fun corruptionFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        kind = RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
        reason = reason,
    )

    private sealed interface CurrentReadResult {
        data class Current(val value: VersionedOperationSnapshot) : CurrentReadResult
        data class Result(val result: FeatureReconciliationResult) : CurrentReadResult
    }

    private companion object {
        val terminalStatuses = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}
