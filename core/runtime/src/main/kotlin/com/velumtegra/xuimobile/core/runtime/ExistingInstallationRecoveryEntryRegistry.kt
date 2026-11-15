package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-local one-shot Phase 9 RECOVERY authority.
 *
 * A verified preflight is short-lived permission to cross the recovery dispatch boundary, not
 * durable truth. Process death drops it. Durable MUTATION_IN_FLIGHT/POST_VERIFY_REQUIRED recovery
 * never rebuilds this authority and therefore cannot replay the recovery command.
 */
class ExistingInstallationRecoveryEntryRegistry {
    private val entries = ConcurrentHashMap<OperationId, VerifiedExistingInstallationActionPreflight>()

    fun register(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationRecoveryEntryRegistrationResult {
        if (preflight.authorization.action != OperationType.RECOVERY ||
            preflight.evidence.scope.action != OperationType.RECOVERY
        ) {
            return ExistingInstallationRecoveryEntryRegistrationResult.Rejected(
                "Recovery runtime entry accepts only exact RECOVERY preflight authority",
            )
        }
        val operationId = preflight.authorization.operationId
        val existing = entries.putIfAbsent(operationId, preflight)
        return when {
            existing == null -> ExistingInstallationRecoveryEntryRegistrationResult.Registered
            sameAuthority(existing, preflight) -> ExistingInstallationRecoveryEntryRegistrationResult.AlreadyRegistered
            else -> ExistingInstallationRecoveryEntryRegistrationResult.Conflict
        }
    }

    fun inspect(
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationRecoveryEntryInspection {
        val entry = entries[current.snapshot.operationId]
            ?: return ExistingInstallationRecoveryEntryInspection.Missing
        return validate(entry, current, now)
    }

    /** One-shot consume immediately before the recovery executor boundary. */
    fun consume(
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationRecoveryEntryConsumeResult {
        val operationId = current.snapshot.operationId
        val entry = entries.remove(operationId)
            ?: return ExistingInstallationRecoveryEntryConsumeResult.Missing
        return when (val validation = validate(entry, current, now)) {
            ExistingInstallationRecoveryEntryInspection.Available ->
                ExistingInstallationRecoveryEntryConsumeResult.Consumed(entry)

            ExistingInstallationRecoveryEntryInspection.Expired ->
                ExistingInstallationRecoveryEntryConsumeResult.Expired

            is ExistingInstallationRecoveryEntryInspection.ContractViolation ->
                ExistingInstallationRecoveryEntryConsumeResult.ContractViolation(validation.reason)

            ExistingInstallationRecoveryEntryInspection.Missing ->
                error("Removed recovery authority cannot become missing")
        }
    }

    fun discard(operationId: OperationId): Boolean = entries.remove(operationId) != null

    private fun validate(
        entry: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationRecoveryEntryInspection {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRecoveryEntryInspection.ContractViolation(
                "Recovery runtime entry requires exact InstallationTarget",
            )
        if (snapshot.type != OperationType.RECOVERY || snapshot.status != OperationStatus.RUNNING) {
            return ExistingInstallationRecoveryEntryInspection.ContractViolation(
                "Recovery authority requires RUNNING RECOVERY durable operation",
            )
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationRecoveryEntryInspection.ContractViolation(
                "Recovery authority may be consumed only at MUTATION_NOT_STARTED",
            )
        }
        val authorization = entry.authorization
        val scope = entry.evidence.scope
        if (authorization.operationId != snapshot.operationId ||
            authorization.operationRevision != current.revision ||
            authorization.operationTarget != target ||
            authorization.action != OperationType.RECOVERY ||
            scope.operationId != snapshot.operationId ||
            scope.operationRevision != current.revision.value ||
            scope.serverId != target.serverId ||
            scope.serverAccessId != target.serverAccessId ||
            scope.installationId != target.installationId ||
            scope.action != OperationType.RECOVERY
        ) {
            return ExistingInstallationRecoveryEntryInspection.ContractViolation(
                "Recovery preflight authority no longer matches exact durable revision/target/action",
            )
        }
        if (now.isBefore(entry.evidence.observedAt) || now.isAfter(entry.evidence.validUntil) ||
            now.isBefore(entry.evidence.installationProof.observedAt) ||
            now.isAfter(entry.evidence.installationProof.validUntil)
        ) {
            return ExistingInstallationRecoveryEntryInspection.Expired
        }
        return ExistingInstallationRecoveryEntryInspection.Available
    }

    private fun sameAuthority(
        first: VerifiedExistingInstallationActionPreflight,
        second: VerifiedExistingInstallationActionPreflight,
    ): Boolean = first.authorization.operationId == second.authorization.operationId &&
        first.authorization.operationRevision == second.authorization.operationRevision &&
        first.authorization.operationTarget == second.authorization.operationTarget &&
        first.authorization.action == second.authorization.action &&
        first.authorization.ownership == second.authorization.ownership &&
        first.evidence == second.evidence
}

sealed interface ExistingInstallationRecoveryEntryRegistrationResult {
    data object Registered : ExistingInstallationRecoveryEntryRegistrationResult
    data object AlreadyRegistered : ExistingInstallationRecoveryEntryRegistrationResult
    data object Conflict : ExistingInstallationRecoveryEntryRegistrationResult
    data class Rejected(val reason: String) : ExistingInstallationRecoveryEntryRegistrationResult
}

sealed interface ExistingInstallationRecoveryEntryInspection {
    data object Available : ExistingInstallationRecoveryEntryInspection
    data object Missing : ExistingInstallationRecoveryEntryInspection
    data object Expired : ExistingInstallationRecoveryEntryInspection
    data class ContractViolation(val reason: String) : ExistingInstallationRecoveryEntryInspection
}

sealed interface ExistingInstallationRecoveryEntryConsumeResult {
    data class Consumed(
        val preflight: VerifiedExistingInstallationActionPreflight,
    ) : ExistingInstallationRecoveryEntryConsumeResult

    data object Missing : ExistingInstallationRecoveryEntryConsumeResult
    data object Expired : ExistingInstallationRecoveryEntryConsumeResult
    data class ContractViolation(val reason: String) : ExistingInstallationRecoveryEntryConsumeResult
}
