package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.ExistingInstallationRestartConfirmation
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-local one-shot Phase 9 RESTART authority.
 *
 * A verified preflight is short-lived permission to cross the restart dispatch boundary, not
 * durable truth. Process death drops it. Durable RESTART_IN_FLIGHT/POST_VERIFY_REQUIRED recovery
 * never rebuilds this authority and therefore cannot replay the restart command.
 */
class ExistingInstallationRestartEntryRegistry {
    private val entries = ConcurrentHashMap<OperationId, VerifiedExistingInstallationActionPreflight>()
    private val confirmations = ConcurrentHashMap<OperationId, ExistingInstallationRestartConfirmation>()
    fun registerConfirmation(confirmation: ExistingInstallationRestartConfirmation): Boolean =
        !entries.containsKey(confirmation.operationId) && confirmations.putIfAbsent(confirmation.operationId, confirmation) == null
    fun hasConfirmation(current: VersionedOperationSnapshot, now: Instant): Boolean =
        confirmations[current.snapshot.operationId]?.let { matches(it, current, now) } == true
    fun consumeConfirmation(current: VersionedOperationSnapshot, now: Instant): ExistingInstallationRestartConfirmation? =
        confirmations.remove(current.snapshot.operationId)?.takeIf { matches(it, current, now) }
    private fun matches(c: ExistingInstallationRestartConfirmation, current: VersionedOperationSnapshot, now: Instant): Boolean =
        current.snapshot.operationId == c.operationId && current.revision == c.operationRevision &&
        current.snapshot.type == OperationType.RESTART && current.snapshot.status == OperationStatus.RUNNING &&
        current.snapshot.target == c.target && current.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED &&
        !now.isBefore(c.confirmedAt) && !now.isAfter(c.validUntil)

    fun register(
        preflight: VerifiedExistingInstallationActionPreflight,
    ): ExistingInstallationRestartEntryRegistrationResult {
        if (preflight.authorization.action != OperationType.RESTART ||
            preflight.evidence.scope.action != OperationType.RESTART
        ) {
            return ExistingInstallationRestartEntryRegistrationResult.Rejected(
                "Restart runtime entry accepts only exact RESTART preflight authority",
            )
        }
        val operationId = preflight.authorization.operationId
        val existing = entries.putIfAbsent(operationId, preflight)
        return when {
            existing == null -> ExistingInstallationRestartEntryRegistrationResult.Registered
            sameAuthority(existing, preflight) -> ExistingInstallationRestartEntryRegistrationResult.AlreadyRegistered
            else -> ExistingInstallationRestartEntryRegistrationResult.Conflict
        }
    }

    fun inspect(
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationRestartEntryInspection {
        val entry = entries[current.snapshot.operationId]
            ?: return ExistingInstallationRestartEntryInspection.Missing
        return validate(entry, current, now)
    }

    /** One-shot consume immediately before the restart executor boundary. */
    fun consume(
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationRestartEntryConsumeResult {
        val operationId = current.snapshot.operationId
        val entry = entries.remove(operationId)
            ?: return ExistingInstallationRestartEntryConsumeResult.Missing
        return when (val validation = validate(entry, current, now)) {
            ExistingInstallationRestartEntryInspection.Available ->
                ExistingInstallationRestartEntryConsumeResult.Consumed(entry)

            ExistingInstallationRestartEntryInspection.Expired ->
                ExistingInstallationRestartEntryConsumeResult.Expired

            is ExistingInstallationRestartEntryInspection.ContractViolation ->
                ExistingInstallationRestartEntryConsumeResult.ContractViolation(validation.reason)

            ExistingInstallationRestartEntryInspection.Missing ->
                error("Removed restart authority cannot become missing")
        }
    }

    fun discard(operationId: OperationId): Boolean {
        val confirmation = confirmations.remove(operationId)
        val preflight = entries.remove(operationId)
        return confirmation != null || preflight != null
    }

    private fun validate(
        entry: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationRestartEntryInspection {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRestartEntryInspection.ContractViolation(
                "Restart runtime entry requires exact InstallationTarget",
            )
        if (snapshot.type != OperationType.RESTART || snapshot.status != OperationStatus.RUNNING) {
            return ExistingInstallationRestartEntryInspection.ContractViolation(
                "Restart authority requires RUNNING RESTART durable operation",
            )
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationRestartEntryInspection.ContractViolation(
                "Restart authority may be consumed only at MUTATION_NOT_STARTED",
            )
        }
        val authorization = entry.authorization
        val scope = entry.evidence.scope
        if (authorization.operationId != snapshot.operationId ||
            authorization.operationRevision != current.revision ||
            authorization.operationTarget != target ||
            authorization.action != OperationType.RESTART ||
            scope.operationId != snapshot.operationId ||
            scope.operationRevision != current.revision.value ||
            scope.serverId != target.serverId ||
            scope.serverAccessId != target.serverAccessId ||
            scope.installationId != target.installationId ||
            scope.action != OperationType.RESTART
        ) {
            return ExistingInstallationRestartEntryInspection.ContractViolation(
                "Restart preflight authority no longer matches exact durable revision/target/action",
            )
        }
        if (now.isBefore(entry.evidence.observedAt) || now.isAfter(entry.evidence.validUntil) ||
            now.isBefore(entry.evidence.installationProof.observedAt) ||
            now.isAfter(entry.evidence.installationProof.validUntil)
        ) {
            return ExistingInstallationRestartEntryInspection.Expired
        }
        return ExistingInstallationRestartEntryInspection.Available
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

sealed interface ExistingInstallationRestartEntryRegistrationResult {
    data object Registered : ExistingInstallationRestartEntryRegistrationResult
    data object AlreadyRegistered : ExistingInstallationRestartEntryRegistrationResult
    data object Conflict : ExistingInstallationRestartEntryRegistrationResult
    data class Rejected(val reason: String) : ExistingInstallationRestartEntryRegistrationResult
}

sealed interface ExistingInstallationRestartEntryInspection {
    data object Available : ExistingInstallationRestartEntryInspection
    data object Missing : ExistingInstallationRestartEntryInspection
    data object Expired : ExistingInstallationRestartEntryInspection
    data class ContractViolation(val reason: String) : ExistingInstallationRestartEntryInspection
}

sealed interface ExistingInstallationRestartEntryConsumeResult {
    data class Consumed(
        val preflight: VerifiedExistingInstallationActionPreflight,
    ) : ExistingInstallationRestartEntryConsumeResult

    data object Missing : ExistingInstallationRestartEntryConsumeResult
    data object Expired : ExistingInstallationRestartEntryConsumeResult
    data class ContractViolation(val reason: String) : ExistingInstallationRestartEntryConsumeResult
}
