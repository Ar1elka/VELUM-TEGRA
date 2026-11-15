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

/** Process-local one-shot authority for the exact destructive Phase 9.7 REINSTALL dispatch. */
class ExistingInstallationReinstallEntryRegistry {
    private val entries = ConcurrentHashMap<OperationId, VerifiedExistingInstallationActionPreflight>()

    fun register(preflight: VerifiedExistingInstallationActionPreflight): ExistingInstallationReinstallEntryRegistrationResult {
        if (preflight.authorization.action != OperationType.REINSTALL ||
            preflight.evidence.scope.action != OperationType.REINSTALL ||
            preflight.authorization.ownership != com.velumtegra.xuimobile.core.model.InstallationOwnership.MANAGED
        ) {
            return ExistingInstallationReinstallEntryRegistrationResult.Rejected(
                "Reinstall runtime entry accepts only exact REINSTALL preflight authority",
            )
        }
        val operationId = preflight.authorization.operationId
        val existing = entries.putIfAbsent(operationId, preflight)
        return when {
            existing == null -> ExistingInstallationReinstallEntryRegistrationResult.Registered
            sameAuthority(existing, preflight) -> ExistingInstallationReinstallEntryRegistrationResult.AlreadyRegistered
            else -> ExistingInstallationReinstallEntryRegistrationResult.Conflict
        }
    }

    fun inspect(current: VersionedOperationSnapshot, now: Instant): ExistingInstallationReinstallEntryInspection {
        val entry = entries[current.snapshot.operationId] ?: return ExistingInstallationReinstallEntryInspection.Missing
        return validate(entry, current, now)
    }

    fun consume(current: VersionedOperationSnapshot, now: Instant): ExistingInstallationReinstallEntryConsumeResult {
        val entry = entries.remove(current.snapshot.operationId) ?: return ExistingInstallationReinstallEntryConsumeResult.Missing
        return when (val validation = validate(entry, current, now)) {
            ExistingInstallationReinstallEntryInspection.Available -> ExistingInstallationReinstallEntryConsumeResult.Consumed(entry)
            ExistingInstallationReinstallEntryInspection.Expired -> ExistingInstallationReinstallEntryConsumeResult.Expired
            is ExistingInstallationReinstallEntryInspection.ContractViolation ->
                ExistingInstallationReinstallEntryConsumeResult.ContractViolation(validation.reason)
            ExistingInstallationReinstallEntryInspection.Missing -> error("Removed reinstall authority cannot become missing")
        }
    }

    fun discard(operationId: OperationId): Boolean = entries.remove(operationId) != null

    private fun validate(
        entry: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationReinstallEntryInspection {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationReinstallEntryInspection.ContractViolation(
                "Reinstall runtime entry requires exact InstallationTarget",
            )
        if (snapshot.type != OperationType.REINSTALL || snapshot.status != OperationStatus.RUNNING) {
            return ExistingInstallationReinstallEntryInspection.ContractViolation(
                "Reinstall authority requires RUNNING REINSTALL durable operation",
            )
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationReinstallEntryInspection.ContractViolation(
                "Reinstall authority may be consumed only at MUTATION_NOT_STARTED",
            )
        }
        val authorization = entry.authorization
        val scope = entry.evidence.scope
        if (authorization.operationId != snapshot.operationId ||
            authorization.operationRevision != current.revision ||
            authorization.operationTarget != target ||
            authorization.action != OperationType.REINSTALL ||
            scope.operationId != snapshot.operationId ||
            scope.operationRevision != current.revision.value ||
            scope.serverId != target.serverId ||
            scope.serverAccessId != target.serverAccessId ||
            scope.installationId != target.installationId ||
            scope.action != OperationType.REINSTALL
        ) {
            return ExistingInstallationReinstallEntryInspection.ContractViolation(
                "Reinstall preflight authority no longer matches exact durable revision/target/action",
            )
        }
        if (now.isBefore(entry.evidence.observedAt) || now.isAfter(entry.evidence.validUntil) ||
            now.isBefore(entry.evidence.installationProof.observedAt) || now.isAfter(entry.evidence.installationProof.validUntil)
        ) {
            return ExistingInstallationReinstallEntryInspection.Expired
        }
        return ExistingInstallationReinstallEntryInspection.Available
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

sealed interface ExistingInstallationReinstallEntryRegistrationResult {
    data object Registered : ExistingInstallationReinstallEntryRegistrationResult
    data object AlreadyRegistered : ExistingInstallationReinstallEntryRegistrationResult
    data object Conflict : ExistingInstallationReinstallEntryRegistrationResult
    data class Rejected(val reason: String) : ExistingInstallationReinstallEntryRegistrationResult
}

sealed interface ExistingInstallationReinstallEntryInspection {
    data object Available : ExistingInstallationReinstallEntryInspection
    data object Missing : ExistingInstallationReinstallEntryInspection
    data object Expired : ExistingInstallationReinstallEntryInspection
    data class ContractViolation(val reason: String) : ExistingInstallationReinstallEntryInspection
}

sealed interface ExistingInstallationReinstallEntryConsumeResult {
    data class Consumed(val preflight: VerifiedExistingInstallationActionPreflight) : ExistingInstallationReinstallEntryConsumeResult
    data object Missing : ExistingInstallationReinstallEntryConsumeResult
    data object Expired : ExistingInstallationReinstallEntryConsumeResult
    data class ContractViolation(val reason: String) : ExistingInstallationReinstallEntryConsumeResult
}
