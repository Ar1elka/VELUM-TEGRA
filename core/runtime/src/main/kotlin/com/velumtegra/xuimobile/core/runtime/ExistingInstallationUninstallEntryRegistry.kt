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

/** Process-local one-shot authority for the exact destructive Phase 9.6 UNINSTALL dispatch. */
class ExistingInstallationUninstallEntryRegistry {
    private val entries = ConcurrentHashMap<OperationId, VerifiedExistingInstallationActionPreflight>()

    fun register(preflight: VerifiedExistingInstallationActionPreflight): ExistingInstallationUninstallEntryRegistrationResult {
        if (preflight.authorization.action != OperationType.UNINSTALL ||
            preflight.evidence.scope.action != OperationType.UNINSTALL
        ) {
            return ExistingInstallationUninstallEntryRegistrationResult.Rejected(
                "Uninstall runtime entry accepts only exact UNINSTALL preflight authority",
            )
        }
        val operationId = preflight.authorization.operationId
        val existing = entries.putIfAbsent(operationId, preflight)
        return when {
            existing == null -> ExistingInstallationUninstallEntryRegistrationResult.Registered
            sameAuthority(existing, preflight) -> ExistingInstallationUninstallEntryRegistrationResult.AlreadyRegistered
            else -> ExistingInstallationUninstallEntryRegistrationResult.Conflict
        }
    }

    fun inspect(current: VersionedOperationSnapshot, now: Instant): ExistingInstallationUninstallEntryInspection {
        val entry = entries[current.snapshot.operationId] ?: return ExistingInstallationUninstallEntryInspection.Missing
        return validate(entry, current, now)
    }

    fun consume(current: VersionedOperationSnapshot, now: Instant): ExistingInstallationUninstallEntryConsumeResult {
        val entry = entries.remove(current.snapshot.operationId) ?: return ExistingInstallationUninstallEntryConsumeResult.Missing
        return when (val validation = validate(entry, current, now)) {
            ExistingInstallationUninstallEntryInspection.Available -> ExistingInstallationUninstallEntryConsumeResult.Consumed(entry)
            ExistingInstallationUninstallEntryInspection.Expired -> ExistingInstallationUninstallEntryConsumeResult.Expired
            is ExistingInstallationUninstallEntryInspection.ContractViolation ->
                ExistingInstallationUninstallEntryConsumeResult.ContractViolation(validation.reason)
            ExistingInstallationUninstallEntryInspection.Missing -> error("Removed uninstall authority cannot become missing")
        }
    }

    fun discard(operationId: OperationId): Boolean = entries.remove(operationId) != null

    private fun validate(
        entry: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        now: Instant,
    ): ExistingInstallationUninstallEntryInspection {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationUninstallEntryInspection.ContractViolation(
                "Uninstall runtime entry requires exact InstallationTarget",
            )
        if (snapshot.type != OperationType.UNINSTALL || snapshot.status != OperationStatus.RUNNING) {
            return ExistingInstallationUninstallEntryInspection.ContractViolation(
                "Uninstall authority requires RUNNING UNINSTALL durable operation",
            )
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationUninstallEntryInspection.ContractViolation(
                "Uninstall authority may be consumed only at MUTATION_NOT_STARTED",
            )
        }
        val authorization = entry.authorization
        val scope = entry.evidence.scope
        if (authorization.operationId != snapshot.operationId ||
            authorization.operationRevision != current.revision ||
            authorization.operationTarget != target ||
            authorization.action != OperationType.UNINSTALL ||
            scope.operationId != snapshot.operationId ||
            scope.operationRevision != current.revision.value ||
            scope.serverId != target.serverId ||
            scope.serverAccessId != target.serverAccessId ||
            scope.installationId != target.installationId ||
            scope.action != OperationType.UNINSTALL
        ) {
            return ExistingInstallationUninstallEntryInspection.ContractViolation(
                "Uninstall preflight authority no longer matches exact durable revision/target/action",
            )
        }
        if (now.isBefore(entry.evidence.observedAt) || now.isAfter(entry.evidence.validUntil) ||
            now.isBefore(entry.evidence.installationProof.observedAt) || now.isAfter(entry.evidence.installationProof.validUntil)
        ) {
            return ExistingInstallationUninstallEntryInspection.Expired
        }
        return ExistingInstallationUninstallEntryInspection.Available
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

sealed interface ExistingInstallationUninstallEntryRegistrationResult {
    data object Registered : ExistingInstallationUninstallEntryRegistrationResult
    data object AlreadyRegistered : ExistingInstallationUninstallEntryRegistrationResult
    data object Conflict : ExistingInstallationUninstallEntryRegistrationResult
    data class Rejected(val reason: String) : ExistingInstallationUninstallEntryRegistrationResult
}

sealed interface ExistingInstallationUninstallEntryInspection {
    data object Available : ExistingInstallationUninstallEntryInspection
    data object Missing : ExistingInstallationUninstallEntryInspection
    data object Expired : ExistingInstallationUninstallEntryInspection
    data class ContractViolation(val reason: String) : ExistingInstallationUninstallEntryInspection
}

sealed interface ExistingInstallationUninstallEntryConsumeResult {
    data class Consumed(val preflight: VerifiedExistingInstallationActionPreflight) : ExistingInstallationUninstallEntryConsumeResult
    data object Missing : ExistingInstallationUninstallEntryConsumeResult
    data object Expired : ExistingInstallationUninstallEntryConsumeResult
    data class ContractViolation(val reason: String) : ExistingInstallationUninstallEntryConsumeResult
}
