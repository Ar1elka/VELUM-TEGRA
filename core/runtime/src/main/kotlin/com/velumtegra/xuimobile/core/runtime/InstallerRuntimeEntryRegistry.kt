package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.VerifiedFreshInstallTarget
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-local one-shot fresh-install authority handoff.
 *
 * The durable OperationJournal deliberately does not persist [VerifiedFreshInstallTarget] because
 * its bounded preflight proof is short-lived mutation authority, not durable operation truth. A
 * process death therefore drops this authority. Recovery from MUTATION_IN_FLIGHT or later never
 * needs it and must use read-only reconciliation instead of rebuilding/replaying the installer.
 */
class InstallerRuntimeEntryRegistry {
    private val entries = ConcurrentHashMap<OperationId, VerifiedFreshInstallTarget>()

    fun register(target: VerifiedFreshInstallTarget): InstallerRuntimeEntryRegistrationResult {
        if (target.operationId.value.isBlank()) {
            return InstallerRuntimeEntryRegistrationResult.Rejected("Installer OperationId cannot be blank")
        }
        val existing = entries.putIfAbsent(target.operationId, target)
        return when {
            existing == null -> InstallerRuntimeEntryRegistrationResult.Registered
            sameAuthority(existing, target) -> InstallerRuntimeEntryRegistrationResult.AlreadyRegistered
            else -> InstallerRuntimeEntryRegistrationResult.Conflict
        }
    }

    /** Read-only check used before opening SSH. It never consumes authority. */
    fun inspect(
        current: VersionedOperationSnapshot,
        now: Instant,
    ): InstallerRuntimeEntryInspection {
        val target = entries[current.snapshot.operationId]
            ?: return InstallerRuntimeEntryInspection.Missing
        return validate(target, current, now)
    }

    /**
     * Consume one exact fresh-install authority immediately before the mutation executor boundary.
     * Even a pre-dispatch local failure after this point requires a new explicit fresh preflight.
     */
    fun consume(
        current: VersionedOperationSnapshot,
        now: Instant,
    ): InstallerRuntimeEntryConsumeResult {
        val operationId = current.snapshot.operationId
        val target = entries.remove(operationId)
            ?: return InstallerRuntimeEntryConsumeResult.Missing
        return when (val validation = validate(target, current, now)) {
            InstallerRuntimeEntryInspection.Available -> InstallerRuntimeEntryConsumeResult.Consumed(target)
            InstallerRuntimeEntryInspection.Expired -> InstallerRuntimeEntryConsumeResult.Expired
            is InstallerRuntimeEntryInspection.ContractViolation -> {
                InstallerRuntimeEntryConsumeResult.ContractViolation(validation.reason)
            }
            InstallerRuntimeEntryInspection.Missing -> error("Removed installer authority cannot become missing")
        }
    }

    fun discard(operationId: OperationId): Boolean = entries.remove(operationId) != null

    private fun validate(
        target: VerifiedFreshInstallTarget,
        current: VersionedOperationSnapshot,
        now: Instant,
    ): InstallerRuntimeEntryInspection {
        val snapshot = current.snapshot
        val durableTarget = snapshot.target as? OperationTarget.ServerTarget
            ?: return InstallerRuntimeEntryInspection.ContractViolation(
                "Fresh Installer runtime entry requires exact ServerTarget",
            )
        if (snapshot.status != OperationStatus.RUNNING) {
            return InstallerRuntimeEntryInspection.ContractViolation(
                "Fresh Installer authority requires RUNNING durable operation status",
            )
        }
        if (snapshot.type != OperationType.INSTALL ||
            target.operationId != snapshot.operationId ||
            target.operationTarget != durableTarget ||
            target.proof.scope.operationId != snapshot.operationId ||
            target.proof.scope.serverId != durableTarget.serverId ||
            target.proof.scope.serverAccessId != durableTarget.serverAccessId
        ) {
            return InstallerRuntimeEntryInspection.ContractViolation(
                "Fresh Installer authority does not match exact durable operation scope",
            )
        }
        if (now.isBefore(target.proof.observedAt) || now.isAfter(target.proof.validUntil)) {
            return InstallerRuntimeEntryInspection.Expired
        }
        return InstallerRuntimeEntryInspection.Available
    }

    private fun sameAuthority(
        first: VerifiedFreshInstallTarget,
        second: VerifiedFreshInstallTarget,
    ): Boolean = first.operationId == second.operationId &&
        first.operationTarget == second.operationTarget &&
        first.proof == second.proof &&
        first.managedInstallId == second.managedInstallId
}

sealed interface InstallerRuntimeEntryRegistrationResult {
    data object Registered : InstallerRuntimeEntryRegistrationResult
    data object AlreadyRegistered : InstallerRuntimeEntryRegistrationResult
    data object Conflict : InstallerRuntimeEntryRegistrationResult
    data class Rejected(val reason: String) : InstallerRuntimeEntryRegistrationResult
}

sealed interface InstallerRuntimeEntryInspection {
    data object Available : InstallerRuntimeEntryInspection
    data object Missing : InstallerRuntimeEntryInspection
    data object Expired : InstallerRuntimeEntryInspection
    data class ContractViolation(val reason: String) : InstallerRuntimeEntryInspection
}

sealed interface InstallerRuntimeEntryConsumeResult {
    data class Consumed(val target: VerifiedFreshInstallTarget) : InstallerRuntimeEntryConsumeResult
    data object Missing : InstallerRuntimeEntryConsumeResult
    data object Expired : InstallerRuntimeEntryConsumeResult
    data class ContractViolation(val reason: String) : InstallerRuntimeEntryConsumeResult
}
