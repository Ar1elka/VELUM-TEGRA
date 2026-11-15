package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccess
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * The user's explicit "install 3x-ui on exactly this reviewed server" decision. It is not a
 * preflight proof: it only permits the runtime to connect and then re-observe the target read-only.
 * [access] is the complete reviewed ServerAccess (server, endpoint, pin, credential reference).
 */
data class InstallerExplicitInstallConsent(
    val operationId: OperationId,
    val expectedRevision: OperationRevision,
    val access: ServerAccess,
    val grantedAt: Instant,
    val validUntil: Instant,
)

/**
 * Process-local, one-shot and never persisted: process death drops the consent, and MUTATION_IN_FLIGHT
 * or later recovery never consults it. Separate from the legacy [InstallerRuntimeEntryRegistry].
 */
class InstallerExplicitConsentRegistry {
    private val entries = ConcurrentHashMap<OperationId, InstallerExplicitInstallConsent>()

    fun register(
        consent: InstallerExplicitInstallConsent,
        now: Instant,
    ): InstallerExplicitConsentRegistrationResult {
        if (consent.operationId.value.isBlank()) {
            return InstallerExplicitConsentRegistrationResult.Rejected("Installer OperationId cannot be blank")
        }
        val ttl = Duration.between(consent.grantedAt, consent.validUntil)
        if (ttl.isNegative || ttl.isZero || ttl > MAX_TTL) {
            return InstallerExplicitConsentRegistrationResult.Rejected("Install consent TTL must be in (0, $MAX_TTL]")
        }
        if (now.isBefore(consent.grantedAt) || now.isAfter(consent.validUntil)) {
            return InstallerExplicitConsentRegistrationResult.Rejected("Install consent is not valid now")
        }
        val existing = entries.putIfAbsent(consent.operationId, consent)
        return when {
            existing == null -> InstallerExplicitConsentRegistrationResult.Registered
            existing == consent -> InstallerExplicitConsentRegistrationResult.AlreadyRegistered
            else -> InstallerExplicitConsentRegistrationResult.Conflict
        }
    }

    /** Read-only check before opening SSH. Never consumes. */
    fun inspect(current: VersionedOperationSnapshot, now: Instant): InstallerRuntimeEntryInspection {
        val consent = entries[current.snapshot.operationId] ?: return InstallerRuntimeEntryInspection.Missing
        return validate(consent, current, now)
    }

    /** Removes the consent first: any outcome after this point needs a new explicit confirmation. */
    fun consume(current: VersionedOperationSnapshot, now: Instant): InstallerExplicitConsentConsumeResult {
        val consent = entries.remove(current.snapshot.operationId)
            ?: return InstallerExplicitConsentConsumeResult.Missing
        return when (val validation = validate(consent, current, now)) {
            InstallerRuntimeEntryInspection.Available -> InstallerExplicitConsentConsumeResult.Consumed(consent)
            InstallerRuntimeEntryInspection.Expired -> InstallerExplicitConsentConsumeResult.Expired
            is InstallerRuntimeEntryInspection.ContractViolation ->
                InstallerExplicitConsentConsumeResult.ContractViolation(validation.reason)
            InstallerRuntimeEntryInspection.Missing -> error("Removed install consent cannot become missing")
        }
    }

    fun discard(operationId: OperationId): Boolean = entries.remove(operationId) != null

    private fun validate(
        consent: InstallerExplicitInstallConsent,
        current: VersionedOperationSnapshot,
        now: Instant,
    ): InstallerRuntimeEntryInspection {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.ServerTarget
            ?: return InstallerRuntimeEntryInspection.ContractViolation("Install consent requires exact ServerTarget")
        if (snapshot.type != OperationType.INSTALL || snapshot.status != OperationStatus.RUNNING ||
            consent.operationId != snapshot.operationId ||
            consent.expectedRevision != current.revision ||
            consent.access.id != target.serverAccessId ||
            consent.access.serverId != target.serverId
        ) {
            return InstallerRuntimeEntryInspection.ContractViolation(
                "Install consent does not match the exact durable INSTALL operation, revision and access",
            )
        }
        if (now.isBefore(consent.grantedAt) || now.isAfter(consent.validUntil)) {
            return InstallerRuntimeEntryInspection.Expired
        }
        return InstallerRuntimeEntryInspection.Available
    }

    companion object {
        val MAX_TTL: Duration = Duration.ofMinutes(2)
    }
}

sealed interface InstallerExplicitConsentRegistrationResult {
    data object Registered : InstallerExplicitConsentRegistrationResult
    data object AlreadyRegistered : InstallerExplicitConsentRegistrationResult
    data object Conflict : InstallerExplicitConsentRegistrationResult
    data class Rejected(val reason: String) : InstallerExplicitConsentRegistrationResult
}

sealed interface InstallerExplicitConsentConsumeResult {
    data class Consumed(val consent: InstallerExplicitInstallConsent) : InstallerExplicitConsentConsumeResult
    data object Missing : InstallerExplicitConsentConsumeResult
    data object Expired : InstallerExplicitConsentConsumeResult
    data class ContractViolation(val reason: String) : InstallerExplicitConsentConsumeResult
}
