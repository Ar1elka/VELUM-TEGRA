package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.ExistingInstallationRecoveryCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationRecoveryDiagnosis
import com.velumtegra.xuimobile.core.model.ExistingInstallationRecoveryEvidence
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationRecoveryRepairPlan
import java.time.Duration
import java.time.Instant

/** Process-local proof that read-only RECOVERY diagnosis allows one exact finite repair. */
class VerifiedExistingInstallationRecoveryRepair internal constructor(
    val preflight: VerifiedExistingInstallationActionPreflight,
    val evidence: ExistingInstallationRecoveryEvidence,
    val plan: ReviewedExistingInstallationRecoveryRepairPlan,
)

sealed interface ExistingInstallationRecoveryRepairPolicyResult {
    data class Verified(
        val repair: VerifiedExistingInstallationRecoveryRepair,
    ) : ExistingInstallationRecoveryRepairPolicyResult

    data class NoRepairRequired(
        val evidence: ExistingInstallationRecoveryEvidence,
    ) : ExistingInstallationRecoveryRepairPolicyResult

    data class Blocked(
        val evidence: ExistingInstallationRecoveryEvidence,
    ) : ExistingInstallationRecoveryRepairPolicyResult
}

/**
 * Phase 9.5 fail-closed repair policy. Diagnosis is read-only; the only mutation authority emitted
 * by this slice is one exact `systemctl start x-ui.service` capability after identity/path/unit
 * presence is proven, service state is exactly INACTIVE and the expected listener is absent.
 */
object ExistingInstallationRecoveryRepairPolicy {
    val START_TIMEOUT: Duration = Duration.ofSeconds(30)

    fun authorize(
        preflight: VerifiedExistingInstallationActionPreflight,
        evidence: ExistingInstallationRecoveryEvidence,
        now: Instant,
    ): ExistingInstallationRecoveryRepairPolicyResult {
        require(preflight.authorization.action == OperationType.RECOVERY) {
            "Recovery repair authorization requires RECOVERY preflight"
        }
        require(preflight.evidence.scope == evidence.scope) {
            "Recovery diagnosis scope must equal exact verified preflight scope"
        }
        if (now.isBefore(evidence.observedAt) || now.isAfter(evidence.validUntil)) {
            return ExistingInstallationRecoveryRepairPolicyResult.Blocked(evidence)
        }
        if (now.isAfter(preflight.evidence.validUntil) || now.isAfter(preflight.evidence.installationProof.validUntil)) {
            return ExistingInstallationRecoveryRepairPolicyResult.Blocked(evidence)
        }

        return when (evidence.diagnosis) {
            ExistingInstallationRecoveryDiagnosis.HEALTHY ->
                ExistingInstallationRecoveryRepairPolicyResult.NoRepairRequired(evidence)

            ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT -> {
                val plan = ReviewedExistingInstallationRecoveryRepairPlan(
                    scope = evidence.scope,
                    capability = ExistingInstallationRecoveryCapability.SYSTEMD_START_EXACT_SERVICE_V1,
                    timeout = START_TIMEOUT,
                )
                ExistingInstallationRecoveryRepairPolicyResult.Verified(
                    VerifiedExistingInstallationRecoveryRepair(preflight, evidence, plan),
                )
            }

            ExistingInstallationRecoveryDiagnosis.UNSUPPORTED_OR_CONTRADICTED,
            ExistingInstallationRecoveryDiagnosis.INCOMPLETE,
            -> ExistingInstallationRecoveryRepairPolicyResult.Blocked(evidence)
        }
    }

    fun isCanonical(plan: ReviewedExistingInstallationRecoveryRepairPlan): Boolean =
        plan.scope.action == OperationType.RECOVERY &&
            plan.capability == ExistingInstallationRecoveryCapability.SYSTEMD_START_EXACT_SERVICE_V1 &&
            plan.timeout == START_TIMEOUT
}
