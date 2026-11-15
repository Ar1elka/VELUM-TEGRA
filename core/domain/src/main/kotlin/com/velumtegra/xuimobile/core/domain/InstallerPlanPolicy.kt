package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.InstallerPlanStep
import com.velumtegra.xuimobile.core.model.InstallerWorkerEvidence
import com.velumtegra.xuimobile.core.model.InstallerWorkerLiveness
import com.velumtegra.xuimobile.core.model.InstallerWorkerProcessState
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.InstallerWorkerTerminalState
import com.velumtegra.xuimobile.core.model.InstallerWorkerUnknownReason
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ReviewedInstallPlan
import java.time.Duration
import java.time.Instant

/** Builds the only Phase 8.3 reviewed plan. No caller-supplied shell/url/path enters the plan. */
object ReviewedInstallPlanPolicy {
    val PREPARE_WORKER_TIMEOUT: Duration = Duration.ofSeconds(10)
    val FETCH_INSTALLER_TIMEOUT: Duration = Duration.ofMinutes(2)
    val EXECUTE_INSTALLER_TIMEOUT: Duration = Duration.ofMinutes(15)
    val WRITE_MARKER_TIMEOUT: Duration = Duration.ofSeconds(10)

    fun build(target: VerifiedFreshInstallTarget): ReviewedInstallPlan {
        val capability = target.proof.installerCapability
        require(capability == FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1) {
            "Fresh-install proof references an unsupported reviewed installer capability"
        }
        val scope = InstallerWorkerScope(
            operationId = target.operationId,
            serverId = target.operationTarget.serverId,
            serverAccessId = target.operationTarget.serverAccessId,
            managedInstallId = target.managedInstallId,
        )
        return ReviewedInstallPlan(
            scope = scope,
            capability = capability,
            steps = listOf(
                InstallerPlanStep.PrepareWorker(PREPARE_WORKER_TIMEOUT),
                InstallerPlanStep.FetchReviewedInstaller(capability, FETCH_INSTALLER_TIMEOUT),
                InstallerPlanStep.ExecuteReviewedInstaller(capability, EXECUTE_INSTALLER_TIMEOUT),
                InstallerPlanStep.WriteManagedMarker(target.managedInstallId, WRITE_MARKER_TIMEOUT),
            ),
        )
    }


    /**
     * Rejects forged/reordered plans before the SSH boundary. Phase 8.4 may execute only the
     * exact plan shape produced by [build], with the exact reviewed capability and timeouts.
     */
    fun isCanonical(plan: ReviewedInstallPlan): Boolean {
        if (plan.capability != FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1) return false
        if (plan.steps.size != 4) return false

        val prepare = plan.steps[0] as? InstallerPlanStep.PrepareWorker ?: return false
        val fetch = plan.steps[1] as? InstallerPlanStep.FetchReviewedInstaller ?: return false
        val execute = plan.steps[2] as? InstallerPlanStep.ExecuteReviewedInstaller ?: return false
        val marker = plan.steps[3] as? InstallerPlanStep.WriteManagedMarker ?: return false

        if (prepare.timeout != PREPARE_WORKER_TIMEOUT) return false
        if (fetch.timeout != FETCH_INSTALLER_TIMEOUT || fetch.capability != plan.capability) return false
        if (execute.timeout != EXECUTE_INSTALLER_TIMEOUT || execute.capability != plan.capability) return false
        if (marker.timeout != WRITE_MARKER_TIMEOUT || marker.managedInstallId != plan.scope.managedInstallId) return false

        return runCatching { ManagedInstallMarkerProtocol.encode(plan.scope.managedInstallId) }.isSuccess
    }

}

/** Canonical non-secret remote marker contract introduced by Phase 8.3. */
object ManagedInstallMarkerProtocol {
    const val MARKER_PATH: String = "/var/lib/velum-tegra/managed-install/v1/identity"
    private const val PREFIX = "VELUM_TEGRA_MANAGED_INSTALL_V1="
    private val managedIdRegex = Regex("v1-[0-9a-f]{32}")

    fun encode(managedInstallId: ManagedInstallId): String {
        require(managedIdRegex.matches(managedInstallId.value)) { "ManagedInstallId is not canonical v1 format" }
        return "$PREFIX${managedInstallId.value}\n"
    }

    /** null means the exact marker path was proven absent by the future read-only executor. */
    fun classifyReadback(
        expected: ManagedInstallId,
        raw: String?,
    ): ManagedInstallMarkerReadbackState {
        if (raw == null) return ManagedInstallMarkerReadbackState.ABSENT
        val actual = parseReadback(raw) ?: return ManagedInstallMarkerReadbackState.MALFORMED
        return if (actual == expected) {
            ManagedInstallMarkerReadbackState.MATCH
        } else {
            ManagedInstallMarkerReadbackState.MISMATCH
        }
    }

    /** Exact id written in a present marker file, or null when the content is not one canonical marker line. */
    fun parseReadback(raw: String): ManagedInstallId? {
        if (raw.length > 128 || '\u0000' in raw || '\r' in raw) return null
        val normalized = raw.removeSuffix("\n")
        if ('\n' in normalized || !normalized.startsWith(PREFIX)) return null
        val actual = normalized.removePrefix(PREFIX)
        return if (managedIdRegex.matches(actual)) ManagedInstallId(actual) else null
    }
}

/**
 * Independent worker-liveness classifier. Phase/progress timestamps are intentionally not inputs.
 * Stale heartbeat alone never proves death; exact bounded process-death confirmation is required.
 */
object InstallerWorkerLivenessPolicy {
    val HEARTBEAT_INTERVAL: Duration = Duration.ofSeconds(5)
    val HEARTBEAT_STALE_AFTER: Duration = Duration.ofSeconds(20)
    val MIN_DEATH_RECHECK_DELAY: Duration = Duration.ofSeconds(2)
    val MAX_DEATH_RECHECK_DELAY: Duration = Duration.ofSeconds(10)
    val PROCESS_OBSERVATION_TIMEOUT: Duration = Duration.ofSeconds(5)

    fun classify(
        expectedScope: InstallerWorkerScope,
        evidence: InstallerWorkerEvidence,
        now: Instant,
    ): InstallerWorkerLiveness {
        if (evidence.scope != expectedScope) {
            return InstallerWorkerLiveness.Unknown(InstallerWorkerUnknownReason.SCOPE_MISMATCH)
        }
        if (evidence.primaryObservedAt.isAfter(now) ||
            evidence.confirmationObservedAt?.isAfter(now) == true ||
            evidence.heartbeatAt?.isAfter(now) == true ||
            evidence.terminalObservedAt?.isAfter(now) == true
        ) {
            return InstallerWorkerLiveness.Unknown(InstallerWorkerUnknownReason.FUTURE_EVIDENCE)
        }

        when (evidence.terminalState) {
            InstallerWorkerTerminalState.SUCCESS -> return InstallerWorkerLiveness.TerminalSuccess
            InstallerWorkerTerminalState.FAILED -> return InstallerWorkerLiveness.TerminalFailure
            InstallerWorkerTerminalState.UNKNOWN -> {
                return InstallerWorkerLiveness.Unknown(InstallerWorkerUnknownReason.TERMINAL_STATE_UNKNOWN)
            }
            InstallerWorkerTerminalState.NONE -> Unit
        }

        val states = listOfNotNull(evidence.primaryProcessState, evidence.confirmationProcessState)
        val anyAlive = states.any { it == InstallerWorkerProcessState.ALIVE }
        val anyDead = states.any { it == InstallerWorkerProcessState.DEAD }
        if (anyAlive && anyDead) {
            return InstallerWorkerLiveness.Unknown(InstallerWorkerUnknownReason.CONFLICTING_LIVENESS_EVIDENCE)
        }
        if (anyAlive) return InstallerWorkerLiveness.KnownAlive

        val heartbeatAt = evidence.heartbeatAt
            ?: return InstallerWorkerLiveness.Unknown(InstallerWorkerUnknownReason.MISSING_HEARTBEAT)
        val heartbeatAge = Duration.between(heartbeatAt, now)
        if (heartbeatAge <= HEARTBEAT_STALE_AFTER) {
            if (anyDead) {
                return InstallerWorkerLiveness.Unknown(InstallerWorkerUnknownReason.CONFLICTING_LIVENESS_EVIDENCE)
            }
            return InstallerWorkerLiveness.KnownAlive
        }

        if (evidence.primaryProcessState != InstallerWorkerProcessState.DEAD) {
            return InstallerWorkerLiveness.Unknown(
                if (evidence.primaryProcessState == InstallerWorkerProcessState.UNKNOWN) {
                    InstallerWorkerUnknownReason.PROCESS_STATE_UNKNOWN
                } else {
                    InstallerWorkerUnknownReason.HEARTBEAT_STALE_WITHOUT_DEATH_PROOF
                },
            )
        }
        if (evidence.confirmationProcessState != InstallerWorkerProcessState.DEAD ||
            evidence.confirmationObservedAt == null
        ) {
            return InstallerWorkerLiveness.Unknown(
                InstallerWorkerUnknownReason.DEATH_CONFIRMATION_MISSING_OR_OUT_OF_BOUNDS,
            )
        }

        val recheckDelay = Duration.between(evidence.primaryObservedAt, evidence.confirmationObservedAt)
        if (recheckDelay < MIN_DEATH_RECHECK_DELAY || recheckDelay > MAX_DEATH_RECHECK_DELAY) {
            return InstallerWorkerLiveness.Unknown(
                InstallerWorkerUnknownReason.DEATH_CONFIRMATION_MISSING_OR_OUT_OF_BOUNDS,
            )
        }
        return InstallerWorkerLiveness.ProvenDead
    }
}
