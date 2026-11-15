package com.velumtegra.xuimobile.core.model

import java.time.Duration
import java.time.Instant

/** Exact non-secret scope shared by one reviewed installer plan and its remote-worker evidence. */
data class InstallerWorkerScope(
    val operationId: OperationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
    val managedInstallId: ManagedInstallId,
)

enum class InstallerPlanStepKind {
    PREPARE_WORKER,
    FETCH_REVIEWED_INSTALLER,
    EXECUTE_REVIEWED_INSTALLER,
    WRITE_MANAGED_MARKER,
}

/**
 * Finite typed install vocabulary. There is intentionally no shell/url/path/string command field.
 * Exact transport compilation belongs to the later SSH executor slice.
 */
sealed interface InstallerPlanStep {
    val kind: InstallerPlanStepKind
    val timeout: Duration

    data class PrepareWorker(
        override val timeout: Duration,
    ) : InstallerPlanStep {
        override val kind: InstallerPlanStepKind = InstallerPlanStepKind.PREPARE_WORKER
    }

    data class FetchReviewedInstaller(
        val capability: FreshInstallInstallerCapability,
        override val timeout: Duration,
    ) : InstallerPlanStep {
        override val kind: InstallerPlanStepKind = InstallerPlanStepKind.FETCH_REVIEWED_INSTALLER
    }

    data class ExecuteReviewedInstaller(
        val capability: FreshInstallInstallerCapability,
        override val timeout: Duration,
    ) : InstallerPlanStep {
        override val kind: InstallerPlanStepKind = InstallerPlanStepKind.EXECUTE_REVIEWED_INSTALLER
    }

    data class WriteManagedMarker(
        val managedInstallId: ManagedInstallId,
        override val timeout: Duration,
    ) : InstallerPlanStep {
        override val kind: InstallerPlanStepKind = InstallerPlanStepKind.WRITE_MANAGED_MARKER
    }
}

data class ReviewedInstallPlan(
    val scope: InstallerWorkerScope,
    val capability: FreshInstallInstallerCapability,
    val steps: List<InstallerPlanStep>,
) {
    init {
        require(steps.isNotEmpty()) { "Reviewed install plan must contain at least one step" }
        require(steps.all { !it.timeout.isZero && !it.timeout.isNegative }) {
            "Reviewed install plan step timeouts must be positive"
        }
    }
}

enum class InstallerWorkerProcessState {
    ALIVE,
    DEAD,
    UNKNOWN,
}

enum class InstallerWorkerTerminalState {
    NONE,
    SUCCESS,
    FAILED,
    UNKNOWN,
}

/**
 * Normalized worker evidence only. It deliberately has no installer phase/progress timestamp:
 * heartbeat and process state are an independent liveness channel.
 */
data class InstallerWorkerEvidence(
    val scope: InstallerWorkerScope,
    val heartbeatAt: Instant?,
    val primaryProcessState: InstallerWorkerProcessState,
    val primaryObservedAt: Instant,
    val confirmationProcessState: InstallerWorkerProcessState? = null,
    val confirmationObservedAt: Instant? = null,
    val terminalState: InstallerWorkerTerminalState = InstallerWorkerTerminalState.NONE,
    val terminalObservedAt: Instant? = null,
) {
    init {
        require((confirmationProcessState == null) == (confirmationObservedAt == null)) {
            "Confirmation process state and timestamp must be present together"
        }
        confirmationObservedAt?.let {
            require(!it.isBefore(primaryObservedAt)) { "Confirmation cannot predate primary observation" }
        }
        when (terminalState) {
            InstallerWorkerTerminalState.NONE -> require(terminalObservedAt == null) {
                "Non-terminal worker evidence cannot carry terminalObservedAt"
            }
            else -> requireNotNull(terminalObservedAt) {
                "Terminal/unknown worker evidence requires terminalObservedAt"
            }
        }
    }
}

enum class InstallerWorkerUnknownReason {
    SCOPE_MISMATCH,
    FUTURE_EVIDENCE,
    MISSING_HEARTBEAT,
    HEARTBEAT_STALE_WITHOUT_DEATH_PROOF,
    CONFLICTING_LIVENESS_EVIDENCE,
    DEATH_CONFIRMATION_MISSING_OR_OUT_OF_BOUNDS,
    TERMINAL_STATE_UNKNOWN,
    PROCESS_STATE_UNKNOWN,
}

sealed interface InstallerWorkerLiveness {
    data object KnownAlive : InstallerWorkerLiveness
    data object TerminalSuccess : InstallerWorkerLiveness
    data object TerminalFailure : InstallerWorkerLiveness
    data object ProvenDead : InstallerWorkerLiveness
    data class Unknown(val reason: InstallerWorkerUnknownReason) : InstallerWorkerLiveness
}

enum class ManagedInstallMarkerReadbackState {
    MATCH,
    ABSENT,
    MISMATCH,
    MALFORMED,
}
