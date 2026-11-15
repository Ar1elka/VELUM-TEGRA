package com.velumtegra.xuimobile.core.model

import java.time.Duration
import java.time.Instant

/** Exact non-secret scope for one Phase 9 preflight/plan. */
data class ExistingInstallationActionScope(
    val operationId: OperationId,
    val operationRevision: Long,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
    val installationId: XuiInstallationId,
    val action: OperationType,
    val ownership: InstallationOwnership,
    val managedInstallId: ManagedInstallId?,
) {
    init {
        require(operationRevision >= 0L) { "operationRevision must be non-negative" }
        require(action in PHASE9_ACTIONS) { "scope action must be a Phase 9 existing-installation action" }
        when (ownership) {
            InstallationOwnership.MANAGED -> requireNotNull(managedInstallId) {
                "Managed Phase 9 scope requires managedInstallId"
            }
            InstallationOwnership.ADOPTED -> require(managedInstallId == null) {
                "Adopted Phase 9 scope cannot carry managedInstallId"
            }
        }
    }

    private companion object {
        val PHASE9_ACTIONS = setOf(
            OperationType.RESTART,
            OperationType.RECOVERY,
            OperationType.UNINSTALL,
            OperationType.REINSTALL,
        )
    }
}

enum class ExistingInstallationAccessPathState {
    EXACT_PINNED_AUTHENTICATED,
    UNAVAILABLE,
    HOST_IDENTITY_MISMATCH,
    AUTHENTICATION_REJECTED,
}

enum class ExistingInstallationLayoutCapability {
    STANDARD_3X_UI_SYSTEMD_V1,
    UNSUPPORTED,
}

enum class ExistingInstallationPrivilegeCapability {
    DIRECT_ROOT,
    UNSUPPORTED,
}

enum class ExistingInstallationMutationBarrierState {
    PROVEN_CLEAR,
    BLOCKED,
    UNKNOWN,
}

/**
 * Normalized, read-only preflight evidence. It carries no password/key/session handle/raw output
 * and cannot itself dispatch any remote command.
 */
data class ExistingInstallationPreflightEvidence(
    val scope: ExistingInstallationActionScope,
    val installationProof: InstallationProof,
    val accessPathState: ExistingInstallationAccessPathState,
    val layoutCapability: ExistingInstallationLayoutCapability,
    val privilegeCapability: ExistingInstallationPrivilegeCapability,
    val mutationBarrierState: ExistingInstallationMutationBarrierState,
    val observedAt: Instant,
    val validUntil: Instant,
) {
    init {
        require(!validUntil.isBefore(observedAt)) { "Preflight validity cannot end before observation" }
        require(installationProof.installationId == scope.installationId) {
            "Preflight proof belongs to another installation"
        }
        require(installationProof.serverId == scope.serverId) {
            "Preflight proof belongs to another server"
        }
        require(installationProof.serverAccessId == scope.serverAccessId) {
            "Preflight proof belongs to another access path"
        }
        require(!installationProof.observedAt.isAfter(observedAt)) {
            "Installation proof cannot postdate aggregate preflight observation"
        }
    }
}

enum class ExistingInstallationRemoteCapability {
    SYSTEMD_RESTART_EXACT_SERVICE_V1,
    OFFICIAL_3X_UI_UNINSTALL_V1,
    OFFICIAL_3X_UI_INSTALL_V1,
}

enum class ExistingInstallationActionPlanStepKind {
    RESTART_EXACT_SERVICE,
    READ_ONLY_RECOVERY_DIAGNOSIS,
    EXECUTE_REVIEWED_UNINSTALL,
    EXECUTE_REVIEWED_INSTALLER,
    WRITE_MANAGED_MARKER,
    VERIFY_EXACT_IDENTITY,
    VERIFY_SERVICE_ACTIVE,
    VERIFY_EXPECTED_LISTENER,
    VERIFY_PANEL_SETTINGS,
    VERIFY_INSTALLATION_ABSENT,
}

/** Finite typed action vocabulary. No shell/url/free-form command field exists. */
sealed interface ExistingInstallationActionPlanStep {
    val kind: ExistingInstallationActionPlanStepKind
    val timeout: Duration

    data class RestartExactService(
        val capability: ExistingInstallationRemoteCapability,
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.RESTART_EXACT_SERVICE
    }

    data class ReadOnlyRecoveryDiagnosis(
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.READ_ONLY_RECOVERY_DIAGNOSIS
    }

    data class ExecuteReviewedUninstall(
        val capability: ExistingInstallationRemoteCapability,
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_UNINSTALL
    }

    data class ExecuteReviewedInstaller(
        val capability: ExistingInstallationRemoteCapability,
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_INSTALLER
    }

    data class WriteManagedMarker(
        val managedInstallId: ManagedInstallId,
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.WRITE_MANAGED_MARKER
    }

    data class VerifyExactIdentity(
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.VERIFY_EXACT_IDENTITY
    }

    data class VerifyServiceActive(
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.VERIFY_SERVICE_ACTIVE
    }

    data class VerifyExpectedListener(
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.VERIFY_EXPECTED_LISTENER
    }

    data class VerifyPanelSettings(
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.VERIFY_PANEL_SETTINGS
    }

    data class VerifyInstallationAbsent(
        override val timeout: Duration,
    ) : ExistingInstallationActionPlanStep {
        override val kind = ExistingInstallationActionPlanStepKind.VERIFY_INSTALLATION_ABSENT
    }
}

data class ReviewedExistingInstallationActionPlan(
    val scope: ExistingInstallationActionScope,
    val steps: List<ExistingInstallationActionPlanStep>,
) {
    init {
        require(steps.isNotEmpty()) { "Reviewed Phase 9 plan must contain at least one step" }
        require(steps.all { !it.timeout.isZero && !it.timeout.isNegative }) {
            "Reviewed Phase 9 plan step timeouts must be positive"
        }
    }
}
