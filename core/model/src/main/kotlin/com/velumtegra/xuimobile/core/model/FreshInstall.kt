package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** Exact read-only preflight scope for one fresh INSTALL operation. */
data class FreshInstallScope(
    val operationId: OperationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
)

enum class FreshInstallInstallerCapability {
    OFFICIAL_3X_UI_LINUX_V1,
}

enum class FreshInstallPrivilegeCapability {
    DIRECT_ROOT,
    NON_INTERACTIVE_ESCALATION,
}

enum class FreshInstallConflictState {
    PROVEN_CLEAR,
    SUPPORTED_INSTALLATION_PRESENT,
    FOREIGN_OR_CONFLICTING_STATE,
    AMBIGUOUS,
}

/**
 * Process-local/read-only evidence used only to authorize a fresh install. It deliberately carries
 * no XuiInstallationId and therefore cannot be confused with an existing-installation proof.
 */
data class FreshInstallPreflightProof(
    val id: TargetProofId,
    val scope: FreshInstallScope,
    val platform: DiscoveryPlatform,
    val installerCapability: FreshInstallInstallerCapability,
    val privilegeCapability: FreshInstallPrivilegeCapability,
    val conflictState: FreshInstallConflictState,
    val observedAt: Instant,
    val validUntil: Instant,
) {
    init {
        require(!validUntil.isBefore(observedAt)) { "Proof validity cannot end before observation" }
    }
}

enum class InstallerPhase {
    PREPARING,
    DOWNLOADING,
    INSTALLING,
    VERIFYING,
}

sealed interface InstallerResult {
    data class Success(
        val managedInstallId: ManagedInstallId,
        val completedAt: Instant,
    ) : InstallerResult

    data class Failed(
        val reason: InstallerFailureKind,
        val completedAt: Instant,
    ) : InstallerResult

    data class CancelledBeforeDispatch(
        val completedAt: Instant,
    ) : InstallerResult

    data class ReconciliationRequired(
        val reason: InstallerUncertaintyKind,
        val observedAt: Instant,
    ) : InstallerResult
}

enum class InstallerFailureKind {
    PREFLIGHT_REJECTED,
    UNSUPPORTED_PLATFORM,
    INSUFFICIENT_PRIVILEGE,
    AUTHENTICATION_REJECTED,
    HOST_IDENTITY_MISMATCH,
    VERIFIED_REMOTE_FAILURE,
    LOCAL_PUBLICATION_FAILED,
    INTERNAL_INVARIANT_FAILURE,
}

enum class InstallerUncertaintyKind {
    TRANSPORT_LOSS_AFTER_DISPATCH,
    TIMEOUT_AFTER_DISPATCH,
    PROCESS_DEATH_AFTER_DISPATCH,
    CANCELLATION_AFTER_DISPATCH,
    VERIFICATION_INCOMPLETE,
}
