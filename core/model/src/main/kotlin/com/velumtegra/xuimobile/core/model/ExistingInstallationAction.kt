package com.velumtegra.xuimobile.core.model

import java.time.Instant

/**
 * Feature-specific Phase 9 state names. They map to the generic durable checkpoint semantics but
 * intentionally carry no SSH command, session, secret or retry authority.
 */
enum class ExistingInstallationActionPhase {
    READ_ONLY_DIAGNOSIS,
    PREPARING,
    MUTATION_DISPATCHED,
    MUTATION_VERIFIED,
    RESTART_DISPATCHED,
    POST_VERIFY,
    COMMIT_VERIFIED,
}

/** The boundary at which remote truth became uncertain. */
enum class ExistingInstallationUncertaintyKind {
    MUTATION_MAY_HAVE_DISPATCHED,
    RESTART_MAY_HAVE_DISPATCHED,
    POST_VERIFY_INCOMPLETE,
    LOCAL_COMMIT_INCOMPLETE,
}

enum class ExistingInstallationPreDispatchRejectionKind {
    TARGET_REJECTED,
    ACTION_NOT_ALLOWED,
    OWNERSHIP_NOT_ALLOWED,
    PREFLIGHT_REJECTED,
}

/**
 * Conservative Phase 9 result algebra. Only a locally committed success is terminal success.
 * Ambiguous post-dispatch outcomes retain the checkpoint semantics of the uncertainty boundary.
 */
sealed interface ExistingInstallationActionResult {
    data class RejectedBeforeDispatch(
        val reason: ExistingInstallationPreDispatchRejectionKind,
        val completedAt: Instant,
    ) : ExistingInstallationActionResult

    data class CancelledBeforeDispatch(
        val completedAt: Instant,
    ) : ExistingInstallationActionResult

    data class ReconciliationRequired(
        val reason: ExistingInstallationUncertaintyKind,
        val observedAt: Instant,
    ) : ExistingInstallationActionResult

    data class CommittedSuccess(
        val completedAt: Instant,
    ) : ExistingInstallationActionResult
}
