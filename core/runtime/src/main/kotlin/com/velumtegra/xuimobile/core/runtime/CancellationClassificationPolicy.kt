package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget

/**
 * Feature/runtime evidence about what kind of remote work may have been active when the user
 * requested cancellation. This is deliberately semantic and transport-independent.
 */
enum class CancellationDispatchEvidence {
    /** No remote mutation could have crossed the Phase 3 dispatch boundary. */
    BEFORE_MUTATION_DISPATCH,

    /** Only read-only remote work may be active. */
    READ_ONLY_ONLY,

    /** A remote mutation may have crossed the dispatch boundary and completion is not proven. */
    MUTATION_MAY_HAVE_DISPATCHED,
}

enum class CancellationResourceDisposition {
    NONE,
    /** Close only resources owned by this exact operation/session; never another owner's handle. */
    CLOSE_EXACT_RESOURCES,
}

enum class CancellationDurableDisposition {
    /** Generic runtime must not rewrite the durable operation state. */
    KEEP_CURRENT,

    /**
     * The feature contract may advance this exact revision to terminal CANCELLED.
     * It must still create a journal-valid TERMINAL checkpoint through normal CAS advancement.
     */
    TERMINAL_CANCEL_ALLOWED,

    /** Durable state must become/retain RECONCILIATION_REQUIRED before any later mutation. */
    REQUIRE_RECONCILIATION,
}

data class CancellationPlanInput(
    val current: VersionedOperationSnapshot,
    val dispatchEvidence: CancellationDispatchEvidence,
    /** Whether the owning feature contract permits terminal cancellation in a proven-safe state. */
    val terminalCancellationPermitted: Boolean,
)

data class CancellationClassificationPlan(
    val operationId: OperationId,
    val target: OperationTarget,
    /** Revision the future coordinator must still own before applying any durable disposition. */
    val expectedRevision: OperationRevision,
    val resourceDisposition: CancellationResourceDisposition,
    val durableDisposition: CancellationDurableDisposition,
)

/**
 * Pure cancellation classifier.
 *
 * It performs no I/O, does not cancel a coroutine itself and never advances OperationJournal.
 * Durable evidence is authoritative over caller-provided dispatch evidence: an unsafe checkpoint
 * cannot be downgraded to terminal CANCELLED merely because a stale callback claims pre-dispatch.
 */
object CancellationClassificationPolicy {
    private val terminalStatuses = setOf(
        OperationStatus.SUCCEEDED,
        OperationStatus.FAILED,
        OperationStatus.CANCELLED,
    )

    private val uncertainMutationCheckpoints = setOf(
        CheckpointSemantics.MUTATION_IN_FLIGHT,
        CheckpointSemantics.RESTART_IN_FLIGHT,
        CheckpointSemantics.POST_VERIFY_REQUIRED,
    )

    private val verifiedMutationCheckpoints = setOf(
        CheckpointSemantics.MUTATION_VERIFIED,
        CheckpointSemantics.COMMIT_VERIFIED,
    )

    fun classify(input: CancellationPlanInput): CancellationClassificationPlan {
        val snapshot = input.current.snapshot
        val identity = PlanIdentity(
            operationId = snapshot.operationId,
            target = snapshot.target,
            expectedRevision = input.current.revision,
        )

        if (snapshot.status in terminalStatuses || snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return identity.plan(
                resourceDisposition = CancellationResourceDisposition.NONE,
                durableDisposition = CancellationDurableDisposition.KEEP_CURRENT,
            )
        }

        if (
            snapshot.status == OperationStatus.RECONCILIATION_REQUIRED ||
            snapshot.checkpoint.semantics in uncertainMutationCheckpoints ||
            input.dispatchEvidence == CancellationDispatchEvidence.MUTATION_MAY_HAVE_DISPATCHED
        ) {
            return identity.plan(
                resourceDisposition = CancellationResourceDisposition.CLOSE_EXACT_RESOURCES,
                durableDisposition = CancellationDurableDisposition.REQUIRE_RECONCILIATION,
            )
        }

        // A verified mutation is known remote truth. Generic cancellation must not rewrite it as if
        // nothing happened, but reconciliation is also unnecessary merely because Stop was pressed.
        if (snapshot.checkpoint.semantics in verifiedMutationCheckpoints) {
            return identity.plan(
                resourceDisposition = CancellationResourceDisposition.CLOSE_EXACT_RESOURCES,
                durableDisposition = CancellationDurableDisposition.KEEP_CURRENT,
            )
        }

        val terminalCancelAllowed = input.terminalCancellationPermitted &&
            input.dispatchEvidence in setOf(
                CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
                CancellationDispatchEvidence.READ_ONLY_ONLY,
            )

        return identity.plan(
            resourceDisposition = CancellationResourceDisposition.CLOSE_EXACT_RESOURCES,
            durableDisposition = if (terminalCancelAllowed) {
                CancellationDurableDisposition.TERMINAL_CANCEL_ALLOWED
            } else {
                CancellationDurableDisposition.KEEP_CURRENT
            },
        )
    }

    private data class PlanIdentity(
        val operationId: OperationId,
        val target: OperationTarget,
        val expectedRevision: OperationRevision,
    ) {
        fun plan(
            resourceDisposition: CancellationResourceDisposition,
            durableDisposition: CancellationDurableDisposition,
        ): CancellationClassificationPlan = CancellationClassificationPlan(
            operationId = operationId,
            target = target,
            expectedRevision = expectedRevision,
            resourceDisposition = resourceDisposition,
            durableDisposition = durableDisposition,
        )
    }
}
