package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class CancellationClassificationPolicyTest {
    @Test
    fun `safe pre-dispatch cancel may become terminal when feature permits`() {
        val current = versioned(CheckpointSemantics.MUTATION_NOT_STARTED)

        val plan = classify(
            current = current,
            evidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
            terminalPermitted = true,
        )

        assertEquals(CancellationResourceDisposition.CLOSE_EXACT_RESOURCES, plan.resourceDisposition)
        assertEquals(CancellationDurableDisposition.TERMINAL_CANCEL_ALLOWED, plan.durableDisposition)
    }

    @Test
    fun `safe pre-dispatch cancel stays nonterminal when feature forbids terminal cancel`() {
        val plan = classify(
            current = versioned(CheckpointSemantics.MUTATION_NOT_STARTED),
            evidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
            terminalPermitted = false,
        )

        assertEquals(CancellationDurableDisposition.KEEP_CURRENT, plan.durableDisposition)
    }

    @Test
    fun `read-only cancel closes exact resources and may terminal-cancel when permitted`() {
        val plan = classify(
            current = versioned(CheckpointSemantics.READ_ONLY),
            evidence = CancellationDispatchEvidence.READ_ONLY_ONLY,
            terminalPermitted = true,
        )

        assertEquals(CancellationResourceDisposition.CLOSE_EXACT_RESOURCES, plan.resourceDisposition)
        assertEquals(CancellationDurableDisposition.TERMINAL_CANCEL_ALLOWED, plan.durableDisposition)
    }

    @Test
    fun `possible mutation dispatch always requires reconciliation`() {
        val plan = classify(
            current = versioned(CheckpointSemantics.MUTATION_NOT_STARTED),
            evidence = CancellationDispatchEvidence.MUTATION_MAY_HAVE_DISPATCHED,
            terminalPermitted = true,
        )

        assertEquals(CancellationResourceDisposition.CLOSE_EXACT_RESOURCES, plan.resourceDisposition)
        assertEquals(CancellationDurableDisposition.REQUIRE_RECONCILIATION, plan.durableDisposition)
    }

    @Test
    fun `unsafe durable checkpoint overrides stale pre-dispatch evidence`() {
        listOf(
            CheckpointSemantics.MUTATION_IN_FLIGHT,
            CheckpointSemantics.RESTART_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
        ).forEach { checkpoint ->
            val plan = classify(
                current = versioned(checkpoint),
                evidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
                terminalPermitted = true,
            )

            assertEquals(CancellationDurableDisposition.REQUIRE_RECONCILIATION, plan.durableDisposition)
        }
    }

    @Test
    fun `reconciliation-required status cannot be downgraded by safe checkpoint`() {
        val plan = classify(
            current = versioned(
                checkpoint = CheckpointSemantics.READ_ONLY,
                status = OperationStatus.RECONCILIATION_REQUIRED,
            ),
            evidence = CancellationDispatchEvidence.READ_ONLY_ONLY,
            terminalPermitted = true,
        )

        assertEquals(CancellationDurableDisposition.REQUIRE_RECONCILIATION, plan.durableDisposition)
    }

    @Test
    fun `waiting status preserves unsafe checkpoint cancellation semantics`() {
        val plan = classify(
            current = versioned(
                checkpoint = CheckpointSemantics.MUTATION_IN_FLIGHT,
                status = OperationStatus.WAITING,
            ),
            evidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
            terminalPermitted = true,
        )

        assertEquals(CancellationDurableDisposition.REQUIRE_RECONCILIATION, plan.durableDisposition)
    }

    @Test
    fun `verified mutation is not rewritten to cancelled or uncertainty`() {
        listOf(
            CheckpointSemantics.MUTATION_VERIFIED,
            CheckpointSemantics.COMMIT_VERIFIED,
        ).forEach { checkpoint ->
            val plan = classify(
                current = versioned(checkpoint),
                evidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
                terminalPermitted = true,
            )

            assertEquals(CancellationResourceDisposition.CLOSE_EXACT_RESOURCES, plan.resourceDisposition)
            assertEquals(CancellationDurableDisposition.KEEP_CURRENT, plan.durableDisposition)
        }
    }

    @Test
    fun `terminal operation requires no cancellation work`() {
        val plan = classify(
            current = versioned(
                checkpoint = CheckpointSemantics.TERMINAL,
                status = OperationStatus.CANCELLED,
            ),
            evidence = CancellationDispatchEvidence.MUTATION_MAY_HAVE_DISPATCHED,
            terminalPermitted = true,
        )

        assertEquals(CancellationResourceDisposition.NONE, plan.resourceDisposition)
        assertEquals(CancellationDurableDisposition.KEEP_CURRENT, plan.durableDisposition)
    }

    @Test
    fun `plan preserves exact operation target and revision`() {
        val current = versioned(
            checkpoint = CheckpointSemantics.READ_ONLY,
            revision = 17L,
        )

        val plan = classify(
            current = current,
            evidence = CancellationDispatchEvidence.READ_ONLY_ONLY,
            terminalPermitted = false,
        )

        assertEquals(current.snapshot.operationId, plan.operationId)
        assertEquals(current.snapshot.target, plan.target)
        assertEquals(OperationRevision(17L), plan.expectedRevision)
    }

    private fun classify(
        current: VersionedOperationSnapshot,
        evidence: CancellationDispatchEvidence,
        terminalPermitted: Boolean,
    ): CancellationClassificationPlan = CancellationClassificationPolicy.classify(
        CancellationPlanInput(
            current = current,
            dispatchEvidence = evidence,
            terminalCancellationPermitted = terminalPermitted,
        ),
    )

    private fun versioned(
        checkpoint: CheckpointSemantics,
        status: OperationStatus = OperationStatus.RUNNING,
        revision: Long = 4L,
    ): VersionedOperationSnapshot {
        val startedAt = Instant.parse("2026-08-30T12:00:00Z")
        val updatedAt = Instant.parse("2026-08-30T12:05:00Z")
        return VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = OperationId("op-cancel-1"),
                type = OperationType.INSTALL,
                target = OperationTarget.ServerTarget(
                    serverId = ServerId("server-1"),
                    serverAccessId = ServerAccessId("access-1"),
                ),
                status = status,
                checkpoint = OperationCheckpoint(
                    phaseName = "cancel-test",
                    semantics = checkpoint,
                    recordedAt = updatedAt,
                ),
                startedAt = startedAt,
                updatedAt = updatedAt,
            ),
            revision = OperationRevision(revision),
        )
    }
}
