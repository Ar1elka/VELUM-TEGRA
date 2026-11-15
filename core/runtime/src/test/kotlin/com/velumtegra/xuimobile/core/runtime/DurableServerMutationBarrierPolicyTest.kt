package com.velumtegra.xuimobile.core.runtime

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
import org.junit.Assert.assertTrue
import org.junit.Test

class DurableServerMutationBarrierPolicyTest {
    @Test
    fun `no durable operation allows new mutation`() {
        assertEquals(
            ServerMutationBarrierDecision.Allowed,
            DurableServerMutationBarrierPolicy.evaluate(ServerId("server-a"), emptyList()),
        )
    }

    @Test
    fun `mutation in flight on same server blocks new mutation`() {
        val blocker = operation(
            operationId = "op-old",
            serverId = "server-a",
            status = OperationStatus.RUNNING,
            semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
        )

        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(blocker),
        )

        assertBlockedBy(decision, "op-old", CheckpointSemantics.MUTATION_IN_FLIGHT)
    }

    @Test
    fun `restart in flight on same server blocks new mutation`() {
        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(
                operation(
                    operationId = "op-old",
                    serverId = "server-a",
                    status = OperationStatus.WAITING,
                    semantics = CheckpointSemantics.RESTART_IN_FLIGHT,
                ),
            ),
        )

        assertBlockedBy(decision, "op-old", CheckpointSemantics.RESTART_IN_FLIGHT)
    }

    @Test
    fun `post verify required on same server blocks new mutation`() {
        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(
                operation(
                    operationId = "op-old",
                    serverId = "server-a",
                    status = OperationStatus.RECONCILIATION_REQUIRED,
                    semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                ),
            ),
        )

        assertBlockedBy(decision, "op-old", CheckpointSemantics.POST_VERIFY_REQUIRED)
    }

    @Test
    fun `unsafe operation on another server does not block exact server`() {
        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(
                operation(
                    operationId = "op-other",
                    serverId = "server-b",
                    status = OperationStatus.RUNNING,
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                ),
            ),
        )

        assertEquals(ServerMutationBarrierDecision.Allowed, decision)
    }

    @Test
    fun `safe nonterminal checkpoints on same server do not create uncertain barrier`() {
        val safeSemantics = listOf(
            CheckpointSemantics.READ_ONLY,
            CheckpointSemantics.MUTATION_NOT_STARTED,
            CheckpointSemantics.MUTATION_VERIFIED,
            CheckpointSemantics.COMMIT_VERIFIED,
        )

        safeSemantics.forEachIndexed { index, semantics ->
            val decision = DurableServerMutationBarrierPolicy.evaluate(
                ServerId("server-a"),
                listOf(
                    operation(
                        operationId = "op-safe-$index",
                        serverId = "server-a",
                        status = OperationStatus.RUNNING,
                        semantics = semantics,
                    ),
                ),
            )
            assertEquals(ServerMutationBarrierDecision.Allowed, decision)
        }
    }

    @Test
    fun `WAITING preserves unsafe checkpoint and still blocks mutation`() {
        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(
                operation(
                    operationId = "op-waiting",
                    serverId = "server-a",
                    status = OperationStatus.WAITING,
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                ),
            ),
        )

        assertBlockedBy(decision, "op-waiting", CheckpointSemantics.MUTATION_IN_FLIGHT)
    }

    @Test
    fun `same unsafe OperationId also blocks mutation replay`() {
        val sameOperation = operation(
            operationId = "op-recover",
            serverId = "server-a",
            status = OperationStatus.RECONCILIATION_REQUIRED,
            semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
        )

        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(sameOperation),
        )

        assertBlockedBy(decision, "op-recover", CheckpointSemantics.MUTATION_IN_FLIGHT)
    }

    @Test
    fun `terminal durable operation does not leave a barrier`() {
        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(
                operation(
                    operationId = "op-done",
                    serverId = "server-a",
                    status = OperationStatus.SUCCEEDED,
                    semantics = CheckpointSemantics.TERMINAL,
                ),
            ),
        )

        assertEquals(ServerMutationBarrierDecision.Allowed, decision)
    }

    @Test
    fun `multiple blockers are deterministic and preserve exact evidence`() {
        val decision = DurableServerMutationBarrierPolicy.evaluate(
            ServerId("server-a"),
            listOf(
                operation(
                    operationId = "op-z",
                    serverId = "server-a",
                    status = OperationStatus.RUNNING,
                    semantics = CheckpointSemantics.RESTART_IN_FLIGHT,
                ),
                operation(
                    operationId = "op-a",
                    serverId = "server-a",
                    status = OperationStatus.WAITING,
                    semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                ),
            ),
        )

        assertTrue(decision is ServerMutationBarrierDecision.BlockedByUncertainMutation)
        val blockers = (decision as ServerMutationBarrierDecision.BlockedByUncertainMutation).blockers
        assertEquals(listOf("op-a", "op-z"), blockers.map { it.operationId.value })
        assertEquals(
            listOf(CheckpointSemantics.POST_VERIFY_REQUIRED, CheckpointSemantics.RESTART_IN_FLIGHT),
            blockers.map { it.checkpointSemantics },
        )
    }

    @Test
    fun `same durable evidence recreates barrier after process-local state is lost`() {
        val durable = listOf(
            operation(
                operationId = "op-uncertain",
                serverId = "server-a",
                status = OperationStatus.RECONCILIATION_REQUIRED,
                semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
            ),
        )

        val beforeProcessDeath = DurableServerMutationBarrierPolicy.evaluate(ServerId("server-a"), durable)
        val afterProcessRestart = DurableServerMutationBarrierPolicy.evaluate(ServerId("server-a"), durable)

        assertEquals(beforeProcessDeath, afterProcessRestart)
        assertTrue(afterProcessRestart is ServerMutationBarrierDecision.BlockedByUncertainMutation)
    }

    private fun assertBlockedBy(
        decision: ServerMutationBarrierDecision,
        operationId: String,
        semantics: CheckpointSemantics,
    ) {
        assertTrue(decision is ServerMutationBarrierDecision.BlockedByUncertainMutation)
        val blockers = (decision as ServerMutationBarrierDecision.BlockedByUncertainMutation).blockers
        assertEquals(1, blockers.size)
        assertEquals(operationId, blockers.single().operationId.value)
        assertEquals(semantics, blockers.single().checkpointSemantics)
    }

    private fun operation(
        operationId: String,
        serverId: String,
        status: OperationStatus,
        semantics: CheckpointSemantics,
    ): OperationSnapshot {
        val now = Instant.parse("2026-09-01T00:00:00Z")
        return OperationSnapshot(
            operationId = OperationId(operationId),
            type = OperationType.INSTALL,
            target = OperationTarget.ServerTarget(
                serverId = ServerId(serverId),
                serverAccessId = ServerAccessId("access-$serverId"),
            ),
            status = status,
            checkpoint = OperationCheckpoint(
                phaseName = semantics.name,
                semantics = semantics,
                recordedAt = now,
            ),
            startedAt = now,
            updatedAt = now,
        )
    }
}
