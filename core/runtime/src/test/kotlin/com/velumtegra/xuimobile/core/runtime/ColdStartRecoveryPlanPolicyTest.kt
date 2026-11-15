package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationDurabilityValidation
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ColdStartRecoveryPlanPolicyTest {
    private val now = Instant.parse("2026-09-01T16:00:00Z")
    private val target = OperationTarget.ServerTarget(
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
    )

    @Test
    fun `process death at read only checkpoint permits exact reconnect`() {
        val plan = plan(
            semantics = CheckpointSemantics.READ_ONLY,
            exit = RecoveryExitProvenance.PROCESS_DEATH,
        )

        assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plan.action)
        assertTrue(plan.automaticAllowed)
        assertNull(plan.blockReason)
    }

    @Test
    fun `process death at mutation in flight requires read only reconciliation`() {
        val plan = plan(
            semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
            exit = RecoveryExitProvenance.PROCESS_DEATH,
        )

        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
        assertTrue(plan.automaticAllowed)
    }

    @Test
    fun `waiting status never erases unsafe checkpoint semantics`() {
        val plan = plan(
            semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
            status = OperationStatus.WAITING,
            exit = RecoveryExitProvenance.SYSTEM_STOP,
        )

        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
        assertTrue(plan.automaticAllowed)
    }

    @Test
    fun `verified mutation is safe for exact reconnect after process death`() {
        val plan = plan(
            semantics = CheckpointSemantics.MUTATION_VERIFIED,
            exit = RecoveryExitProvenance.PROCESS_DEATH,
        )

        assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plan.action)
        assertTrue(plan.automaticAllowed)
    }

    @Test
    fun `user requested stop never authorizes automatic continuation even from safe checkpoint`() {
        val plan = plan(
            semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
            exit = RecoveryExitProvenance.USER_REQUESTED_STOP,
        )

        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `device reboot is conservative even from safe checkpoint`() {
        val plan = plan(
            semantics = CheckpointSemantics.READ_ONLY,
            exit = RecoveryExitProvenance.DEVICE_REBOOT,
        )

        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `unknown cold start provenance requires user allowed exact reconnect for safe checkpoint`() {
        val plan = plan(
            semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
            exit = RecoveryExitProvenance.UNKNOWN,
        )

        assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plan.action)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `unknown cold start provenance cannot replay uncertain mutation`() {
        val plan = plan(
            semantics = CheckpointSemantics.RESTART_IN_FLIGHT,
            exit = RecoveryExitProvenance.UNKNOWN,
        )

        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `corrupt durability evidence blocks recovery before any remote work`() {
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = versioned(CheckpointSemantics.READ_ONLY),
                durabilityValidation = OperationDurabilityValidation.Corrupt("journal mismatch"),
                exitProvenance = RecoveryExitProvenance.PROCESS_DEATH,
            ),
        )

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.DURABILITY_EVIDENCE_CORRUPT, plan.blockReason)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `missing exact access blocks recovery without fallback`() {
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = versioned(CheckpointSemantics.MUTATION_NOT_STARTED),
                durabilityValidation = OperationDurabilityValidation.Valid,
                exitProvenance = RecoveryExitProvenance.PROCESS_DEATH,
                prerequisiteBlock = RecoveryBlockReason.EXACT_ACCESS_MISSING,
            ),
        )

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.EXACT_ACCESS_MISSING, plan.blockReason)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `host identity mismatch blocks recovery rather than becoming network retry`() {
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = versioned(CheckpointSemantics.READ_ONLY),
                durabilityValidation = OperationDurabilityValidation.Valid,
                exitProvenance = RecoveryExitProvenance.PROCESS_DEATH,
                prerequisiteBlock = RecoveryBlockReason.HOST_IDENTITY_MISMATCH,
            ),
        )

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.HOST_IDENTITY_MISMATCH, plan.blockReason)
    }

    @Test
    fun `authentication rejection blocks recovery rather than switching credentials`() {
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = versioned(CheckpointSemantics.READ_ONLY),
                durabilityValidation = OperationDurabilityValidation.Valid,
                exitProvenance = RecoveryExitProvenance.PROCESS_DEATH,
                prerequisiteBlock = RecoveryBlockReason.AUTHENTICATION_REJECTED,
            ),
        )

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.AUTHENTICATION_REJECTED, plan.blockReason)
    }

    @Test
    fun `system stop at safe checkpoint permits later exact reconnect`() {
        val plan = plan(
            semantics = CheckpointSemantics.READ_ONLY,
            exit = RecoveryExitProvenance.SYSTEM_STOP,
        )

        assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plan.action)
        assertTrue(plan.automaticAllowed)
    }

    @Test
    fun `missing required secret blocks recovery without credential substitution`() {
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = versioned(CheckpointSemantics.READ_ONLY),
                durabilityValidation = OperationDurabilityValidation.Valid,
                exitProvenance = RecoveryExitProvenance.PROCESS_DEATH,
                prerequisiteBlock = RecoveryBlockReason.REQUIRED_SECRET_MISSING,
            ),
        )

        assertEquals(RecoveryAction.RECOVERY_BLOCKED, plan.action)
        assertEquals(RecoveryBlockReason.REQUIRED_SECRET_MISSING, plan.blockReason)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `terminal operation produces no recovery work`() {
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = versioned(
                    semantics = CheckpointSemantics.TERMINAL,
                    status = OperationStatus.SUCCEEDED,
                ),
                durabilityValidation = OperationDurabilityValidation.Valid,
                exitProvenance = RecoveryExitProvenance.UNKNOWN,
            ),
        )

        assertEquals(RecoveryAction.NO_ACTION, plan.action)
        assertFalse(plan.automaticAllowed)
        assertNull(plan.blockReason)
    }

    @Test
    fun `plan preserves exact operation target and expected revision`() {
        val current = versioned(
            semantics = CheckpointSemantics.READ_ONLY,
            revision = 17L,
            operationId = OperationId("op-exact"),
        )
        val plan = ColdStartRecoveryPlanPolicy.plan(
            RecoveryPlanInput(
                current = current,
                durabilityValidation = OperationDurabilityValidation.Valid,
                exitProvenance = RecoveryExitProvenance.PROCESS_DEATH,
            ),
        )

        assertEquals(current.snapshot.operationId, plan.operationId)
        assertEquals(current.snapshot.target, plan.target)
        assertEquals(current.revision, plan.expectedRevision)
    }

    @Test
    fun `reconciliation required status forces reconciliation even with safe checkpoint`() {
        val plan = plan(
            semantics = CheckpointSemantics.READ_ONLY,
            status = OperationStatus.RECONCILIATION_REQUIRED,
            exit = RecoveryExitProvenance.PROCESS_DEATH,
        )

        assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
    }

    private fun plan(
        semantics: CheckpointSemantics,
        exit: RecoveryExitProvenance,
        status: OperationStatus = OperationStatus.RUNNING,
    ): ColdStartRecoveryPlan = ColdStartRecoveryPlanPolicy.plan(
        RecoveryPlanInput(
            current = versioned(semantics = semantics, status = status),
            durabilityValidation = OperationDurabilityValidation.Valid,
            exitProvenance = exit,
        ),
    )

    private fun versioned(
        semantics: CheckpointSemantics,
        status: OperationStatus = OperationStatus.RUNNING,
        revision: Long = 3L,
        operationId: OperationId = OperationId("op-a"),
    ): VersionedOperationSnapshot = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.RECOVERY,
            target = target,
            status = status,
            checkpoint = OperationCheckpoint(
                phaseName = "phase",
                semantics = semantics,
                recordedAt = now,
            ),
            startedAt = now,
            updatedAt = now,
        ),
        revision = OperationRevision(revision),
    )
}
