package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResumePolicyTest {
    private val now = Instant.parse("2026-08-30T09:00:00Z")

    private fun operation(semantics: CheckpointSemantics): OperationSnapshot = OperationSnapshot(
        operationId = OperationId("op-a"),
        type = OperationType.RECOVERY,
        target = OperationTarget.InstallationTarget(
            serverId = ServerId("server-a"),
            serverAccessId = ServerAccessId("access-a"),
            installationId = XuiInstallationId("xui-a"),
        ),
        status = OperationStatus.RUNNING,
        checkpoint = OperationCheckpoint("phase", semantics, now),
        startedAt = now,
        updatedAt = now,
    )

    @Test
    fun `backgrounding does not stop operation`() {
        val plan = ResumePolicy.plan(
            operation(CheckpointSemantics.READ_ONLY),
            InterruptionReason.APP_BACKGROUNDED,
            ConnectivityState.ONLINE,
        )
        assertEquals(ResumeAction.CONTINUE, plan.action)
        assertTrue(plan.automaticAllowed)
    }

    @Test
    fun `network loss waits instead of failing`() {
        val plan = ResumePolicy.plan(
            operation(CheckpointSemantics.MUTATION_NOT_STARTED),
            InterruptionReason.NETWORK_LOSS,
            ConnectivityState.OFFLINE,
        )
        assertEquals(ResumeAction.WAIT_FOR_NETWORK, plan.action)
    }

    @Test
    fun `network returns after mutation uncertainty requires read only reconciliation`() {
        val plan = ResumePolicy.plan(
            operation(CheckpointSemantics.MUTATION_IN_FLIGHT),
            InterruptionReason.NETWORK_LOSS,
            ConnectivityState.ONLINE,
        )
        assertEquals(ResumeAction.RECONCILE_READ_ONLY, plan.action)
    }

    @Test
    fun `process death cannot replay in flight mutation`() {
        val plan = ResumePolicy.plan(
            operation(CheckpointSemantics.MUTATION_IN_FLIGHT),
            InterruptionReason.PROCESS_DEATH,
            ConnectivityState.ONLINE,
        )
        assertEquals(ResumeAction.RECONCILE_READ_ONLY, plan.action)
        assertTrue(plan.automaticAllowed)
    }

    @Test
    fun `force stop waits for explicit user launch then reconciles`() {
        val plan = ResumePolicy.plan(
            operation(CheckpointSemantics.MUTATION_IN_FLIGHT),
            InterruptionReason.USER_FORCE_STOP,
            ConnectivityState.ONLINE,
        )
        assertEquals(ResumeAction.RECONCILE_READ_ONLY, plan.action)
        assertFalse(plan.automaticAllowed)
    }

    @Test
    fun `device reboot never blindly replays mutation`() {
        val plan = ResumePolicy.plan(
            operation(CheckpointSemantics.RESTART_IN_FLIGHT),
            InterruptionReason.DEVICE_REBOOT,
            ConnectivityState.ONLINE,
        )
        assertEquals(ResumeAction.RECONCILE_READ_ONLY, plan.action)
        assertFalse(plan.automaticAllowed)
    }
}
