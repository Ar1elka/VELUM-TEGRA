package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerPlanPolicyTest {
    private val now = Instant.parse("2026-09-11T19:00:00Z")
    private val operationId = OperationId("install-op-plan")
    private val serverId = ServerId("server-plan")
    private val accessId = ServerAccessId("access-plan")

    private fun verifiedTarget(): VerifiedFreshInstallTarget {
        val operation = OperationSnapshot(
            operationId = operationId,
            type = OperationType.INSTALL,
            target = OperationTarget.ServerTarget(serverId, accessId),
            status = OperationStatus.PENDING,
            checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now),
            startedAt = now,
            updatedAt = now,
        )
        val proof = FreshInstallPreflightProof(
            id = TargetProofId("proof-plan"),
            scope = FreshInstallScope(operationId, serverId, accessId),
            platform = DiscoveryPlatform("ubuntu", "24.04"),
            installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
            privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
            conflictState = FreshInstallConflictState.PROVEN_CLEAR,
            observedAt = now,
            validUntil = now.plusSeconds(60),
        )
        val result = FreshInstallAuthorizationPolicy.verify(operation, proof, now)
        return (result as FreshInstallVerificationResult.Verified).target
    }

    @Test
    fun `reviewed plan is exact finite typed and bounded`() {
        val target = verifiedTarget()
        val plan = ReviewedInstallPlanPolicy.build(target)
        assertEquals(operationId, plan.scope.operationId)
        assertEquals(serverId, plan.scope.serverId)
        assertEquals(accessId, plan.scope.serverAccessId)
        assertEquals(target.managedInstallId, plan.scope.managedInstallId)
        assertEquals(
            listOf(
                InstallerPlanStepKind.PREPARE_WORKER,
                InstallerPlanStepKind.FETCH_REVIEWED_INSTALLER,
                InstallerPlanStepKind.EXECUTE_REVIEWED_INSTALLER,
                InstallerPlanStepKind.WRITE_MANAGED_MARKER,
            ),
            plan.steps.map { it.kind },
        )
        assertTrue(plan.steps.all { !it.timeout.isZero && !it.timeout.isNegative })
        assertTrue(plan.steps.all { it.timeout <= ReviewedInstallPlanPolicy.EXECUTE_INSTALLER_TIMEOUT })
    }

    @Test
    fun `managed marker format is fixed bounded and exact`() {
        val managedId = verifiedTarget().managedInstallId
        val encoded = ManagedInstallMarkerProtocol.encode(managedId)
        assertEquals("/var/lib/velum-tegra/managed-install/v1/identity", ManagedInstallMarkerProtocol.MARKER_PATH)
        assertEquals(ManagedInstallMarkerReadbackState.MATCH, ManagedInstallMarkerProtocol.classifyReadback(managedId, encoded))
        assertEquals(ManagedInstallMarkerReadbackState.ABSENT, ManagedInstallMarkerProtocol.classifyReadback(managedId, null))
        val other = ManagedInstallIdentityPolicy.forOperation(OperationId("other-operation"))
        assertEquals(
            ManagedInstallMarkerReadbackState.MISMATCH,
            ManagedInstallMarkerProtocol.classifyReadback(managedId, ManagedInstallMarkerProtocol.encode(other)),
        )
        assertEquals(
            ManagedInstallMarkerReadbackState.MALFORMED,
            ManagedInstallMarkerProtocol.classifyReadback(managedId, "not-a-managed-marker\n"),
        )
        assertFalse(encoded.contains(operationId.value))
    }

    private fun scope() = InstallerWorkerScope(
        operationId,
        serverId,
        accessId,
        ManagedInstallIdentityPolicy.forOperation(operationId),
    )

    @Test
    fun `fresh heartbeat or exact alive process proves worker alive independently from phase`() {
        val expected = scope()
        val freshHeartbeat = InstallerWorkerEvidence(
            scope = expected,
            heartbeatAt = now.minusSeconds(5),
            primaryProcessState = InstallerWorkerProcessState.UNKNOWN,
            primaryObservedAt = now,
        )
        assertEquals(
            InstallerWorkerLiveness.KnownAlive,
            InstallerWorkerLivenessPolicy.classify(expected, freshHeartbeat, now),
        )

        val aliveWithStaleHeartbeat = freshHeartbeat.copy(
            heartbeatAt = now.minusSeconds(60),
            primaryProcessState = InstallerWorkerProcessState.ALIVE,
        )
        assertEquals(
            InstallerWorkerLiveness.KnownAlive,
            InstallerWorkerLivenessPolicy.classify(expected, aliveWithStaleHeartbeat, now),
        )
    }

    @Test
    fun `stale heartbeat alone never proves abandonment`() {
        val expected = scope()
        val evidence = InstallerWorkerEvidence(
            scope = expected,
            heartbeatAt = now.minusSeconds(60),
            primaryProcessState = InstallerWorkerProcessState.DEAD,
            primaryObservedAt = now.minusSeconds(3),
        )
        val result = InstallerWorkerLivenessPolicy.classify(expected, evidence, now)
        assertTrue(result is InstallerWorkerLiveness.Unknown)
        assertEquals(
            InstallerWorkerUnknownReason.DEATH_CONFIRMATION_MISSING_OR_OUT_OF_BOUNDS,
            (result as InstallerWorkerLiveness.Unknown).reason,
        )
    }

    @Test
    fun `stale heartbeat plus two bounded exact dead checks proves worker dead`() {
        val expected = scope()
        val evidence = InstallerWorkerEvidence(
            scope = expected,
            heartbeatAt = now.minusSeconds(60),
            primaryProcessState = InstallerWorkerProcessState.DEAD,
            primaryObservedAt = now.minusSeconds(5),
            confirmationProcessState = InstallerWorkerProcessState.DEAD,
            confirmationObservedAt = now.minusSeconds(2),
        )
        assertEquals(
            InstallerWorkerLiveness.ProvenDead,
            InstallerWorkerLivenessPolicy.classify(expected, evidence, now),
        )
    }

    @Test
    fun `cross operation evidence and contradictory evidence remain unknown`() {
        val expected = scope()
        val crossScope = expected.copy(operationId = OperationId("other-operation"))
        val cross = InstallerWorkerEvidence(
            scope = crossScope,
            heartbeatAt = now.minusSeconds(5),
            primaryProcessState = InstallerWorkerProcessState.ALIVE,
            primaryObservedAt = now,
        )
        val crossResult = InstallerWorkerLivenessPolicy.classify(expected, cross, now)
        assertEquals(
            InstallerWorkerUnknownReason.SCOPE_MISMATCH,
            (crossResult as InstallerWorkerLiveness.Unknown).reason,
        )

        val contradictory = InstallerWorkerEvidence(
            scope = expected,
            heartbeatAt = now.minusSeconds(60),
            primaryProcessState = InstallerWorkerProcessState.ALIVE,
            primaryObservedAt = now.minusSeconds(3),
            confirmationProcessState = InstallerWorkerProcessState.DEAD,
            confirmationObservedAt = now,
        )
        val contradictoryResult = InstallerWorkerLivenessPolicy.classify(expected, contradictory, now)
        assertEquals(
            InstallerWorkerUnknownReason.CONFLICTING_LIVENESS_EVIDENCE,
            (contradictoryResult as InstallerWorkerLiveness.Unknown).reason,
        )
    }

    @Test
    fun `terminal worker evidence is explicit and unknown terminal stays nonterminal`() {
        val expected = scope()
        val success = InstallerWorkerEvidence(
            scope = expected,
            heartbeatAt = now.minusSeconds(1),
            primaryProcessState = InstallerWorkerProcessState.DEAD,
            primaryObservedAt = now,
            terminalState = InstallerWorkerTerminalState.SUCCESS,
            terminalObservedAt = now,
        )
        assertEquals(
            InstallerWorkerLiveness.TerminalSuccess,
            InstallerWorkerLivenessPolicy.classify(expected, success, now),
        )

        val unknown = success.copy(
            terminalState = InstallerWorkerTerminalState.UNKNOWN,
        )
        val result = InstallerWorkerLivenessPolicy.classify(expected, unknown, now)
        assertEquals(
            InstallerWorkerUnknownReason.TERMINAL_STATE_UNKNOWN,
            (result as InstallerWorkerLiveness.Unknown).reason,
        )
    }
}
