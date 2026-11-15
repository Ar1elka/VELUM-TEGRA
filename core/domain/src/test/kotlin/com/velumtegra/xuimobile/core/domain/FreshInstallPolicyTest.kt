package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FreshInstallPolicyTest {
    private val now = Instant.parse("2026-09-11T18:00:00Z")
    private val operationId = OperationId("install-op-a")
    private val serverId = ServerId("server-a")
    private val accessId = ServerAccessId("access-a")

    private fun operation(
        type: OperationType = OperationType.INSTALL,
        target: OperationTarget = OperationTarget.ServerTarget(serverId, accessId),
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_NOT_STARTED,
    ) = OperationSnapshot(
        operationId = operationId,
        type = type,
        target = target,
        status = OperationStatus.PENDING,
        checkpoint = OperationCheckpoint(
            phaseName = "PREPARING",
            semantics = semantics,
            recordedAt = now,
        ),
        startedAt = now,
        updatedAt = now,
    )

    private fun proof(
        scope: FreshInstallScope = FreshInstallScope(operationId, serverId, accessId),
        conflictState: FreshInstallConflictState = FreshInstallConflictState.PROVEN_CLEAR,
        observedAt: Instant = now,
        validUntil: Instant = now.plusSeconds(60),
    ) = FreshInstallPreflightProof(
        id = TargetProofId("fresh-proof-a"),
        scope = scope,
        platform = DiscoveryPlatform("ubuntu", "24.04"),
        installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
        privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
        conflictState = conflictState,
        observedAt = observedAt,
        validUntil = validUntil,
    )

    @Test
    fun `exact fresh proof authorizes exact install target`() {
        val result = FreshInstallAuthorizationPolicy.verify(operation(), proof(), now)
        assertTrue(result is FreshInstallVerificationResult.Verified)
        val verified = (result as FreshInstallVerificationResult.Verified).target
        assertEquals(operationId, verified.operationId)
        assertEquals(serverId, verified.operationTarget.serverId)
        assertEquals(accessId, verified.operationTarget.serverAccessId)
        assertEquals(ManagedInstallIdentityPolicy.forOperation(operationId), verified.managedInstallId)
    }

    @Test
    fun `reinstall cannot consume fresh install proof`() {
        val result = FreshInstallAuthorizationPolicy.verify(
            operation(type = OperationType.REINSTALL),
            proof(),
            now,
        )
        assertTrue(result is FreshInstallVerificationResult.Rejected)
    }

    @Test
    fun `existing installation target cannot consume fresh install proof`() {
        val result = FreshInstallAuthorizationPolicy.verify(
            operation(
                target = OperationTarget.InstallationTarget(
                    serverId,
                    accessId,
                    XuiInstallationId("existing-xui"),
                ),
            ),
            proof(),
            now,
        )
        assertTrue(result is FreshInstallVerificationResult.Rejected)
    }

    @Test
    fun `proof for another operation or access is rejected`() {
        val otherOperation = proof(
            scope = FreshInstallScope(OperationId("other-op"), serverId, accessId),
        )
        val otherAccess = proof(
            scope = FreshInstallScope(operationId, serverId, ServerAccessId("other-access")),
        )
        assertTrue(FreshInstallAuthorizationPolicy.verify(operation(), otherOperation, now) is FreshInstallVerificationResult.Rejected)
        assertTrue(FreshInstallAuthorizationPolicy.verify(operation(), otherAccess, now) is FreshInstallVerificationResult.Rejected)
    }

    @Test
    fun `conflict or stale proof is rejected before mutation authority exists`() {
        val conflict = proof(conflictState = FreshInstallConflictState.SUPPORTED_INSTALLATION_PRESENT)
        val stale = proof(observedAt = now.minusSeconds(60), validUntil = now.minusSeconds(1))
        assertTrue(FreshInstallAuthorizationPolicy.verify(operation(), conflict, now) is FreshInstallVerificationResult.Rejected)
        assertTrue(FreshInstallAuthorizationPolicy.verify(operation(), stale, now) is FreshInstallVerificationResult.Rejected)
    }

    @Test
    fun `proof cannot authorize after mutation checkpoint started`() {
        val result = FreshInstallAuthorizationPolicy.verify(
            operation(semantics = CheckpointSemantics.MUTATION_IN_FLIGHT),
            proof(),
            now,
        )
        assertTrue(result is FreshInstallVerificationResult.Rejected)
    }

    @Test
    fun `phase mapping is conservative around dispatch and verification`() {
        assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, InstallerCheckpointPolicy.forPhase(InstallerPhase.PREPARING))
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, InstallerCheckpointPolicy.forPhase(InstallerPhase.DOWNLOADING))
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, InstallerCheckpointPolicy.forPhase(InstallerPhase.INSTALLING))
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, InstallerCheckpointPolicy.forPhase(InstallerPhase.VERIFYING))
    }

    @Test
    fun `uncertain result never maps to terminal`() {
        val uncertain = InstallerResult.ReconciliationRequired(
            InstallerUncertaintyKind.TRANSPORT_LOSS_AFTER_DISPATCH,
            now,
        )
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, InstallerCheckpointPolicy.forResult(uncertain))
        assertEquals(
            CheckpointSemantics.TERMINAL,
            InstallerCheckpointPolicy.forResult(InstallerResult.CancelledBeforeDispatch(now)),
        )
    }

    @Test
    fun `managed marker identity is deterministic operation scoped and non raw`() {
        val first = ManagedInstallIdentityPolicy.forOperation(operationId)
        val second = ManagedInstallIdentityPolicy.forOperation(operationId)
        val other = ManagedInstallIdentityPolicy.forOperation(OperationId("install-op-b"))
        assertEquals(first, second)
        assertNotEquals(first, other)
        assertTrue(first.value.startsWith("v1-"))
        assertTrue(operationId.value !in first.value)
    }
}
