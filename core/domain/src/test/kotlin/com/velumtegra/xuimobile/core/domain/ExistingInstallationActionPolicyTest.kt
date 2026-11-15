package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationActionPolicyTest {
    private val now = Instant.parse("2026-09-13T09:00:00Z")
    private val serverId = ServerId("server-a")
    private val accessId = ServerAccessId("access-a")
    private val installationId = XuiInstallationId("xui-a")
    private val managedInstallId = ManagedInstallId("v1-managed-a")

    private fun identity(ownership: InstallationOwnership) = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = if (ownership == InstallationOwnership.MANAGED) managedInstallId else null,
    )

    private fun installation(
        ownership: InstallationOwnership = InstallationOwnership.MANAGED,
    ): XuiInstallation {
        val identity = identity(ownership)
        return XuiInstallation(
            id = installationId,
            serverId = serverId,
            ownership = ownership,
            identity = identity,
            baseline = InstallationBaseline(
                serviceUnit = identity.serviceUnit,
                binaryPath = identity.binaryPath,
                rootPath = identity.rootPath,
                databasePath = identity.databasePath,
                panelPort = 2053,
                webBasePath = "/panel/",
                listenAddress = "127.0.0.1",
                capturedAt = now.minusSeconds(30),
            ),
        )
    }

    private fun verifiedTarget(
        installation: XuiInstallation = installation(),
        proofAccessId: ServerAccessId = accessId,
        observedAt: Instant = now.minusSeconds(5),
        validUntil: Instant = now.plusSeconds(55),
    ): VerifiedInstallationTarget {
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.10", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("secret-a")),
            pinnedHostKey = HostKeyFingerprint("SHA256:test"),
        )
        val proof = InstallationProof(
            id = TargetProofId("proof-a"),
            installationId = installation.id,
            serverId = installation.serverId,
            serverAccessId = proofAccessId,
            observedIdentity = installation.identity,
            observedAt = observedAt,
            validUntil = validUntil,
        )
        val result = TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now.minusSeconds(1))
        assertTrue(result is TargetVerificationResult.Verified)
        return (result as TargetVerificationResult.Verified).target
    }

    private fun operation(
        type: OperationType,
        target: OperationTarget = OperationTarget.InstallationTarget(serverId, accessId, installationId),
        status: OperationStatus = OperationStatus.PENDING,
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_NOT_STARTED,
        revision: Long = 3L,
    ) = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = OperationId("phase9-op"),
            type = type,
            target = target,
            status = status,
            checkpoint = OperationCheckpoint("PREPARING", semantics, now),
            startedAt = now.minusSeconds(10),
            updatedAt = now,
        ),
        revision = OperationRevision(revision),
    )

    @Test
    fun `exact restart recovery and uninstall authorize either ownership`() {
        val actions = listOf(OperationType.RESTART, OperationType.RECOVERY, OperationType.UNINSTALL)
        val ownerships = listOf(InstallationOwnership.MANAGED, InstallationOwnership.ADOPTED)

        actions.forEach { action ->
            ownerships.forEach { ownership ->
                val installation = installation(ownership)
                val result = ExistingInstallationActionAuthorizationPolicy.verify(
                    operation(action),
                    installation,
                    verifiedTarget(installation),
                    now,
                )
                assertTrue("$action/$ownership should be authorized", result is ExistingInstallationActionAuthorizationResult.Verified)
            }
        }
    }

    @Test
    fun `managed reinstall is authorized but adopted reinstall fails closed`() {
        val managed = installation(InstallationOwnership.MANAGED)
        val managedResult = ExistingInstallationActionAuthorizationPolicy.verify(
            operation(OperationType.REINSTALL),
            managed,
            verifiedTarget(managed),
            now,
        )
        assertTrue(managedResult is ExistingInstallationActionAuthorizationResult.Verified)

        val adopted = installation(InstallationOwnership.ADOPTED)
        val adoptedResult = ExistingInstallationActionAuthorizationPolicy.verify(
            operation(OperationType.REINSTALL),
            adopted,
            verifiedTarget(adopted),
            now,
        )
        assertTrue(adoptedResult is ExistingInstallationActionAuthorizationResult.Rejected)
    }

    @Test
    fun `non Phase 9 action and ServerTarget are rejected`() {
        val installation = installation()
        val verified = verifiedTarget(installation)
        assertTrue(
            ExistingInstallationActionAuthorizationPolicy.verify(
                operation(OperationType.INSTALL), installation, verified, now,
            ) is ExistingInstallationActionAuthorizationResult.Rejected,
        )
        assertTrue(
            ExistingInstallationActionAuthorizationPolicy.verify(
                operation(
                    OperationType.RESTART,
                    OperationTarget.ServerTarget(serverId, accessId),
                ),
                installation,
                verified,
                now,
            ) is ExistingInstallationActionAuthorizationResult.Rejected,
        )
    }

    @Test
    fun `verified target must equal durable operation target`() {
        val installation = installation()
        val result = ExistingInstallationActionAuthorizationPolicy.verify(
            operation(
                OperationType.RESTART,
                OperationTarget.InstallationTarget(serverId, accessId, XuiInstallationId("other-xui")),
            ),
            installation,
            verifiedTarget(installation),
            now,
        )
        assertTrue(result is ExistingInstallationActionAuthorizationResult.Rejected)
    }

    @Test
    fun `stale or future proof is rejected at action authorization boundary`() {
        val installation = installation()
        val stale = verifiedTarget(
            installation = installation,
            observedAt = now.minusSeconds(60),
            validUntil = now.minusSeconds(1),
        )
        val future = verifiedTarget(
            installation = installation,
            observedAt = now.plusSeconds(10),
            validUntil = now.plusSeconds(70),
        )
        assertTrue(
            ExistingInstallationActionAuthorizationPolicy.verify(
                operation(OperationType.RESTART), installation, stale, now,
            ) is ExistingInstallationActionAuthorizationResult.Rejected,
        )
        assertTrue(
            ExistingInstallationActionAuthorizationPolicy.verify(
                operation(OperationType.RESTART), installation, future, now,
            ) is ExistingInstallationActionAuthorizationResult.Rejected,
        )
    }

    @Test
    fun `unsafe checkpoint or reconciliation status cannot mint new action authority`() {
        val installation = installation()
        val verified = verifiedTarget(installation)
        assertTrue(
            ExistingInstallationActionAuthorizationPolicy.verify(
                operation(OperationType.RESTART, semantics = CheckpointSemantics.RESTART_IN_FLIGHT),
                installation,
                verified,
                now,
            ) is ExistingInstallationActionAuthorizationResult.Rejected,
        )
        assertTrue(
            ExistingInstallationActionAuthorizationPolicy.verify(
                operation(OperationType.RESTART, status = OperationStatus.RECONCILIATION_REQUIRED),
                installation,
                verified,
                now,
            ) is ExistingInstallationActionAuthorizationResult.Rejected,
        )
    }

    @Test
    fun `verified capability is exact to operation action target and ownership`() {
        val installation = installation()
        val result = ExistingInstallationActionAuthorizationPolicy.verify(
            operation(OperationType.RESTART),
            installation,
            verifiedTarget(installation),
            now,
        )
        assertTrue(result is ExistingInstallationActionAuthorizationResult.Verified)
        val authorization = (result as ExistingInstallationActionAuthorizationResult.Verified).authorization
        assertEquals(OperationId("phase9-op"), authorization.operationId)
        assertEquals(OperationRevision(3L), authorization.operationRevision)
        assertEquals(OperationType.RESTART, authorization.action)
        assertEquals(installationId, authorization.operationTarget.installationId)
        assertEquals(accessId, authorization.operationTarget.serverAccessId)
        assertEquals(InstallationOwnership.MANAGED, authorization.ownership)
    }

    @Test
    fun `phase mapping is conservative across read only mutation restart verify and commit boundaries`() {
        assertEquals(CheckpointSemantics.READ_ONLY, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.READ_ONLY_DIAGNOSIS))
        assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.PREPARING))
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.MUTATION_DISPATCHED))
        assertEquals(CheckpointSemantics.MUTATION_VERIFIED, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.MUTATION_VERIFIED))
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.RESTART_DISPATCHED))
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.POST_VERIFY))
        assertEquals(CheckpointSemantics.COMMIT_VERIFIED, ExistingInstallationActionStatePolicy.checkpointForPhase(ExistingInstallationActionPhase.COMMIT_VERIFIED))
    }

    @Test
    fun `uncertainty result preserves the exact unsafe dispatch boundary`() {
        val mutationUnknown = ExistingInstallationActionResult.ReconciliationRequired(
            ExistingInstallationUncertaintyKind.MUTATION_MAY_HAVE_DISPATCHED,
            now,
        )
        val restartUnknown = ExistingInstallationActionResult.ReconciliationRequired(
            ExistingInstallationUncertaintyKind.RESTART_MAY_HAVE_DISPATCHED,
            now,
        )
        val verifyUnknown = ExistingInstallationActionResult.ReconciliationRequired(
            ExistingInstallationUncertaintyKind.POST_VERIFY_INCOMPLETE,
            now,
        )
        val localCommitUnknown = ExistingInstallationActionResult.ReconciliationRequired(
            ExistingInstallationUncertaintyKind.LOCAL_COMMIT_INCOMPLETE,
            now,
        )
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, ExistingInstallationActionStatePolicy.checkpointForResult(mutationUnknown))
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, ExistingInstallationActionStatePolicy.checkpointForResult(restartUnknown))
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, ExistingInstallationActionStatePolicy.checkpointForResult(verifyUnknown))
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, ExistingInstallationActionStatePolicy.checkpointForResult(localCommitUnknown))
    }

    @Test
    fun `only pre dispatch terminal outcomes or committed success map terminal`() {
        assertEquals(
            CheckpointSemantics.TERMINAL,
            ExistingInstallationActionStatePolicy.checkpointForResult(
                ExistingInstallationActionResult.RejectedBeforeDispatch(
                    ExistingInstallationPreDispatchRejectionKind.PREFLIGHT_REJECTED,
                    now,
                ),
            ),
        )
        assertEquals(
            CheckpointSemantics.TERMINAL,
            ExistingInstallationActionStatePolicy.checkpointForResult(
                ExistingInstallationActionResult.CancelledBeforeDispatch(now),
            ),
        )
        assertEquals(
            CheckpointSemantics.TERMINAL,
            ExistingInstallationActionStatePolicy.checkpointForResult(
                ExistingInstallationActionResult.CommittedSuccess(now),
            ),
        )
    }
}
