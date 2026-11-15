package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationActionPlanPolicyTest {
    private val now = Instant.parse("2026-09-13T09:30:00Z")
    private val serverId = ServerId("server-plan")
    private val accessId = ServerAccessId("access-plan")
    private val installationId = XuiInstallationId("xui-plan")
    private val operationId = OperationId("phase9-plan-op")
    private val managedInstallId = ManagedInstallId("v1-managed-plan")

    private fun identity(ownership: InstallationOwnership) = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = if (ownership == InstallationOwnership.MANAGED) managedInstallId else null,
    )

    private fun installation(ownership: InstallationOwnership = InstallationOwnership.MANAGED) = XuiInstallation(
        id = installationId,
        serverId = serverId,
        ownership = ownership,
        identity = identity(ownership),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = 2053,
            webBasePath = "/panel/",
            listenAddress = "127.0.0.1",
            capturedAt = now.minusSeconds(120),
        ),
    )

    private fun access() = ServerAccess(
        id = accessId,
        serverId = serverId,
        endpoint = SshEndpoint("203.0.113.20", 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("secret-plan")),
        pinnedHostKey = HostKeyFingerprint("SHA256:phase9-plan"),
    )

    private fun targetProof(
        installation: XuiInstallation,
        observedAt: Instant = now.minusSeconds(5),
        validUntil: Instant = now.plusSeconds(55),
    ) = InstallationProof(
        id = TargetProofId("target-proof-plan"),
        installationId = installation.id,
        serverId = installation.serverId,
        serverAccessId = accessId,
        observedIdentity = installation.identity,
        observedAt = observedAt,
        validUntil = validUntil,
    )

    private fun verifiedTarget(installation: XuiInstallation): VerifiedInstallationTarget {
        val result = TargetProofPolicy.verifyKnownInstallation(
            installation = installation,
            access = access(),
            proof = targetProof(installation),
            now = now,
        )
        assertTrue(result is TargetVerificationResult.Verified)
        return (result as TargetVerificationResult.Verified).target
    }

    private fun operation(
        action: OperationType,
        revision: Long = 7L,
        target: OperationTarget = OperationTarget.InstallationTarget(serverId, accessId, installationId),
        status: OperationStatus = OperationStatus.RUNNING,
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_NOT_STARTED,
    ) = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = action,
            target = target,
            status = status,
            checkpoint = OperationCheckpoint("PREPARING", semantics, now.minusSeconds(1)),
            startedAt = now.minusSeconds(30),
            updatedAt = now.minusSeconds(1),
        ),
        revision = OperationRevision(revision),
    )

    private fun authorization(
        action: OperationType,
        installation: XuiInstallation = installation(),
        versioned: VersionedOperationSnapshot = operation(action),
    ): VerifiedExistingInstallationAction {
        val result = ExistingInstallationActionAuthorizationPolicy.verify(
            operation = versioned,
            installation = installation,
            verifiedTarget = verifiedTarget(installation),
            now = now,
        )
        assertTrue(result is ExistingInstallationActionAuthorizationResult.Verified)
        return (result as ExistingInstallationActionAuthorizationResult.Verified).authorization
    }

    private fun evidence(
        authorization: VerifiedExistingInstallationAction,
        installation: XuiInstallation,
        accessPathState: ExistingInstallationAccessPathState = ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
        layout: ExistingInstallationLayoutCapability = ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
        privilege: ExistingInstallationPrivilegeCapability = ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
        barrier: ExistingInstallationMutationBarrierState = ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
        observedAt: Instant = now.minusSeconds(2),
        validUntil: Instant = now.plusSeconds(30),
        proof: InstallationProof = targetProof(installation, now.minusSeconds(3), now.plusSeconds(30)),
        revision: Long = authorization.operationRevision.value,
    ) = ExistingInstallationPreflightEvidence(
        scope = ExistingInstallationActionScope(
            operationId = authorization.operationId,
            operationRevision = revision,
            serverId = authorization.operationTarget.serverId,
            serverAccessId = authorization.operationTarget.serverAccessId,
            installationId = authorization.operationTarget.installationId,
            action = authorization.action,
            ownership = authorization.ownership,
            managedInstallId = installation.identity.managedInstallId,
        ),
        installationProof = proof,
        accessPathState = accessPathState,
        layoutCapability = layout,
        privilegeCapability = privilege,
        mutationBarrierState = barrier,
        observedAt = observedAt,
        validUntil = validUntil,
    )

    private fun verifiedPreflight(
        action: OperationType,
        ownership: InstallationOwnership = InstallationOwnership.MANAGED,
    ): VerifiedExistingInstallationActionPreflight {
        val installation = installation(ownership)
        val current = operation(action)
        val authorization = authorization(action, installation, current)
        val result = ExistingInstallationActionPreflightPolicy.verify(
            authorization = authorization,
            currentOperation = current,
            installation = installation,
            evidence = evidence(authorization, installation),
            now = now,
        )
        assertTrue(result is ExistingInstallationActionPreflightResult.Verified)
        return (result as ExistingInstallationActionPreflightResult.Verified).preflight
    }

    @Test
    fun `preflight is exact to operation revision action target ownership and fresh proof`() {
        val installation = installation()
        val current = operation(OperationType.RESTART, revision = 9L)
        val authorization = authorization(OperationType.RESTART, installation, current)
        val result = ExistingInstallationActionPreflightPolicy.verify(
            authorization,
            current,
            installation,
            evidence(authorization, installation),
            now,
        )
        assertTrue(result is ExistingInstallationActionPreflightResult.Verified)
        val verified = (result as ExistingInstallationActionPreflightResult.Verified).preflight
        assertEquals(OperationRevision(9L), verified.authorization.operationRevision)
        assertEquals(9L, verified.evidence.scope.operationRevision)
        assertEquals(OperationType.RESTART, verified.evidence.scope.action)
        assertEquals(installationId, verified.evidence.scope.installationId)
        assertEquals(accessId, verified.evidence.scope.serverAccessId)
    }

    @Test
    fun `revision advance and current unsafe state fail closed before plan creation`() {
        val installation = installation()
        val authorizedAt = operation(OperationType.RESTART, revision = 4L)
        val authorization = authorization(OperationType.RESTART, installation, authorizedAt)

        val revisionMoved = operation(OperationType.RESTART, revision = 5L)
        assertTrue(
            ExistingInstallationActionPreflightPolicy.verify(
                authorization, revisionMoved, installation, evidence(authorization, installation), now,
            ) is ExistingInstallationActionPreflightResult.Rejected,
        )

        val unsafe = operation(
            OperationType.RESTART,
            revision = 4L,
            status = OperationStatus.RECONCILIATION_REQUIRED,
            semantics = CheckpointSemantics.RESTART_IN_FLIGHT,
        )
        assertTrue(
            ExistingInstallationActionPreflightPolicy.verify(
                authorization, unsafe, installation, evidence(authorization, installation), now,
            ) is ExistingInstallationActionPreflightResult.Rejected,
        )
    }

    @Test
    fun `preflight requires exact pinned authenticated access supported layout direct root and clear barrier`() {
        val installation = installation()
        val current = operation(OperationType.UNINSTALL)
        val authorization = authorization(OperationType.UNINSTALL, installation, current)

        val badEvidence = listOf(
            evidence(authorization, installation, accessPathState = ExistingInstallationAccessPathState.HOST_IDENTITY_MISMATCH),
            evidence(authorization, installation, layout = ExistingInstallationLayoutCapability.UNSUPPORTED),
            evidence(authorization, installation, privilege = ExistingInstallationPrivilegeCapability.UNSUPPORTED),
            evidence(authorization, installation, barrier = ExistingInstallationMutationBarrierState.BLOCKED),
            evidence(authorization, installation, barrier = ExistingInstallationMutationBarrierState.UNKNOWN),
        )
        badEvidence.forEach { candidate ->
            assertTrue(
                ExistingInstallationActionPreflightPolicy.verify(
                    authorization, current, installation, candidate, now,
                ) is ExistingInstallationActionPreflightResult.Rejected,
            )
        }
    }

    @Test
    fun `preflight rejects stale future or mismatched same session proof`() {
        val installation = installation()
        val current = operation(OperationType.RESTART)
        val authorization = authorization(OperationType.RESTART, installation, current)

        val stale = evidence(
            authorization,
            installation,
            observedAt = now.minusSeconds(60),
            validUntil = now.minusSeconds(1),
            proof = targetProof(installation, now.minusSeconds(60), now.minusSeconds(1)),
        )
        assertTrue(
            ExistingInstallationActionPreflightPolicy.verify(
                authorization, current, installation, stale, now,
            ) is ExistingInstallationActionPreflightResult.Rejected,
        )

        val future = evidence(
            authorization,
            installation,
            observedAt = now.plusSeconds(5),
            validUntil = now.plusSeconds(30),
            proof = targetProof(installation, now.plusSeconds(4), now.plusSeconds(30)),
        )
        assertTrue(
            ExistingInstallationActionPreflightPolicy.verify(
                authorization, current, installation, future, now,
            ) is ExistingInstallationActionPreflightResult.Rejected,
        )

        val otherIdentity = installation.copy(
            baseline = installation.baseline.copy(panelPort = 8443),
        )
        val wrongProof = targetProof(otherIdentity).copy(
            observedIdentity = installation.identity.copy(binaryPath = "/opt/other/x-ui"),
        )
        val mismatch = evidence(authorization, installation, proof = wrongProof)
        assertTrue(
            ExistingInstallationActionPreflightPolicy.verify(
                authorization, current, installation, mismatch, now,
            ) is ExistingInstallationActionPreflightResult.Rejected,
        )
    }

    @Test
    fun `restart plan is finite typed bounded and requires exact post verify`() {
        val plan = ReviewedExistingInstallationActionPlanPolicy.build(
            verifiedPreflight(OperationType.RESTART),
        )
        assertEquals(
            listOf(
                ExistingInstallationActionPlanStepKind.RESTART_EXACT_SERVICE,
                ExistingInstallationActionPlanStepKind.VERIFY_EXACT_IDENTITY,
                ExistingInstallationActionPlanStepKind.VERIFY_SERVICE_ACTIVE,
                ExistingInstallationActionPlanStepKind.VERIFY_EXPECTED_LISTENER,
            ),
            plan.steps.map { it.kind },
        )
        assertTrue(ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan))
        assertTrue(ExistingInstallationPlanInspectionPolicy.containsMutation(plan))
        assertTrue(plan.steps.all { !it.timeout.isNegative && !it.timeout.isZero })
    }

    @Test
    fun `recovery plan is diagnosis only and cannot silently escalate to mutation`() {
        val plan = ReviewedExistingInstallationActionPlanPolicy.build(
            verifiedPreflight(OperationType.RECOVERY),
        )
        assertEquals(
            listOf(ExistingInstallationActionPlanStepKind.READ_ONLY_RECOVERY_DIAGNOSIS),
            plan.steps.map { it.kind },
        )
        assertTrue(ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan))
        assertFalse(ExistingInstallationPlanInspectionPolicy.containsMutation(plan))
    }

    @Test
    fun `uninstall plan is one reviewed destructive capability followed by exact absence verification`() {
        listOf(InstallationOwnership.MANAGED, InstallationOwnership.ADOPTED).forEach { ownership ->
            val plan = ReviewedExistingInstallationActionPlanPolicy.build(
                verifiedPreflight(OperationType.UNINSTALL, ownership),
            )
            assertEquals(
                listOf(
                    ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_UNINSTALL,
                    ExistingInstallationActionPlanStepKind.VERIFY_INSTALLATION_ABSENT,
                ),
                plan.steps.map { it.kind },
            )
            assertTrue(ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan))
        }
    }

    @Test
    fun `managed reinstall is one compound plan preserving managed marker and adopted reinstall remains impossible`() {
        val preflight = verifiedPreflight(OperationType.REINSTALL, InstallationOwnership.MANAGED)
        val plan = ReviewedExistingInstallationActionPlanPolicy.build(preflight)
        assertEquals(
            listOf(
                ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_UNINSTALL,
                ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_INSTALLER,
                ExistingInstallationActionPlanStepKind.WRITE_MANAGED_MARKER,
                ExistingInstallationActionPlanStepKind.VERIFY_EXACT_IDENTITY,
                ExistingInstallationActionPlanStepKind.VERIFY_SERVICE_ACTIVE,
                ExistingInstallationActionPlanStepKind.VERIFY_EXPECTED_LISTENER,
                ExistingInstallationActionPlanStepKind.VERIFY_PANEL_SETTINGS,
            ),
            plan.steps.map { it.kind },
        )
        val marker = plan.steps[2] as ExistingInstallationActionPlanStep.WriteManagedMarker
        assertEquals(managedInstallId, marker.managedInstallId)
        assertTrue(ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan))

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
    fun `forged reordered or capability changed plans are not canonical`() {
        val canonical = ReviewedExistingInstallationActionPlanPolicy.build(
            verifiedPreflight(OperationType.RESTART),
        )
        val reordered = canonical.copy(steps = canonical.steps.reversed())
        assertFalse(ReviewedExistingInstallationActionPlanPolicy.isCanonical(reordered))

        val first = canonical.steps.first() as ExistingInstallationActionPlanStep.RestartExactService
        val forged = canonical.copy(
            steps = listOf(
                first.copy(capability = ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_UNINSTALL_V1),
            ) + canonical.steps.drop(1),
        )
        assertFalse(ReviewedExistingInstallationActionPlanPolicy.isCanonical(forged))
    }
}
