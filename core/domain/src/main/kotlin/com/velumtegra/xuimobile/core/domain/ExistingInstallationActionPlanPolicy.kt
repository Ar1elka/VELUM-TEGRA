package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ExistingInstallationAccessPathState
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionPlanStep
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionPlanStepKind
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionScope
import com.velumtegra.xuimobile.core.model.ExistingInstallationLayoutCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationMutationBarrierState
import com.velumtegra.xuimobile.core.model.ExistingInstallationPreflightEvidence
import com.velumtegra.xuimobile.core.model.ExistingInstallationPrivilegeCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationRemoteCapability
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.time.Duration
import java.time.Instant

/** Process-local proof that the exact Phase 9 action passed same-session read-only preflight. */
class VerifiedExistingInstallationActionPreflight internal constructor(
    val authorization: VerifiedExistingInstallationAction,
    val evidence: ExistingInstallationPreflightEvidence,
)

sealed interface ExistingInstallationActionPreflightResult {
    data class Verified(
        val preflight: VerifiedExistingInstallationActionPreflight,
    ) : ExistingInstallationActionPreflightResult

    data class Rejected(
        val reason: String,
    ) : ExistingInstallationActionPreflightResult
}

/**
 * Pure Phase 9 preflight gate. Future SSH/runtime code may normalize observations into the evidence
 * type, but only this policy turns exact fresh evidence into a process-local preflight capability.
 */
object ExistingInstallationActionPreflightPolicy {
    private val preDispatchStatuses = setOf(
        OperationStatus.PENDING,
        OperationStatus.RUNNING,
    )

    fun verify(
        authorization: VerifiedExistingInstallationAction,
        currentOperation: VersionedOperationSnapshot,
        installation: XuiInstallation,
        evidence: ExistingInstallationPreflightEvidence,
        now: Instant,
    ): ExistingInstallationActionPreflightResult {
        val snapshot = currentOperation.snapshot
        if (currentOperation.revision != authorization.operationRevision) {
            return rejected("Operation revision changed after Phase 9 action authorization")
        }
        if (snapshot.operationId != authorization.operationId || snapshot.type != authorization.action) {
            return rejected("Current operation identity/action no longer matches authorization")
        }
        if (snapshot.target != authorization.operationTarget) {
            return rejected("Current durable operation target no longer matches authorization")
        }
        if (snapshot.status !in preDispatchStatuses ||
            snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED
        ) {
            return rejected("Current operation is no longer at a safe pre-dispatch checkpoint")
        }
        if (installation.id != authorization.operationTarget.installationId ||
            installation.serverId != authorization.operationTarget.serverId ||
            installation.ownership != authorization.ownership
        ) {
            return rejected("Current installation no longer matches the authorized target/ownership")
        }
        if (installation.identity != authorization.verifiedTarget.proof.observedIdentity) {
            return rejected("Current installation identity differs from authorized proof")
        }

        val expectedScope = ExistingInstallationActionScope(
            operationId = authorization.operationId,
            operationRevision = authorization.operationRevision.value,
            serverId = authorization.operationTarget.serverId,
            serverAccessId = authorization.operationTarget.serverAccessId,
            installationId = authorization.operationTarget.installationId,
            action = authorization.action,
            ownership = authorization.ownership,
            managedInstallId = installation.identity.managedInstallId,
        )
        if (evidence.scope != expectedScope) {
            return rejected("Preflight evidence scope does not match exact operation/action/target/revision")
        }
        if (evidence.accessPathState != ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED) {
            return rejected("Exact pinned/authenticated access path was not re-established")
        }
        if (evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1) {
            return rejected("Installation layout is unsupported for reviewed Phase 9 plans")
        }
        if (evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT) {
            return rejected("Required explicit direct-root capability was not proven")
        }
        if (evidence.mutationBarrierState != ExistingInstallationMutationBarrierState.PROVEN_CLEAR) {
            return rejected("Same-server mutation barrier is blocked or unknown")
        }
        if (now.isBefore(evidence.observedAt)) {
            return rejected("Preflight evidence observation is in the future")
        }
        if (now.isAfter(evidence.validUntil)) {
            return rejected("Preflight evidence is stale")
        }

        val proof = evidence.installationProof
        if (proof.installationId != installation.id || proof.serverId != installation.serverId) {
            return rejected("Preflight proof does not belong to the exact installation")
        }
        if (proof.serverAccessId != authorization.operationTarget.serverAccessId) {
            return rejected("Preflight proof was observed through a different access path")
        }
        if (proof.observedIdentity != installation.identity) {
            return rejected("Preflight installation identity does not match durable installation identity")
        }
        if (now.isBefore(proof.observedAt)) {
            return rejected("Preflight installation proof observation is in the future")
        }
        if (now.isAfter(proof.validUntil)) {
            return rejected("Preflight installation proof is stale")
        }
        if (authorization.action == OperationType.REINSTALL && authorization.ownership != InstallationOwnership.MANAGED) {
            return rejected("Reinstall preflight remains fail-closed for non-managed ownership")
        }

        return ExistingInstallationActionPreflightResult.Verified(
            VerifiedExistingInstallationActionPreflight(authorization, evidence),
        )
    }

    private fun rejected(reason: String) = ExistingInstallationActionPreflightResult.Rejected(reason)
}

/** Reviewed finite plan shapes only. Concrete SSH command compilation is deliberately Phase 9.4+. */
object ReviewedExistingInstallationActionPlanPolicy {
    val RESTART_TIMEOUT: Duration = Duration.ofSeconds(30)
    val RECOVERY_DIAGNOSIS_TIMEOUT: Duration = Duration.ofSeconds(30)
    val UNINSTALL_TIMEOUT: Duration = Duration.ofMinutes(5)
    val INSTALL_TIMEOUT: Duration = Duration.ofMinutes(15)
    val WRITE_MARKER_TIMEOUT: Duration = Duration.ofSeconds(10)
    val VERIFY_TIMEOUT: Duration = Duration.ofSeconds(30)

    fun build(preflight: VerifiedExistingInstallationActionPreflight): ReviewedExistingInstallationActionPlan {
        val scope = preflight.evidence.scope
        val steps = when (scope.action) {
            OperationType.RESTART -> restartSteps()
            OperationType.RECOVERY -> recoverySteps()
            OperationType.UNINSTALL -> uninstallSteps()
            OperationType.REINSTALL -> reinstallSteps(scope)
            else -> error("Verified Phase 9 preflight carried unsupported action ${scope.action}")
        }
        return ReviewedExistingInstallationActionPlan(scope, steps)
    }

    fun isCanonical(plan: ReviewedExistingInstallationActionPlan): Boolean {
        val expected = when (plan.scope.action) {
            OperationType.RESTART -> restartSteps()
            OperationType.RECOVERY -> recoverySteps()
            OperationType.UNINSTALL -> uninstallSteps()
            OperationType.REINSTALL -> runCatching { reinstallSteps(plan.scope) }.getOrNull() ?: return false
            else -> return false
        }
        return plan.steps == expected
    }

    private fun restartSteps(): List<ExistingInstallationActionPlanStep> = listOf(
        ExistingInstallationActionPlanStep.RestartExactService(
            ExistingInstallationRemoteCapability.SYSTEMD_RESTART_EXACT_SERVICE_V1,
            RESTART_TIMEOUT,
        ),
        ExistingInstallationActionPlanStep.VerifyExactIdentity(VERIFY_TIMEOUT),
        ExistingInstallationActionPlanStep.VerifyServiceActive(VERIFY_TIMEOUT),
        ExistingInstallationActionPlanStep.VerifyExpectedListener(VERIFY_TIMEOUT),
    )

    private fun recoverySteps(): List<ExistingInstallationActionPlanStep> = listOf(
        ExistingInstallationActionPlanStep.ReadOnlyRecoveryDiagnosis(RECOVERY_DIAGNOSIS_TIMEOUT),
    )

    private fun uninstallSteps(): List<ExistingInstallationActionPlanStep> = listOf(
        ExistingInstallationActionPlanStep.ExecuteReviewedUninstall(
            ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_UNINSTALL_V1,
            UNINSTALL_TIMEOUT,
        ),
        ExistingInstallationActionPlanStep.VerifyInstallationAbsent(VERIFY_TIMEOUT),
    )

    private fun reinstallSteps(scope: ExistingInstallationActionScope): List<ExistingInstallationActionPlanStep> {
        require(scope.ownership == InstallationOwnership.MANAGED) {
            "Reviewed reinstall plan requires MANAGED ownership"
        }
        val managedInstallId = requireNotNull(scope.managedInstallId) {
            "Reviewed reinstall plan requires managedInstallId"
        }
        return listOf(
            ExistingInstallationActionPlanStep.ExecuteReviewedUninstall(
                ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_UNINSTALL_V1,
                UNINSTALL_TIMEOUT,
            ),
            ExistingInstallationActionPlanStep.ExecuteReviewedInstaller(
                ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_INSTALL_V1,
                INSTALL_TIMEOUT,
            ),
            ExistingInstallationActionPlanStep.WriteManagedMarker(managedInstallId, WRITE_MARKER_TIMEOUT),
            ExistingInstallationActionPlanStep.VerifyExactIdentity(VERIFY_TIMEOUT),
            ExistingInstallationActionPlanStep.VerifyServiceActive(VERIFY_TIMEOUT),
            ExistingInstallationActionPlanStep.VerifyExpectedListener(VERIFY_TIMEOUT),
            ExistingInstallationActionPlanStep.VerifyPanelSettings(VERIFY_TIMEOUT),
        )
    }
}

/** Classification helper used by tests/future executors to prove a plan contains no recovery mutation. */
object ExistingInstallationPlanInspectionPolicy {
    private val mutationKinds = setOf(
        ExistingInstallationActionPlanStepKind.RESTART_EXACT_SERVICE,
        ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_UNINSTALL,
        ExistingInstallationActionPlanStepKind.EXECUTE_REVIEWED_INSTALLER,
        ExistingInstallationActionPlanStepKind.WRITE_MANAGED_MARKER,
    )

    fun containsMutation(plan: ReviewedExistingInstallationActionPlan): Boolean =
        plan.steps.any { it.kind in mutationKinds }
}
