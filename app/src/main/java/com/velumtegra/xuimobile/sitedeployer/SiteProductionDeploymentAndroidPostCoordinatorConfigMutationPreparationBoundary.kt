package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import java.security.MessageDigest

/**
 * Phase 11.85 consumes the exact validated Phase 11.84 post-coordinator read-only preflight result
 * and locally delegates to the already accepted Phase 11.70 config-mutation preparation boundary.
 *
 * This boundary performs no network I/O and grants no write/reload/retry authority. It exists only
 * to preserve the Phase 11.83 -> 11.84 lineage when projecting the deterministic Phase 11.70 result.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        mutationTransactionId: String,
    ): SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)
        require(
            handoff.status == SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
        ) { "Phase 11.85 accepts only a READY Phase 11.83 handoff" }
        require(transactionId.matches(mutationTransactionId)) {
            "Phase 11.85 mutation transaction id must be canonical"
        }

        val expectedAdmission =
            SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(handoff)
        require(phase1184Execution.phase1184AdmissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.85 Phase 11.84 execution belongs to another admission"
        }
        require(phase1184Execution.phase1183HandoffSha256 == handoff.handoffSha256)
        require(phase1184Execution.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(phase1184Execution.servingPolicySelectionSha256 == handoff.servingPolicySelectionSha256)
        require(phase1184Execution.phase1169AdmissionSha256 == expectedAdmission.phase1169Admission.admissionSha256)
        require(!phase1184Execution.remoteMutationPerformed)
        require(!phase1184Execution.coordinatorReinvoked)
        require(!phase1184Execution.staticPublicationReplayPerformed)
        require(!phase1184Execution.automaticRetryPerformed)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1170 = SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.prepare(
            selection = selection,
            policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
            mutationTransactionId = mutationTransactionId,
        )

        return compose(
            handoff = handoff,
            phase1184AdmissionSha256 = expectedAdmission.admissionSha256,
            phase1184ExecutionResultSha256 = phase1184Execution.executionResultSha256,
            phase1169ExecutionResultSha256 = phase1184Execution.phase1169ExecutionResult.executionResultSha256,
            phase1170 = phase1170,
        ).also { validateAgainst(it, handoff, phase1184Execution) }
    }

    /** Zero-network deterministic seam for regression tests after upstream proof validation. */
    internal fun prepareValidated(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184ExecutionResultSha256: String,
        phase1169ExecutionResultSha256: String,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
        mutationTransactionId: String,
    ): SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        require(handoff.status == SiteProductionDeploymentPostCoordinatorServingHandoffStatus
            .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT)
        require(sha256.matches(phase1184ExecutionResultSha256))
        require(sha256.matches(phase1169ExecutionResultSha256))
        require(transactionId.matches(mutationTransactionId))
        val selection = requireNotNull(handoff.servingPolicySelection)
        val admission = SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(handoff)
        val phase1170 = SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
            .prepareValidated(
                selection = selection,
                admission = admission.phase1169Admission,
                readOnlyPreflight = readOnlyPreflight,
                policyBoundPreflightExecutionResultSha256 = phase1169ExecutionResultSha256,
                mutationTransactionId = mutationTransactionId,
            )
        return compose(
            handoff = handoff,
            phase1184AdmissionSha256 = admission.admissionSha256,
            phase1184ExecutionResultSha256 = phase1184ExecutionResultSha256,
            phase1169ExecutionResultSha256 = phase1169ExecutionResultSha256,
            phase1170 = phase1170,
        ).also(::validate)
    }

    fun validate(result: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        listOf(
            result.phase1183HandoffSha256,
            result.phase1184AdmissionSha256,
            result.phase1184ExecutionResultSha256,
            result.phase1180ExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.phase1169ExecutionResultSha256,
            result.publicationPlanSha256,
            result.preparationResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(transactionId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
            .validate(result.phase1170Preparation)
        require(result.phase1170Preparation.servingPolicySelectionSha256 == result.servingPolicySelectionSha256)
        require(result.phase1170Preparation.policyBoundPreflightExecutionResultSha256 == result.phase1169ExecutionResultSha256)
        require(result.phase1170Preparation.publicationPlanSha256 == result.publicationPlanSha256)
        require(result.phase1170Preparation.selectedProtocol == result.selectedProtocol)
        require(result.phase1170Preparation.readOnlyPreflightStatus == result.preflightStatus)
        require(result.phase1170Preparation.mutationTransactionId == result.mutationTransactionId)
        require(result.mutationPreparationCreated == result.phase1170Preparation.mutationPreparationCreated)
        require(!result.productionNetworkTouchedByPreparation)
        require(!result.remoteMutationPerformed)
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(!result.webServingMutationAuthorized)
        require(!result.automaticRetryAuthorized)
        when (result.status) {
            SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus
                .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION -> {
                require(result.phase1170Preparation.status ==
                    SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                        .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY)
                require(result.mutationPreparationCreated)
            }
            SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus
                .BLOCKED_BY_POST_COORDINATOR_READ_ONLY_PREFLIGHT -> {
                require(result.phase1170Preparation.status ==
                    SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                        .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT)
                require(!result.mutationPreparationCreated)
            }
        }
        require(result.preparationResultSha256 == resultSha256(result.copy(preparationResultSha256 = ""))) {
            "Phase 11.85 preparation-result SHA-256 mismatch"
        }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
    ) {
        validate(result)
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)
        val admission = SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(handoff)
        val selection = requireNotNull(handoff.servingPolicySelection)
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(result.phase1184AdmissionSha256 == admission.admissionSha256)
        require(result.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(result.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(result.phase1169ExecutionResultSha256 == phase1184Execution.phase1169ExecutionResult.executionResultSha256)
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.validateAgainst(
            result.phase1170Preparation,
            selection,
            phase1184Execution.phase1169ExecutionResult,
        )
    }

    private fun compose(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184AdmissionSha256: String,
        phase1184ExecutionResultSha256: String,
        phase1169ExecutionResultSha256: String,
        phase1170: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult {
        val status = when (phase1170.status) {
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY ->
                SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus
                    .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT ->
                SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus
                    .BLOCKED_BY_POST_COORDINATOR_READ_ONLY_PREFLIGHT
        }
        val base = SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status = status,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1184AdmissionSha256 = phase1184AdmissionSha256,
            phase1184ExecutionResultSha256 = phase1184ExecutionResultSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = requireNotNull(handoff.servingPolicySelectionSha256),
            phase1169ExecutionResultSha256 = phase1169ExecutionResultSha256,
            phase1170Preparation = phase1170,
            publicationPlanSha256 = phase1170.publicationPlanSha256,
            selectedProtocol = phase1170.selectedProtocol,
            preflightStatus = phase1170.readOnlyPreflightStatus,
            mutationTransactionId = phase1170.mutationTransactionId,
            mutationPreparationCreated = phase1170.mutationPreparationCreated,
            productionNetworkTouchedByPreparation = false,
            remoteMutationPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            webServingMutationAuthorized = false,
            automaticRetryAuthorized = false,
            preparationResultSha256 = "",
        )
        return base.copy(preparationResultSha256 = resultSha256(base))
    }

    private fun resultSha256(value: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult): String =
        digest(buildString {
            append("phase=11.85\n")
            append("contractVersion=").append(value.contractVersion).append('\n')
            append("status=").append(value.status.name).append('\n')
            append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
            append("phase1184Admission=").append(value.phase1184AdmissionSha256).append('\n')
            append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
            append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
            append("selection=").append(value.servingPolicySelectionSha256).append('\n')
            append("phase1169Execution=").append(value.phase1169ExecutionResultSha256).append('\n')
            append("phase1170Preparation=").append(value.phase1170Preparation.preparationResultSha256).append('\n')
            append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
            append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
            append("preflightStatus=").append(value.preflightStatus.name).append('\n')
            append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
            append("mutationPreparationCreated=").append(value.mutationPreparationCreated).append('\n')
            append("productionNetworkTouchedByPreparation=").append(value.productionNetworkTouchedByPreparation).append('\n')
            append("remoteMutationPerformed=").append(value.remoteMutationPerformed).append('\n')
            append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
            append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
            append("webServingMutationAuthorized=").append(value.webServingMutationAuthorized).append('\n')
            append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
        })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
