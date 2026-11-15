package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import java.security.MessageDigest

/**
 * Phase 11.86 preserves the post-coordinator lineage while locally delegating the exact validated
 * Phase 11.85 result to the already accepted Phase 11.71 staging/syntax authority preparation.
 *
 * This boundary performs no network I/O and no remote mutation. READY may only carry the exact
 * existing bounded Phase 11.59 staging/syntax execution plan. Production config activation,
 * nginx reload, coordinator/static replay and automatic retry remain forbidden.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)
        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary.validateAgainst(
            result = phase1185Preparation,
            handoff = handoff,
            phase1184Execution = phase1184Execution,
        )
        require(phase1185Preparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(phase1185Preparation.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(!phase1185Preparation.productionNetworkTouchedByPreparation)
        require(!phase1185Preparation.remoteMutationPerformed)
        require(!phase1185Preparation.coordinatorReinvoked)
        require(!phase1185Preparation.staticPublicationReplayPerformed)
        require(!phase1185Preparation.automaticRetryAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val readOnlyPreflight =
            phase1184Execution.phase1169ExecutionResult.preflightExecutionProof.preflightReport
        val phase1171 =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                .prepareValidated(
                    selection = selection,
                    policyBoundPreflightExecutionResultSha256 =
                        phase1185Preparation.phase1169ExecutionResultSha256,
                    policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                    readOnlyPreflight = readOnlyPreflight,
                )

        return compose(
            handoff = handoff,
            phase1185Preparation = phase1185Preparation,
            phase1171 = phase1171,
        ).also {
            validateAgainst(
                result = it,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
            )
        }
    }

    /** Zero-network deterministic seam for regression tests after upstream proof validation. */
    internal fun prepareValidated(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ): SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
            .validate(phase1185Preparation)
        require(phase1185Preparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(phase1185Preparation.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(phase1185Preparation.servingPolicySelectionSha256 == handoff.servingPolicySelectionSha256)
        require(!phase1185Preparation.productionNetworkTouchedByPreparation)
        require(!phase1185Preparation.remoteMutationPerformed)
        require(!phase1185Preparation.coordinatorReinvoked)
        require(!phase1185Preparation.staticPublicationReplayPerformed)
        require(!phase1185Preparation.automaticRetryAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1171 =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                .prepareValidated(
                    selection = selection,
                    policyBoundPreflightExecutionResultSha256 =
                        phase1185Preparation.phase1169ExecutionResultSha256,
                    policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                    readOnlyPreflight = readOnlyPreflight,
                )

        return compose(
            handoff = handoff,
            phase1185Preparation = phase1185Preparation,
            phase1171 = phase1171,
        ).also(::validate)
    }

    fun validate(result: SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        listOf(
            result.phase1183HandoffSha256,
            result.phase1184AdmissionSha256,
            result.phase1184ExecutionResultSha256,
            result.phase1185PreparationResultSha256,
            result.phase1180ExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.phase1169ExecutionResultSha256,
            result.phase1170PreparationResultSha256,
            result.publicationPlanSha256,
            result.authorityPreparationResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(transactionId.matches(result.mutationTransactionId))
        result.mutationPreparationSha256?.let { require(sha256.matches(it)) }
        result.stagingSyntaxExecutionPlanSha256?.let { require(sha256.matches(it)) }

        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
            .validate(result.phase1171AuthorityPreparation)
        val phase1171 = result.phase1171AuthorityPreparation
        require(phase1171.servingPolicySelectionSha256 == result.servingPolicySelectionSha256)
        require(phase1171.policyBoundPreflightExecutionResultSha256 == result.phase1169ExecutionResultSha256)
        require(phase1171.policyBoundConfigMutationPreparationResultSha256 == result.phase1170PreparationResultSha256)
        require(phase1171.publicationPlanSha256 == result.publicationPlanSha256)
        require(phase1171.selectedProtocol == result.selectedProtocol)
        require(phase1171.readOnlyPreflightStatus == result.preflightStatus)
        require(phase1171.mutationTransactionId == result.mutationTransactionId)
        require(phase1171.mutationPreparationSha256 == result.mutationPreparationSha256)
        require(phase1171.stagingSyntaxExecutionPlan?.executionPlanSha256 == result.stagingSyntaxExecutionPlanSha256)
        require(phase1171.stagingSyntaxExecutionPlanCreated == result.stagingSyntaxExecutionPlanCreated)
        require(phase1171.stagingConfigWriteAuthorized == result.stagingConfigWriteAuthorized)
        require(phase1171.validationConfigWriteAuthorized == result.validationConfigWriteAuthorized)
        require(phase1171.isolatedNginxSyntaxValidationAuthorized == result.isolatedNginxSyntaxValidationAuthorized)
        require(!result.productionNetworkTouchedByAuthorityPreparation)
        require(!result.remoteMutationPerformed)
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(!result.exactConfigActivationAuthorized)
        require(!result.webServerReloadAuthorized)
        require(!result.automaticRetryAuthorized)

        when (result.status) {
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION -> {
                require(
                    phase1171.status ==
                        SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                            .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                )
                require(result.stagingSyntaxExecutionPlanCreated)
                require(result.stagingSyntaxExecutionPlanSha256 != null)
                require(result.mutationPreparationSha256 != null)
                require(result.stagingConfigWriteAuthorized)
                require(result.validationConfigWriteAuthorized)
                require(result.isolatedNginxSyntaxValidationAuthorized)
            }

            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                .BLOCKED_BY_POST_COORDINATOR_CONFIG_MUTATION_PREPARATION -> {
                require(
                    phase1171.status ==
                        SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                            .BLOCKED_BY_POLICY_BOUND_CONFIG_MUTATION_PREPARATION,
                )
                require(!result.stagingSyntaxExecutionPlanCreated)
                require(result.stagingSyntaxExecutionPlanSha256 == null)
                require(result.mutationPreparationSha256 == null)
                require(!result.stagingConfigWriteAuthorized)
                require(!result.validationConfigWriteAuthorized)
                require(!result.isolatedNginxSyntaxValidationAuthorized)
            }
        }

        require(
            result.authorityPreparationResultSha256 ==
                resultSha256(result.copy(authorityPreparationResultSha256 = "")),
        ) { "Phase 11.86 authority-preparation SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
    ) {
        validate(result)
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)
        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary.validateAgainst(
            phase1185Preparation,
            handoff,
            phase1184Execution,
        )
        val selection = requireNotNull(handoff.servingPolicySelection)
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(result.phase1184AdmissionSha256 == phase1185Preparation.phase1184AdmissionSha256)
        require(result.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(result.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(result.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(result.phase1169ExecutionResultSha256 == phase1184Execution.phase1169ExecutionResult.executionResultSha256)
        require(result.phase1170PreparationResultSha256 == phase1185Preparation.phase1170Preparation.preparationResultSha256)
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary.validateAgainst(
            result = result.phase1171AuthorityPreparation,
            selection = selection,
            policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
            policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
        )
    }

    private fun compose(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1171: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult {
        val status = when (phase1171.status) {
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION ->
                SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                .BLOCKED_BY_POLICY_BOUND_CONFIG_MUTATION_PREPARATION ->
                SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                    .BLOCKED_BY_POST_COORDINATOR_CONFIG_MUTATION_PREPARATION
        }
        val base = SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status = status,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1184AdmissionSha256 = phase1185Preparation.phase1184AdmissionSha256,
            phase1184ExecutionResultSha256 = phase1185Preparation.phase1184ExecutionResultSha256,
            phase1185PreparationResultSha256 = phase1185Preparation.preparationResultSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = phase1185Preparation.servingPolicySelectionSha256,
            phase1169ExecutionResultSha256 = phase1185Preparation.phase1169ExecutionResultSha256,
            phase1170PreparationResultSha256 = phase1185Preparation.phase1170Preparation.preparationResultSha256,
            phase1171AuthorityPreparation = phase1171,
            publicationPlanSha256 = phase1171.publicationPlanSha256,
            selectedProtocol = phase1171.selectedProtocol,
            preflightStatus = phase1171.readOnlyPreflightStatus,
            mutationTransactionId = phase1171.mutationTransactionId,
            mutationPreparationSha256 = phase1171.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = phase1171.stagingSyntaxExecutionPlan?.executionPlanSha256,
            stagingSyntaxExecutionPlanCreated = phase1171.stagingSyntaxExecutionPlanCreated,
            productionNetworkTouchedByAuthorityPreparation = false,
            remoteMutationPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            stagingConfigWriteAuthorized = phase1171.stagingConfigWriteAuthorized,
            validationConfigWriteAuthorized = phase1171.validationConfigWriteAuthorized,
            isolatedNginxSyntaxValidationAuthorized = phase1171.isolatedNginxSyntaxValidationAuthorized,
            exactConfigActivationAuthorized = false,
            webServerReloadAuthorized = false,
            automaticRetryAuthorized = false,
            authorityPreparationResultSha256 = "",
        )
        return base.copy(authorityPreparationResultSha256 = resultSha256(base))
    }

    private fun resultSha256(
        value: SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
    ): String = digest(buildString {
        append("phase=11.86\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1184Admission=").append(value.phase1184AdmissionSha256).append('\n')
        append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
        append("phase1185Preparation=").append(value.phase1185PreparationResultSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Execution=").append(value.phase1169ExecutionResultSha256).append('\n')
        append("phase1170Preparation=").append(value.phase1170PreparationResultSha256).append('\n')
        append("phase1171AuthorityPreparation=")
            .append(value.phase1171AuthorityPreparation.authorityPreparationResultSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("preflightStatus=").append(value.preflightStatus.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256 ?: "").append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256 ?: "").append('\n')
        append("stagingSyntaxExecutionPlanCreated=").append(value.stagingSyntaxExecutionPlanCreated).append('\n')
        append("productionNetworkTouchedByAuthorityPreparation=")
            .append(value.productionNetworkTouchedByAuthorityPreparation).append('\n')
        append("remoteMutationPerformed=").append(value.remoteMutationPerformed).append('\n')
        append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
        append("stagingConfigWriteAuthorized=").append(value.stagingConfigWriteAuthorized).append('\n')
        append("validationConfigWriteAuthorized=").append(value.validationConfigWriteAuthorized).append('\n')
        append("isolatedNginxSyntaxValidationAuthorized=")
            .append(value.isolatedNginxSyntaxValidationAuthorized).append('\n')
        append("exactConfigActivationAuthorized=").append(value.exactConfigActivationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(value.webServerReloadAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
