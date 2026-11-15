package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import java.security.MessageDigest

/**
 * Phase 11.88 is the zero-network post-coordinator gate immediately after the successful Phase
 * 11.87 staging/syntax execution proof and immediately before a later separate exact config
 * activation execution.
 *
 * It preserves the exact Phase 11.83-11.87 lineage and delegates only to the already accepted
 * Phase 11.73 authority-preparation boundary. No network I/O, remote mutation, production config
 * activation, nginx reload, coordinator/static-publication replay or automatic retry occurs here.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
    ): SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult {
        validateUpstreamChain(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            phase1187Execution = phase1187Execution,
        )

        val readOnlyPreflight =
            phase1184Execution.phase1169ExecutionResult.preflightExecutionProof.preflightReport
        return prepareValidated(
            handoff = handoff,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            phase1187ExecutionResultSha256 = phase1187Execution.executionResultSha256,
            phase1187AdmissionSha256 = phase1187Execution.phase1187AdmissionSha256,
            phase1172ExecutionResultSha256 =
                phase1187Execution.phase1172ExecutionResult.executionResultSha256,
            phase11_59ExecutionProofSha256 =
                phase1187Execution.phase1172ExecutionResult.phase11_59ExecutionProof
                    .executionProofSha256,
            readOnlyPreflight = readOnlyPreflight,
        ).also {
            validateAgainst(
                result = it,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
                phase1187Execution = phase1187Execution,
            )
        }
    }

    /**
     * Deterministic zero-network seam for regression tests after the Phase 11.87 execution proof
     * has already been validated by its owning boundary.
     */
    internal fun prepareValidated(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187ExecutionResultSha256: String,
        phase1187AdmissionSha256: String,
        phase1172ExecutionResultSha256: String,
        phase11_59ExecutionProofSha256: String,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ): SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
            .validate(phase1185Preparation)
        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
            .validate(phase1186AuthorityPreparation)
        listOf(
            phase1187ExecutionResultSha256,
            phase1187AdmissionSha256,
            phase1172ExecutionResultSha256,
            phase11_59ExecutionProofSha256,
        ).forEach { require(sha256.matches(it)) }

        require(phase1185Preparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(phase1186AuthorityPreparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(
            phase1186AuthorityPreparation.phase1185PreparationResultSha256 ==
                phase1185Preparation.preparationResultSha256,
        )
        require(
            phase1186AuthorityPreparation.phase1184ExecutionResultSha256 ==
                phase1185Preparation.phase1184ExecutionResultSha256,
        )
        require(
            phase1186AuthorityPreparation.phase1169ExecutionResultSha256 ==
                phase1185Preparation.phase1169ExecutionResultSha256,
        )
        require(
            phase1186AuthorityPreparation.phase1170PreparationResultSha256 ==
                phase1185Preparation.phase1170Preparation.preparationResultSha256,
        )
        require(
            phase1186AuthorityPreparation.status ==
                SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
        )
        require(!phase1186AuthorityPreparation.exactConfigActivationAuthorized)
        require(!phase1186AuthorityPreparation.webServerReloadAuthorized)
        require(!phase1186AuthorityPreparation.coordinatorReinvoked)
        require(!phase1186AuthorityPreparation.staticPublicationReplayPerformed)
        require(!phase1186AuthorityPreparation.automaticRetryAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1173 =
            SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                .prepareValidated(
                    selection = selection,
                    policyBoundPreflightExecutionResultSha256 =
                        phase1185Preparation.phase1169ExecutionResultSha256,
                    policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                    stagingSyntaxAuthorityPreparation =
                        phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                    policyBoundStagingSyntaxExecutionResultSha256 =
                        phase1172ExecutionResultSha256,
                    phase11_59ExecutionProofSha256 = phase11_59ExecutionProofSha256,
                    readOnlyPreflight = readOnlyPreflight,
                )

        val base = SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
            phase1187ExecutionResultSha256 = phase1187ExecutionResultSha256,
            phase1187AdmissionSha256 = phase1187AdmissionSha256,
            phase1186AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
            phase1185PreparationResultSha256 = phase1185Preparation.preparationResultSha256,
            phase1184ExecutionResultSha256 = phase1185Preparation.phase1184ExecutionResultSha256,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            phase1169ExecutionResultSha256 = phase1185Preparation.phase1169ExecutionResultSha256,
            phase1170PreparationResultSha256 =
                phase1185Preparation.phase1170Preparation.preparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.phase1171AuthorityPreparation
                    .authorityPreparationResultSha256,
            phase1172ExecutionResultSha256 = phase1172ExecutionResultSha256,
            phase1173AuthorityPreparation = phase1173,
            publicationPlanSha256 = phase1173.publicationPlanSha256,
            selectedProtocol = phase1173.selectedProtocol,
            mutationTransactionId = phase1173.mutationTransactionId,
            mutationPreparationSha256 = phase1173.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = phase1173.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = phase1173.activationExecutionPlan.activationPlanSha256,
            successfulPostCoordinatorStagingSyntaxExecutionProofValidated = true,
            activationExecutionPlanCreated = phase1173.activationExecutionPlanCreated,
            productionNetworkTouchedByAuthorityPreparation = false,
            remoteMutationPerformed = false,
            stagingConfigWriteAuthorized = phase1173.stagingConfigWriteAuthorized,
            exactConfigActivationAuthorized = phase1173.exactConfigActivationAuthorized,
            nginxSyntaxValidationAuthorized = phase1173.nginxSyntaxValidationAuthorized,
            webServerReloadAuthorized = phase1173.webServerReloadAuthorized,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            automaticRetryAuthorized = phase1173.automaticRetryAuthorized,
            authorityPreparationResultSha256 = "",
        )
        return base.copy(
            authorityPreparationResultSha256 = authorityPreparationResultSha256(base),
        ).also(::validate)
    }

    fun validate(
        result: SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
        )
        listOf(
            result.phase1187ExecutionResultSha256,
            result.phase1187AdmissionSha256,
            result.phase1186AuthorityPreparationResultSha256,
            result.phase1185PreparationResultSha256,
            result.phase1184ExecutionResultSha256,
            result.phase1183HandoffSha256,
            result.phase1180ExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.phase1169ExecutionResultSha256,
            result.phase1170PreparationResultSha256,
            result.phase1171AuthorityPreparationResultSha256,
            result.phase1172ExecutionResultSha256,
            result.publicationPlanSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.activationExecutionPlanSha256,
            result.authorityPreparationResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(transactionId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validate(result.phase1173AuthorityPreparation)
        val phase1173 = result.phase1173AuthorityPreparation
        require(
            phase1173.policyBoundStagingSyntaxExecutionResultSha256 ==
                result.phase1172ExecutionResultSha256,
        )
        require(
            phase1173.policyBoundStagingSyntaxAuthorityPreparationResultSha256 ==
                result.phase1171AuthorityPreparationResultSha256,
        )
        require(phase1173.servingPolicySelectionSha256 == result.servingPolicySelectionSha256)
        require(
            phase1173.policyBoundPreflightExecutionResultSha256 ==
                result.phase1169ExecutionResultSha256,
        )
        require(
            phase1173.policyBoundConfigMutationPreparationResultSha256 ==
                result.phase1170PreparationResultSha256,
        )
        require(phase1173.publicationPlanSha256 == result.publicationPlanSha256)
        require(phase1173.selectedProtocol == result.selectedProtocol)
        require(phase1173.mutationTransactionId == result.mutationTransactionId)
        require(phase1173.mutationPreparationSha256 == result.mutationPreparationSha256)
        require(
            phase1173.stagingSyntaxExecutionPlanSha256 ==
                result.stagingSyntaxExecutionPlanSha256,
        )
        require(phase1173.phase11_59ExecutionProofSha256 == result.phase11_59ExecutionProofSha256)
        require(
            phase1173.activationExecutionPlan.activationPlanSha256 ==
                result.activationExecutionPlanSha256,
        )
        require(result.successfulPostCoordinatorStagingSyntaxExecutionProofValidated)
        require(result.activationExecutionPlanCreated)
        require(!result.productionNetworkTouchedByAuthorityPreparation)
        require(!result.remoteMutationPerformed)
        require(result.stagingConfigWriteAuthorized)
        require(result.exactConfigActivationAuthorized)
        require(result.nginxSyntaxValidationAuthorized)
        require(!result.webServerReloadAuthorized)
        require(!result.coordinatorReinvocationAuthorized)
        require(!result.staticPublicationReplayAuthorized)
        require(!result.automaticRetryAuthorized)
        require(
            result.authorityPreparationResultSha256 ==
                authorityPreparationResultSha256(
                    result.copy(authorityPreparationResultSha256 = ""),
                ),
        ) { "Phase 11.88 config-activation authority-preparation SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
    ) {
        validate(result)
        validateUpstreamChain(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            phase1187Execution = phase1187Execution,
        )
        require(result.phase1187ExecutionResultSha256 == phase1187Execution.executionResultSha256)
        require(result.phase1187AdmissionSha256 == phase1187Execution.phase1187AdmissionSha256)
        require(
            result.phase1186AuthorityPreparationResultSha256 ==
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
        )
        require(result.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(result.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(result.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(
            result.phase1172ExecutionResultSha256 ==
                phase1187Execution.phase1172ExecutionResult.executionResultSha256,
        )
        require(
            result.phase11_59ExecutionProofSha256 ==
                phase1187Execution.phase1172ExecutionResult.phase11_59ExecutionProof
                    .executionProofSha256,
        )
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validateAgainst(
                result = result.phase1173AuthorityPreparation,
                selection = requireNotNull(handoff.servingPolicySelection),
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                stagingSyntaxAuthorityPreparation =
                    phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                stagingSyntaxExecution = phase1187Execution.phase1172ExecutionResult,
            )
    }

    private fun validateUpstreamChain(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
    ) {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)
        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary.validateAgainst(
            result = phase1185Preparation,
            handoff = handoff,
            phase1184Execution = phase1184Execution,
        )
        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
            .validateAgainst(
                result = phase1186AuthorityPreparation,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
            )
        val phase1187Admission =
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                .admit(phase1186AuthorityPreparation)
        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1187Execution,
                admission = phase1187Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            )
        require(phase1187Execution.exactPostCoordinatorChainBindingVerified)
        require(phase1187Execution.nginxSyntaxValidationPassed)
        require(phase1187Execution.operationOwnedCleanupVerified)
        require(!phase1187Execution.exactConfigActivationPerformed)
        require(!phase1187Execution.webServerReloadPerformed)
        require(!phase1187Execution.coordinatorReinvoked)
        require(!phase1187Execution.staticPublicationReplayPerformed)
        require(!phase1187Execution.automaticRetryPerformed)
    }

    private fun authorityPreparationResultSha256(
        value: SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
    ): String = digest(buildString {
        append("phase=11.88\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1187Execution=").append(value.phase1187ExecutionResultSha256).append('\n')
        append("phase1187Admission=").append(value.phase1187AdmissionSha256).append('\n')
        append("phase1186AuthorityPreparation=").append(value.phase1186AuthorityPreparationResultSha256).append('\n')
        append("phase1185Preparation=").append(value.phase1185PreparationResultSha256).append('\n')
        append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Execution=").append(value.phase1169ExecutionResultSha256).append('\n')
        append("phase1170Preparation=").append(value.phase1170PreparationResultSha256).append('\n')
        append("phase1171AuthorityPreparation=").append(value.phase1171AuthorityPreparationResultSha256).append('\n')
        append("phase1172Execution=").append(value.phase1172ExecutionResultSha256).append('\n')
        append("phase1173AuthorityPreparation=").append(
            value.phase1173AuthorityPreparation.authorityPreparationResultSha256,
        ).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(value.phase11_59ExecutionProofSha256).append('\n')
        append("activationExecutionPlan=").append(value.activationExecutionPlanSha256).append('\n')
        append("successfulPostCoordinatorStagingSyntaxExecutionProofValidated=")
            .append(value.successfulPostCoordinatorStagingSyntaxExecutionProofValidated).append('\n')
        append("activationExecutionPlanCreated=").append(value.activationExecutionPlanCreated).append('\n')
        append("productionNetworkTouchedByAuthorityPreparation=")
            .append(value.productionNetworkTouchedByAuthorityPreparation).append('\n')
        append("remoteMutationPerformed=").append(value.remoteMutationPerformed).append('\n')
        append("stagingConfigWriteAuthorized=").append(value.stagingConfigWriteAuthorized).append('\n')
        append("exactConfigActivationAuthorized=").append(value.exactConfigActivationAuthorized).append('\n')
        append("nginxSyntaxValidationAuthorized=").append(value.nginxSyntaxValidationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(value.webServerReloadAuthorized).append('\n')
        append("coordinatorReinvocationAuthorized=").append(value.coordinatorReinvocationAuthorized).append('\n')
        append("staticPublicationReplayAuthorized=").append(value.staticPublicationReplayAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
