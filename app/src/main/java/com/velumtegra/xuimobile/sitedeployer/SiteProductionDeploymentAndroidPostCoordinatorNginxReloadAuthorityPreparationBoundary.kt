package com.velumtegra.xuimobile.sitedeployer

import java.security.MessageDigest

/**
 * Phase 11.90 is the zero-network post-coordinator gate immediately after the successful Phase
 * 11.89 exact-config activation proof and immediately before a later separate nginx reload.
 *
 * It preserves the exact Phase 11.83-11.89 lineage and delegates only to the already accepted
 * Phase 11.75 reload-authority preparation boundary. No network I/O, remote mutation, nginx
 * reload/restart, coordinator/static-publication replay or automatic retry occurs here.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary {
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
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        phase1189Execution: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
    ): SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult {
        val phase1189Admission =
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                .admit(phase1188AuthorityPreparation)
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1189Execution,
                admission = phase1189Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188AuthorityPreparation,
            )
        require(phase1189Execution.exactConfigActivationPerformed)
        require(phase1189Execution.exactConfigSha256Verified)
        require(phase1189Execution.nginxSyntaxValidationPassed)
        require(phase1189Execution.exactConfigPathPresentAfterActivation)
        require(phase1189Execution.stagingConfigAbsentAfterActivation)
        require(phase1189Execution.listenerStillFreeAfterActivation)
        require(!phase1189Execution.rollbackToAbsentPerformed)
        require(!phase1189Execution.webServerReloadPerformed)
        require(!phase1189Execution.coordinatorReinvoked)
        require(!phase1189Execution.staticPublicationReplayPerformed)
        require(!phase1189Execution.automaticRetryPerformed)

        return prepareValidated(
            handoff = handoff,
            phase1188AuthorityPreparation = phase1188AuthorityPreparation,
            phase1189ExecutionResultSha256 = phase1189Execution.executionResultSha256,
            phase1189AdmissionSha256 = phase1189Execution.phase1189AdmissionSha256,
            phase1174ExecutionResultSha256 =
                phase1189Execution.phase1174ExecutionResult.executionResultSha256,
            phase11_60ExecutionProofSha256 =
                phase1189Execution.phase1174ExecutionResult.phase11_60ExecutionProof
                    .executionProofSha256,
        ).also {
            validateAgainst(
                result = it,
                handoff = handoff,
                phase1188AuthorityPreparation = phase1188AuthorityPreparation,
                phase1189Execution = phase1189Execution,
            )
        }
    }

    /** Deterministic zero-network seam after the Phase 11.89 proof was validated by its owner. */
    internal fun prepareValidated(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        phase1189ExecutionResultSha256: String,
        phase1189AdmissionSha256: String,
        phase1174ExecutionResultSha256: String,
        phase11_60ExecutionProofSha256: String,
    ): SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
            .validate(phase1188AuthorityPreparation)
        listOf(
            phase1189ExecutionResultSha256,
            phase1189AdmissionSha256,
            phase1174ExecutionResultSha256,
            phase11_60ExecutionProofSha256,
        ).forEach { require(sha256.matches(it)) }

        require(phase1188AuthorityPreparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(
            phase1188AuthorityPreparation.status ==
                SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
        )
        require(phase1188AuthorityPreparation.exactConfigActivationAuthorized)
        require(!phase1188AuthorityPreparation.webServerReloadAuthorized)
        require(!phase1188AuthorityPreparation.coordinatorReinvocationAuthorized)
        require(!phase1188AuthorityPreparation.staticPublicationReplayAuthorized)
        require(!phase1188AuthorityPreparation.automaticRetryAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        require(selection.selectionSha256 == phase1188AuthorityPreparation.servingPolicySelectionSha256)
        val phase1175 =
            SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
                .prepareValidated(
                    selection = selection,
                    activationAuthorityPreparation =
                        phase1188AuthorityPreparation.phase1173AuthorityPreparation,
                    policyBoundConfigActivationExecutionResultSha256 =
                        phase1174ExecutionResultSha256,
                    phase11_60ExecutionProofSha256 = phase11_60ExecutionProofSha256,
                )

        val base = SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
            phase1189ExecutionResultSha256 = phase1189ExecutionResultSha256,
            phase1189AdmissionSha256 = phase1189AdmissionSha256,
            phase1188AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.authorityPreparationResultSha256,
            phase1187ExecutionResultSha256 =
                phase1188AuthorityPreparation.phase1187ExecutionResultSha256,
            phase1186AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.phase1186AuthorityPreparationResultSha256,
            phase1185PreparationResultSha256 =
                phase1188AuthorityPreparation.phase1185PreparationResultSha256,
            phase1184ExecutionResultSha256 =
                phase1188AuthorityPreparation.phase1184ExecutionResultSha256,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            phase1169ExecutionResultSha256 =
                phase1188AuthorityPreparation.phase1169ExecutionResultSha256,
            phase1170PreparationResultSha256 =
                phase1188AuthorityPreparation.phase1170PreparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.phase1171AuthorityPreparationResultSha256,
            phase1172ExecutionResultSha256 =
                phase1188AuthorityPreparation.phase1172ExecutionResultSha256,
            phase1173AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.phase1173AuthorityPreparation
                    .authorityPreparationResultSha256,
            phase1174ExecutionResultSha256 = phase1174ExecutionResultSha256,
            phase1175AuthorityPreparation = phase1175,
            phase1175AuthorityPreparationResultSha256 =
                phase1175.authorityPreparationResultSha256,
            publicationPlanSha256 = phase1175.publicationPlanSha256,
            selectedProtocol = phase1175.selectedProtocol,
            mutationTransactionId = phase1175.mutationTransactionId,
            mutationPreparationSha256 = phase1175.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = phase1175.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = phase1175.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = phase1175.activationExecutionPlanSha256,
            phase11_60ExecutionProofSha256 = phase11_60ExecutionProofSha256,
            nginxReloadExecutionPlan = phase1175.nginxReloadExecutionPlan,
            successfulPostCoordinatorConfigActivationExecutionProofValidated = true,
            nginxReloadExecutionPlanCreated = phase1175.nginxReloadExecutionPlanCreated,
            productionNetworkTouchedByAuthorityPreparation = false,
            remoteMutationPerformed = false,
            exactConfigActivationPerformedByAuthorityPreparation = false,
            nginxReloadExecutionAuthorized = phase1175.nginxReloadExecutionAuthorized,
            nginxReloadPerformed = false,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            automaticRetryAuthorized = phase1175.automaticRetryAuthorized,
            authorityPreparationResultSha256 = "",
        )
        return base.copy(
            authorityPreparationResultSha256 = authorityPreparationResultSha256(base),
        ).also(::validate)
    }

    fun validate(
        result: SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
        )
        listOf(
            result.phase1189ExecutionResultSha256,
            result.phase1189AdmissionSha256,
            result.phase1188AuthorityPreparationResultSha256,
            result.phase1187ExecutionResultSha256,
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
            result.phase1173AuthorityPreparationResultSha256,
            result.phase1174ExecutionResultSha256,
            result.phase1175AuthorityPreparationResultSha256,
            result.publicationPlanSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.activationExecutionPlanSha256,
            result.phase11_60ExecutionProofSha256,
            result.nginxReloadExecutionPlan.reloadPlanSha256,
            result.authorityPreparationResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(transactionId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
            .validate(result.phase1175AuthorityPreparation)
        require(
            result.phase1175AuthorityPreparation.authorityPreparationResultSha256 ==
                result.phase1175AuthorityPreparationResultSha256,
        )
        require(
            result.phase1175AuthorityPreparation.policyBoundConfigActivationExecutionResultSha256 ==
                result.phase1174ExecutionResultSha256,
        )
        require(
            result.phase1175AuthorityPreparation
                .policyBoundConfigActivationAuthorityPreparationResultSha256 ==
                result.phase1173AuthorityPreparationResultSha256,
        )
        require(
            result.phase1175AuthorityPreparation.servingPolicySelectionSha256 ==
                result.servingPolicySelectionSha256,
        )
        require(
            result.phase1175AuthorityPreparation.publicationPlanSha256 ==
                result.publicationPlanSha256,
        )
        require(
            result.phase1175AuthorityPreparation.phase11_60ExecutionProofSha256 ==
                result.phase11_60ExecutionProofSha256,
        )
        require(
            result.phase1175AuthorityPreparation.nginxReloadExecutionPlan.reloadPlanSha256 ==
                result.nginxReloadExecutionPlan.reloadPlanSha256,
        )
        require(result.successfulPostCoordinatorConfigActivationExecutionProofValidated)
        require(result.nginxReloadExecutionPlanCreated)
        require(!result.productionNetworkTouchedByAuthorityPreparation)
        require(!result.remoteMutationPerformed)
        require(!result.exactConfigActivationPerformedByAuthorityPreparation)
        require(result.nginxReloadExecutionAuthorized)
        require(!result.nginxReloadPerformed)
        require(!result.coordinatorReinvocationAuthorized)
        require(!result.staticPublicationReplayAuthorized)
        require(!result.automaticRetryAuthorized)
        require(result.nginxReloadExecutionPlan.reloadNginxOnceAuthorized)
        require(!result.nginxReloadExecutionPlan.configMutationAuthorized)
        require(!result.nginxReloadExecutionPlan.dnsMutationAuthorized)
        require(!result.nginxReloadExecutionPlan.firewallMutationAuthorized)
        require(!result.nginxReloadExecutionPlan.packageInstallAuthorized)
        require(!result.nginxReloadExecutionPlan.automaticRetryAuthorized)
        require(
            result.authorityPreparationResultSha256 ==
                authorityPreparationResultSha256(
                    result.copy(authorityPreparationResultSha256 = ""),
                ),
        ) { "Phase 11.90 nginx-reload authority preparation SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        phase1189Execution: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
    ) {
        validate(result)
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
            .validate(phase1188AuthorityPreparation)
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
            .validateExecutionResult(phase1189Execution)
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(
            result.phase1188AuthorityPreparationResultSha256 ==
                phase1188AuthorityPreparation.authorityPreparationResultSha256,
        )
        require(result.phase1189ExecutionResultSha256 == phase1189Execution.executionResultSha256)
        require(result.phase1189AdmissionSha256 == phase1189Execution.phase1189AdmissionSha256)
        require(
            result.phase1174ExecutionResultSha256 ==
                phase1189Execution.phase1174ExecutionResult.executionResultSha256,
        )
        require(
            result.phase11_60ExecutionProofSha256 ==
                phase1189Execution.phase1174ExecutionResult.phase11_60ExecutionProof
                    .executionProofSha256,
        )
        require(
            phase1189Execution.phase1188AuthorityPreparationResultSha256 ==
                phase1188AuthorityPreparation.authorityPreparationResultSha256,
        )
        require(phase1189Execution.phase1183HandoffSha256 == handoff.handoffSha256)
    }

    private fun authorityPreparationResultSha256(
        value: SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
    ): String = digest(buildString {
        append("phase=11.90\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1189Execution=").append(value.phase1189ExecutionResultSha256).append('\n')
        append("phase1189Admission=").append(value.phase1189AdmissionSha256).append('\n')
        append("phase1188AuthorityPreparation=").append(value.phase1188AuthorityPreparationResultSha256).append('\n')
        append("phase1187Execution=").append(value.phase1187ExecutionResultSha256).append('\n')
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
        append("phase1173AuthorityPreparation=").append(value.phase1173AuthorityPreparationResultSha256).append('\n')
        append("phase1174Execution=").append(value.phase1174ExecutionResultSha256).append('\n')
        append("phase1175AuthorityPreparation=").append(value.phase1175AuthorityPreparationResultSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(value.phase11_59ExecutionProofSha256).append('\n')
        append("activationExecutionPlan=").append(value.activationExecutionPlanSha256).append('\n')
        append("phase11_60Proof=").append(value.phase11_60ExecutionProofSha256).append('\n')
        append("nginxReloadPlan=").append(value.nginxReloadExecutionPlan.reloadPlanSha256).append('\n')
        append("successfulPostCoordinatorConfigActivationExecutionProofValidated=").append(value.successfulPostCoordinatorConfigActivationExecutionProofValidated).append('\n')
        append("nginxReloadExecutionPlanCreated=").append(value.nginxReloadExecutionPlanCreated).append('\n')
        append("productionNetworkTouchedByAuthorityPreparation=").append(value.productionNetworkTouchedByAuthorityPreparation).append('\n')
        append("remoteMutationPerformed=").append(value.remoteMutationPerformed).append('\n')
        append("exactConfigActivationPerformedByAuthorityPreparation=").append(value.exactConfigActivationPerformedByAuthorityPreparation).append('\n')
        append("nginxReloadExecutionAuthorized=").append(value.nginxReloadExecutionAuthorized).append('\n')
        append("nginxReloadPerformed=").append(value.nginxReloadPerformed).append('\n')
        append("coordinatorReinvocationAuthorized=").append(value.coordinatorReinvocationAuthorized).append('\n')
        append("staticPublicationReplayAuthorized=").append(value.staticPublicationReplayAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun digest(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.encodeToByteArray())
            .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
