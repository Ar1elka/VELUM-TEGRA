package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort
import java.security.MessageDigest

/**
 * Phase 11.91 consumes the exact READY Phase 11.90 post-coordinator nginx-reload authority and
 * delegates exactly once to the already accepted Phase 11.76/11.61 nginx-reload executor.
 *
 * This boundary authorizes only one nginx reload with exact-config and listener verification.
 * Config/certificate/DNS/firewall/package mutation, coordinator/static-publication replay and
 * automatic retry remain forbidden.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        authorityPreparation: SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission {
        SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
            .validate(authorityPreparation)
        val phase1176Admission =
            SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
                .admit(authorityPreparation.phase1175AuthorityPreparation)
        val base = SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmissionStatus
                .READY_FOR_FRESH_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
            phase1190AuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            phase1189ExecutionResultSha256 = authorityPreparation.phase1189ExecutionResultSha256,
            phase1189AdmissionSha256 = authorityPreparation.phase1189AdmissionSha256,
            phase1188AuthorityPreparationResultSha256 =
                authorityPreparation.phase1188AuthorityPreparationResultSha256,
            phase1187ExecutionResultSha256 = authorityPreparation.phase1187ExecutionResultSha256,
            phase1186AuthorityPreparationResultSha256 =
                authorityPreparation.phase1186AuthorityPreparationResultSha256,
            phase1185PreparationResultSha256 = authorityPreparation.phase1185PreparationResultSha256,
            phase1184ExecutionResultSha256 = authorityPreparation.phase1184ExecutionResultSha256,
            phase1183HandoffSha256 = authorityPreparation.phase1183HandoffSha256,
            phase1180ExecutionResultSha256 = authorityPreparation.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = authorityPreparation.servingPolicySelectionSha256,
            phase1169ExecutionResultSha256 = authorityPreparation.phase1169ExecutionResultSha256,
            phase1170PreparationResultSha256 = authorityPreparation.phase1170PreparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                authorityPreparation.phase1171AuthorityPreparationResultSha256,
            phase1172ExecutionResultSha256 = authorityPreparation.phase1172ExecutionResultSha256,
            phase1173AuthorityPreparationResultSha256 =
                authorityPreparation.phase1173AuthorityPreparationResultSha256,
            phase1174ExecutionResultSha256 = authorityPreparation.phase1174ExecutionResultSha256,
            phase1175AuthorityPreparationResultSha256 =
                authorityPreparation.phase1175AuthorityPreparationResultSha256,
            phase1176Admission = phase1176Admission,
            publicationPlanSha256 = authorityPreparation.publicationPlanSha256,
            selectedProtocol = authorityPreparation.selectedProtocol,
            mutationTransactionId = authorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = authorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = authorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = authorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = authorityPreparation.activationExecutionPlanSha256,
            phase11_60ExecutionProofSha256 = authorityPreparation.phase11_60ExecutionProofSha256,
            nginxReloadExecutionPlanSha256 =
                authorityPreparation.nginxReloadExecutionPlan.reloadPlanSha256,
            requiresFreshCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            realVpsExecutionEligible = true,
            nginxReloadAuthorized = true,
            configMutationAuthorized = false,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            automaticRetryAuthorized = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        phase1189Execution: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
        phase1190AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort,
    ): SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.91 execution attempt id must be canonical"
        }
        validateAdmission(admission)
        validateChain(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            phase1187Execution = phase1187Execution,
            phase1188AuthorityPreparation = phase1188AuthorityPreparation,
            phase1189Execution = phase1189Execution,
            phase1190AuthorityPreparation = phase1190AuthorityPreparation,
        )
        val expectedAdmission = admit(phase1190AuthorityPreparation)
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.91 admission does not match the exact Phase 11.90 authority"
        }
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.nginxReloadAuthorized)
        require(!admission.configMutationAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1176Execution =
            SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary.executeOnce(
                admission = admission.phase1176Admission,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                stagingSyntaxAuthorityPreparation = phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                stagingSyntaxExecution = phase1187Execution.phase1172ExecutionResult,
                activationAuthorityPreparation = phase1188AuthorityPreparation.phase1173AuthorityPreparation,
                activationExecution = phase1189Execution.phase1174ExecutionResult,
                reloadAuthorityPreparation = phase1190AuthorityPreparation.phase1175AuthorityPreparation,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
                executionUsePort = executionUsePort,
            )
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1176Execution,
                admission = admission.phase1176Admission,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                stagingSyntaxAuthorityPreparation = phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                stagingSyntaxExecution = phase1187Execution.phase1172ExecutionResult,
                activationAuthorityPreparation = phase1188AuthorityPreparation.phase1173AuthorityPreparation,
                activationExecution = phase1189Execution.phase1174ExecutionResult,
                reloadAuthorityPreparation = phase1190AuthorityPreparation.phase1175AuthorityPreparation,
            )

        val base = SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPostCoordinatorNginxReloadExecutionStatus
                .NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE_WITHOUT_COORDINATOR_REPLAY,
            phase1191AdmissionSha256 = admission.admissionSha256,
            phase1190AuthorityPreparationResultSha256 =
                phase1190AuthorityPreparation.authorityPreparationResultSha256,
            phase1189ExecutionResultSha256 = phase1189Execution.executionResultSha256,
            phase1189AdmissionSha256 = phase1189Execution.phase1189AdmissionSha256,
            phase1188AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.authorityPreparationResultSha256,
            phase1187ExecutionResultSha256 = phase1187Execution.executionResultSha256,
            phase1186AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
            phase1185PreparationResultSha256 = phase1185Preparation.preparationResultSha256,
            phase1184ExecutionResultSha256 = phase1184Execution.executionResultSha256,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            phase1169ExecutionResultSha256 = phase1184Execution.phase1169ExecutionResult.executionResultSha256,
            phase1170PreparationResultSha256 = phase1185Preparation.phase1170Preparation.preparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.phase1171AuthorityPreparation.authorityPreparationResultSha256,
            phase1172ExecutionResultSha256 = phase1187Execution.phase1172ExecutionResult.executionResultSha256,
            phase1173AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.phase1173AuthorityPreparation.authorityPreparationResultSha256,
            phase1174ExecutionResultSha256 = phase1189Execution.phase1174ExecutionResult.executionResultSha256,
            phase1175AuthorityPreparationResultSha256 =
                phase1190AuthorityPreparation.phase1175AuthorityPreparation.authorityPreparationResultSha256,
            phase1176ExecutionResult = phase1176Execution,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            publicationPlanSha256 = phase1190AuthorityPreparation.publicationPlanSha256,
            selectedProtocol = phase1190AuthorityPreparation.selectedProtocol,
            mutationTransactionId = phase1190AuthorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = phase1190AuthorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = phase1190AuthorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = phase1190AuthorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = phase1190AuthorityPreparation.activationExecutionPlanSha256,
            phase11_60ExecutionProofSha256 = phase1190AuthorityPreparation.phase11_60ExecutionProofSha256,
            nginxReloadExecutionPlanSha256 =
                phase1190AuthorityPreparation.nginxReloadExecutionPlan.reloadPlanSha256,
            exactPostCoordinatorChainBindingVerified = true,
            successfulPostCoordinatorConfigActivationExecutionProofValidated =
                phase1176Execution.successfulConfigActivationExecutionProofValidated,
            durablePreReloadCheckpointRecorded = phase1176Execution.durablePreReloadCheckpointRecorded,
            credentialLeaseMaterialConsumed = phase1176Execution.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1176Execution.productionNetworkTouched,
            liveHostKeyPinVerified = phase1176Execution.liveHostKeyPinVerified,
            nginxReloadPerformed = phase1176Execution.nginxReloadPerformed,
            exactConfigSha256VerifiedBeforeReload = phase1176Execution.exactConfigSha256VerifiedBeforeReload,
            nginxSyntaxValidationPassedBeforeReload = phase1176Execution.nginxSyntaxValidationPassedBeforeReload,
            listenerFreeBeforeReload = phase1176Execution.listenerFreeBeforeReload,
            exactConfigSha256VerifiedAfterReload = phase1176Execution.exactConfigSha256VerifiedAfterReload,
            nginxMasterRunningAfterReload = phase1176Execution.nginxMasterRunningAfterReload,
            expectedListenerLiveAfterReload = phase1176Execution.expectedListenerLiveAfterReload,
            configMutationPerformed = phase1176Execution.configMutationPerformed,
            coordinatorReinvoked = phase1176Execution.coordinatorInvoked,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = phase1176Execution.automaticRetryPerformed,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
            validateExecutionResultAgainst(
                result = it,
                admission = admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188AuthorityPreparation,
                phase1189Execution = phase1189Execution,
                phase1190AuthorityPreparation = phase1190AuthorityPreparation,
            )
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(
            admission.status == SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmissionStatus
                .READY_FOR_FRESH_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
        )
        listOf(
            admission.phase1190AuthorityPreparationResultSha256,
            admission.phase1189ExecutionResultSha256,
            admission.phase1189AdmissionSha256,
            admission.phase1188AuthorityPreparationResultSha256,
            admission.phase1187ExecutionResultSha256,
            admission.phase1186AuthorityPreparationResultSha256,
            admission.phase1185PreparationResultSha256,
            admission.phase1184ExecutionResultSha256,
            admission.phase1183HandoffSha256,
            admission.phase1180ExecutionResultSha256,
            admission.servingPolicySelectionSha256,
            admission.phase1169ExecutionResultSha256,
            admission.phase1170PreparationResultSha256,
            admission.phase1171AuthorityPreparationResultSha256,
            admission.phase1172ExecutionResultSha256,
            admission.phase1173AuthorityPreparationResultSha256,
            admission.phase1174ExecutionResultSha256,
            admission.phase1175AuthorityPreparationResultSha256,
            admission.publicationPlanSha256,
            admission.mutationPreparationSha256,
            admission.stagingSyntaxExecutionPlanSha256,
            admission.phase11_59ExecutionProofSha256,
            admission.activationExecutionPlanSha256,
            admission.phase11_60ExecutionProofSha256,
            admission.nginxReloadExecutionPlanSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
            .validateAdmission(admission.phase1176Admission)
        require(
            admission.phase1176Admission.policyBoundNginxReloadAuthorityPreparationResultSha256 ==
                admission.phase1175AuthorityPreparationResultSha256,
        )
        require(admission.phase1176Admission.servingPolicySelectionSha256 == admission.servingPolicySelectionSha256)
        require(admission.phase1176Admission.publicationPlanSha256 == admission.publicationPlanSha256)
        require(admission.phase1176Admission.mutationTransactionId == admission.mutationTransactionId)
        require(admission.phase1176Admission.phase11_60ExecutionProofSha256 == admission.phase11_60ExecutionProofSha256)
        require(admission.phase1176Admission.nginxReloadExecutionPlanSha256 == admission.nginxReloadExecutionPlanSha256)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.realVpsExecutionEligible)
        require(admission.nginxReloadAuthorized)
        require(!admission.configMutationAuthorized)
        require(!admission.coordinatorReinvocationAuthorized)
        require(!admission.staticPublicationReplayAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = ""))) {
            "Phase 11.91 admission SHA-256 mismatch"
        }
    }

    fun validateExecutionResult(result: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status == SiteProductionDeploymentPostCoordinatorNginxReloadExecutionStatus
                .NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE_WITHOUT_COORDINATOR_REPLAY,
        )
        listOf(
            result.phase1191AdmissionSha256,
            result.phase1190AuthorityPreparationResultSha256,
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
            result.freshCredentialResolutionProofSha256,
            result.publicationPlanSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.activationExecutionPlanSha256,
            result.phase11_60ExecutionProofSha256,
            result.nginxReloadExecutionPlanSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
            .validateExecutionResult(result.phase1176ExecutionResult)
        require(result.exactPostCoordinatorChainBindingVerified)
        require(result.successfulPostCoordinatorConfigActivationExecutionProofValidated)
        require(result.durablePreReloadCheckpointRecorded)
        require(result.credentialLeaseMaterialConsumed)
        require(result.productionNetworkTouched)
        require(result.liveHostKeyPinVerified)
        require(result.nginxReloadPerformed)
        require(result.exactConfigSha256VerifiedBeforeReload)
        require(result.nginxSyntaxValidationPassedBeforeReload)
        require(result.listenerFreeBeforeReload)
        require(result.exactConfigSha256VerifiedAfterReload)
        require(result.nginxMasterRunningAfterReload)
        require(result.expectedListenerLiveAfterReload)
        require(!result.configMutationPerformed)
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(!result.automaticRetryPerformed)
        require(result.executionResultSha256 == executionResultSha256(result.copy(executionResultSha256 = ""))) {
            "Phase 11.91 execution-result SHA-256 mismatch"
        }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
        admission: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        phase1189Execution: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
        phase1190AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        validateChain(
            handoff,
            phase1184Execution,
            phase1185Preparation,
            phase1186AuthorityPreparation,
            phase1187Execution,
            phase1188AuthorityPreparation,
            phase1189Execution,
            phase1190AuthorityPreparation,
        )
        require(result.phase1191AdmissionSha256 == admission.admissionSha256)
        require(result.phase1190AuthorityPreparationResultSha256 ==
            phase1190AuthorityPreparation.authorityPreparationResultSha256)
        require(result.phase1189ExecutionResultSha256 == phase1189Execution.executionResultSha256)
        require(result.phase1189AdmissionSha256 == phase1189Execution.phase1189AdmissionSha256)
        require(result.phase1188AuthorityPreparationResultSha256 ==
            phase1188AuthorityPreparation.authorityPreparationResultSha256)
        require(result.phase1187ExecutionResultSha256 == phase1187Execution.executionResultSha256)
        require(result.phase1186AuthorityPreparationResultSha256 ==
            phase1186AuthorityPreparation.authorityPreparationResultSha256)
        require(result.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(result.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(result.phase1176ExecutionResult.admissionSha256 == admission.phase1176Admission.admissionSha256)
        require(result.phase1176ExecutionResult.executionResultSha256.matches(sha256))
        require(result.phase1176ExecutionResult.phase11_61ExecutionProof.executionProofSha256.matches(sha256))
        require(result.phase1176ExecutionResult.freshCredentialResolutionProofSha256 ==
            result.freshCredentialResolutionProofSha256)
    }

    private fun validateChain(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        phase1189Execution: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
        phase1190AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult,
    ) {
        SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
            .validateAgainst(
                result = phase1190AuthorityPreparation,
                handoff = handoff,
                phase1188AuthorityPreparation = phase1188AuthorityPreparation,
                phase1189Execution = phase1189Execution,
            )
        require(phase1190AuthorityPreparation.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(phase1190AuthorityPreparation.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(phase1190AuthorityPreparation.phase1186AuthorityPreparationResultSha256 ==
            phase1186AuthorityPreparation.authorityPreparationResultSha256)
        require(phase1190AuthorityPreparation.phase1187ExecutionResultSha256 == phase1187Execution.executionResultSha256)
        require(phase1188AuthorityPreparation.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(phase1188AuthorityPreparation.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(phase1188AuthorityPreparation.phase1186AuthorityPreparationResultSha256 ==
            phase1186AuthorityPreparation.authorityPreparationResultSha256)
        require(phase1189Execution.phase1187ExecutionResultSha256 == phase1187Execution.executionResultSha256)
        require(phase1190AuthorityPreparation.nginxReloadExecutionAuthorized)
        require(!phase1190AuthorityPreparation.nginxReloadPerformed)
        require(!phase1190AuthorityPreparation.coordinatorReinvocationAuthorized)
        require(!phase1190AuthorityPreparation.staticPublicationReplayAuthorized)
        require(!phase1190AuthorityPreparation.automaticRetryAuthorized)
    }

    private fun admissionSha256(
        value: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission,
    ): String = digest(buildString {
        append("phase=11.91-admission\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1190AuthorityPreparation=").append(value.phase1190AuthorityPreparationResultSha256).append('\n')
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
        append("phase1176Admission=").append(value.phase1176Admission.admissionSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(value.phase11_59ExecutionProofSha256).append('\n')
        append("activationExecutionPlan=").append(value.activationExecutionPlanSha256).append('\n')
        append("phase11_60Proof=").append(value.phase11_60ExecutionProofSha256).append('\n')
        append("nginxReloadPlan=").append(value.nginxReloadExecutionPlanSha256).append('\n')
        append("requiresFreshCredentialResolution=").append(value.requiresFreshCredentialResolution).append('\n')
        append("requiresLiveRemoteHostKeyVerification=").append(value.requiresLiveRemoteHostKeyVerification).append('\n')
        append("realVpsExecutionEligible=").append(value.realVpsExecutionEligible).append('\n')
        append("nginxReloadAuthorized=").append(value.nginxReloadAuthorized).append('\n')
        append("configMutationAuthorized=").append(value.configMutationAuthorized).append('\n')
        append("coordinatorReinvocationAuthorized=").append(value.coordinatorReinvocationAuthorized).append('\n')
        append("staticPublicationReplayAuthorized=").append(value.staticPublicationReplayAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun executionResultSha256(
        value: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
    ): String = digest(buildString {
        append("phase=11.91-result\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1191Admission=").append(value.phase1191AdmissionSha256).append('\n')
        append("phase1190AuthorityPreparation=").append(value.phase1190AuthorityPreparationResultSha256).append('\n')
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
        append("phase1176Execution=").append(value.phase1176ExecutionResult.executionResultSha256).append('\n')
        append("phase11_61Proof=").append(value.phase1176ExecutionResult.phase11_61ExecutionProof.executionProofSha256).append('\n')
        append("freshCredentialResolution=").append(value.freshCredentialResolutionProofSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(value.phase11_59ExecutionProofSha256).append('\n')
        append("activationExecutionPlan=").append(value.activationExecutionPlanSha256).append('\n')
        append("phase11_60Proof=").append(value.phase11_60ExecutionProofSha256).append('\n')
        append("nginxReloadPlan=").append(value.nginxReloadExecutionPlanSha256).append('\n')
        append("exactPostCoordinatorChainBindingVerified=").append(value.exactPostCoordinatorChainBindingVerified).append('\n')
        append("successfulPostCoordinatorConfigActivationExecutionProofValidated=").append(value.successfulPostCoordinatorConfigActivationExecutionProofValidated).append('\n')
        append("durablePreReloadCheckpointRecorded=").append(value.durablePreReloadCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(value.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(value.productionNetworkTouched).append('\n')
        append("liveHostKeyPinVerified=").append(value.liveHostKeyPinVerified).append('\n')
        append("nginxReloadPerformed=").append(value.nginxReloadPerformed).append('\n')
        append("exactConfigSha256VerifiedBeforeReload=").append(value.exactConfigSha256VerifiedBeforeReload).append('\n')
        append("nginxSyntaxValidationPassedBeforeReload=").append(value.nginxSyntaxValidationPassedBeforeReload).append('\n')
        append("listenerFreeBeforeReload=").append(value.listenerFreeBeforeReload).append('\n')
        append("exactConfigSha256VerifiedAfterReload=").append(value.exactConfigSha256VerifiedAfterReload).append('\n')
        append("nginxMasterRunningAfterReload=").append(value.nginxMasterRunningAfterReload).append('\n')
        append("expectedListenerLiveAfterReload=").append(value.expectedListenerLiveAfterReload).append('\n')
        append("configMutationPerformed=").append(value.configMutationPerformed).append('\n')
        append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
        append("automaticRetryPerformed=").append(value.automaticRetryPerformed).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
