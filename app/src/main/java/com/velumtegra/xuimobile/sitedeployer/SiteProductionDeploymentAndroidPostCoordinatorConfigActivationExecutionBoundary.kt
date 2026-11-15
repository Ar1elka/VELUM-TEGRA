package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort
import java.security.MessageDigest

/**
 * Phase 11.89 consumes the exact READY Phase 11.88 post-coordinator activation authority and
 * delegates exactly once to the already accepted Phase 11.74 exact-config activation executor.
 *
 * This boundary authorizes only exact config activation + SHA verification + nginx syntax
 * validation. nginx reload/restart, coordinator/static-publication replay and automatic retry
 * remain forbidden.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        authorityPreparation: SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmission {
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
            .validate(authorityPreparation)

        val phase1174Admission =
            SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                .admit(authorityPreparation.phase1173AuthorityPreparation)
        require(
            phase1174Admission.policyBoundConfigActivationAuthorityPreparationResultSha256 ==
                authorityPreparation.phase1173AuthorityPreparation.authorityPreparationResultSha256,
        )

        val base = SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
            phase1188AuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            phase1187ExecutionResultSha256 = authorityPreparation.phase1187ExecutionResultSha256,
            phase1187AdmissionSha256 = authorityPreparation.phase1187AdmissionSha256,
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
            phase1174Admission = phase1174Admission,
            publicationPlanSha256 = authorityPreparation.publicationPlanSha256,
            selectedProtocol = authorityPreparation.selectedProtocol,
            mutationTransactionId = authorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = authorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = authorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = authorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = authorityPreparation.activationExecutionPlanSha256,
            requiresFreshCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            realVpsExecutionEligible = true,
            exactConfigActivationAuthorized = true,
            webServerReloadAuthorized = false,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            automaticRetryAuthorized = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort:
            SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort,
    ): SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.89 execution attempt id must be canonical"
        }
        validateAdmission(admission)
        validateChain(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            phase1187Execution = phase1187Execution,
            phase1188AuthorityPreparation = phase1188AuthorityPreparation,
        )
        val expectedAdmission = admit(phase1188AuthorityPreparation)
        require(expectedAdmission.admissionSha256 == admission.admissionSha256) {
            "Phase 11.89 admission no longer matches the exact Phase 11.88 authority preparation"
        }
        require(
            admission.status ==
                SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
        )
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.exactConfigActivationAuthorized)
        require(!admission.webServerReloadAuthorized)
        require(serverAccess.endpoint.host == handoff.remoteHostIdentity)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1174Execution =
            SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary.executeOnce(
                admission = admission.phase1174Admission,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                stagingSyntaxAuthorityPreparation =
                    phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                stagingSyntaxExecution = phase1187Execution.phase1172ExecutionResult,
                activationAuthorityPreparation =
                    phase1188AuthorityPreparation.phase1173AuthorityPreparation,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
                executionUsePort = executionUsePort,
            )
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1174Execution,
                admission = admission.phase1174Admission,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                stagingSyntaxAuthorityPreparation =
                    phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                stagingSyntaxExecution = phase1187Execution.phase1172ExecutionResult,
                activationAuthorityPreparation =
                    phase1188AuthorityPreparation.phase1173AuthorityPreparation,
            )
        require(phase1174Execution.exactConfigActivationPerformed)
        require(phase1174Execution.exactConfigSha256Verified)
        require(phase1174Execution.nginxSyntaxValidationPassed)
        require(phase1174Execution.exactConfigPathPresentAfterActivation)
        require(phase1174Execution.stagingConfigAbsentAfterActivation)
        require(phase1174Execution.listenerStillFreeAfterActivation)
        require(!phase1174Execution.rollbackToAbsentPerformed)
        require(!phase1174Execution.webServerReloadPerformed)
        require(!phase1174Execution.automaticRetryPerformed)
        require(!phase1174Execution.coordinatorInvoked)

        val base = SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPostCoordinatorConfigActivationExecutionStatus
                    .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD_OR_COORDINATOR_REPLAY,
            phase1189AdmissionSha256 = admission.admissionSha256,
            phase1188AuthorityPreparationResultSha256 =
                phase1188AuthorityPreparation.authorityPreparationResultSha256,
            phase1187ExecutionResultSha256 = phase1187Execution.executionResultSha256,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1184ExecutionResultSha256 = phase1184Execution.executionResultSha256,
            phase1185PreparationResultSha256 = phase1185Preparation.preparationResultSha256,
            phase1186AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            phase1169ExecutionResultSha256 =
                phase1184Execution.phase1169ExecutionResult.executionResultSha256,
            phase1170PreparationResultSha256 =
                phase1185Preparation.phase1170Preparation.preparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.phase1171AuthorityPreparation
                    .authorityPreparationResultSha256,
            phase1172ExecutionResultSha256 =
                phase1187Execution.phase1172ExecutionResult.executionResultSha256,
            phase1174ExecutionResult = phase1174Execution,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            publicationPlanSha256 = admission.publicationPlanSha256,
            selectedProtocol = admission.selectedProtocol,
            mutationTransactionId = admission.mutationTransactionId,
            mutationPreparationSha256 = admission.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = admission.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = admission.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = admission.activationExecutionPlanSha256,
            exactPostCoordinatorChainBindingVerified = true,
            durablePreactivationCheckpointRecorded =
                phase1174Execution.durablePreactivationCheckpointRecorded,
            credentialLeaseMaterialConsumed = phase1174Execution.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1174Execution.productionNetworkTouched,
            liveHostKeyPinVerified = phase1174Execution.liveHostKeyPinVerified,
            exactConfigActivationPerformed = phase1174Execution.exactConfigActivationPerformed,
            exactConfigSha256Verified = phase1174Execution.exactConfigSha256Verified,
            nginxSyntaxValidationPassed = phase1174Execution.nginxSyntaxValidationPassed,
            exactConfigPathPresentAfterActivation =
                phase1174Execution.exactConfigPathPresentAfterActivation,
            stagingConfigAbsentAfterActivation = phase1174Execution.stagingConfigAbsentAfterActivation,
            listenerStillFreeAfterActivation = phase1174Execution.listenerStillFreeAfterActivation,
            rollbackToAbsentPerformed = phase1174Execution.rollbackToAbsentPerformed,
            webServerReloadPerformed = phase1174Execution.webServerReloadPerformed,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = phase1174Execution.automaticRetryPerformed,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
            validateExecutionResult(it)
            validateExecutionResultAgainst(
                result = it,
                admission = admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188AuthorityPreparation,
            )
        }
    }

    fun validateAdmission(
        admission: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmission,
    ) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(
            admission.status ==
                SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
        )
        listOf(
            admission.phase1188AuthorityPreparationResultSha256,
            admission.phase1187ExecutionResultSha256,
            admission.phase1187AdmissionSha256,
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
            admission.publicationPlanSha256,
            admission.mutationPreparationSha256,
            admission.stagingSyntaxExecutionPlanSha256,
            admission.phase11_59ExecutionProofSha256,
            admission.activationExecutionPlanSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
            .validateAdmission(admission.phase1174Admission)
        require(
            admission.phase1174Admission.policyBoundStagingSyntaxExecutionResultSha256 ==
                admission.phase1172ExecutionResultSha256,
        )
        require(
            admission.phase1174Admission.servingPolicySelectionSha256 ==
                admission.servingPolicySelectionSha256,
        )
        require(admission.phase1174Admission.publicationPlanSha256 == admission.publicationPlanSha256)
        require(admission.phase1174Admission.selectedProtocol == admission.selectedProtocol)
        require(admission.phase1174Admission.mutationTransactionId == admission.mutationTransactionId)
        require(admission.phase1174Admission.mutationPreparationSha256 == admission.mutationPreparationSha256)
        require(
            admission.phase1174Admission.stagingSyntaxExecutionPlanSha256 ==
                admission.stagingSyntaxExecutionPlanSha256,
        )
        require(admission.phase1174Admission.phase11_59ExecutionProofSha256 == admission.phase11_59ExecutionProofSha256)
        require(admission.phase1174Admission.activationExecutionPlanSha256 == admission.activationExecutionPlanSha256)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.realVpsExecutionEligible)
        require(admission.exactConfigActivationAuthorized)
        require(!admission.webServerReloadAuthorized)
        require(!admission.coordinatorReinvocationAuthorized)
        require(!admission.staticPublicationReplayAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(admission.phase1174Admission.exactConfigActivationAuthorized)
        require(!admission.phase1174Admission.webServerReloadAuthorized)
        require(!admission.phase1174Admission.automaticRetryAuthorized)
        require(!admission.phase1174Admission.coordinatorInvoked)
        require(
            admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = "")),
        ) { "Phase 11.89 admission SHA-256 mismatch" }
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPostCoordinatorConfigActivationExecutionStatus
                    .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD_OR_COORDINATOR_REPLAY,
        )
        listOf(
            result.phase1189AdmissionSha256,
            result.phase1188AuthorityPreparationResultSha256,
            result.phase1187ExecutionResultSha256,
            result.phase1183HandoffSha256,
            result.phase1184ExecutionResultSha256,
            result.phase1185PreparationResultSha256,
            result.phase1186AuthorityPreparationResultSha256,
            result.phase1180ExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.phase1169ExecutionResultSha256,
            result.phase1170PreparationResultSha256,
            result.phase1171AuthorityPreparationResultSha256,
            result.phase1172ExecutionResultSha256,
            result.freshCredentialResolutionProofSha256,
            result.publicationPlanSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.activationExecutionPlanSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
            .validateExecutionResult(result.phase1174ExecutionResult)
        require(result.exactPostCoordinatorChainBindingVerified)
        require(result.durablePreactivationCheckpointRecorded)
        require(result.credentialLeaseMaterialConsumed)
        require(result.productionNetworkTouched)
        require(result.liveHostKeyPinVerified)
        require(result.exactConfigActivationPerformed)
        require(result.exactConfigSha256Verified)
        require(result.nginxSyntaxValidationPassed)
        require(result.exactConfigPathPresentAfterActivation)
        require(result.stagingConfigAbsentAfterActivation)
        require(result.listenerStillFreeAfterActivation)
        require(!result.rollbackToAbsentPerformed)
        require(!result.webServerReloadPerformed)
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(!result.automaticRetryPerformed)
        require(
            result.executionResultSha256 ==
                executionResultSha256(result.copy(executionResultSha256 = "")),
        ) { "Phase 11.89 execution-result SHA-256 mismatch" }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
        admission: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        phase1187Execution: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
        phase1188AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult,
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
        )
        require(result.phase1189AdmissionSha256 == admission.admissionSha256)
        require(
            result.phase1188AuthorityPreparationResultSha256 ==
                phase1188AuthorityPreparation.authorityPreparationResultSha256,
        )
        require(result.phase1187ExecutionResultSha256 == phase1187Execution.executionResultSha256)
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(result.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(result.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(
            result.phase1186AuthorityPreparationResultSha256 ==
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
        )
        require(result.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(result.servingPolicySelectionSha256 == admission.servingPolicySelectionSha256)
        require(result.phase1169ExecutionResultSha256 == admission.phase1169ExecutionResultSha256)
        require(result.phase1170PreparationResultSha256 == admission.phase1170PreparationResultSha256)
        require(result.phase1171AuthorityPreparationResultSha256 == admission.phase1171AuthorityPreparationResultSha256)
        require(result.phase1172ExecutionResultSha256 == admission.phase1172ExecutionResultSha256)
        require(result.publicationPlanSha256 == admission.publicationPlanSha256)
        require(result.selectedProtocol == admission.selectedProtocol)
        require(result.mutationTransactionId == admission.mutationTransactionId)
        require(result.mutationPreparationSha256 == admission.mutationPreparationSha256)
        require(result.stagingSyntaxExecutionPlanSha256 == admission.stagingSyntaxExecutionPlanSha256)
        require(result.phase11_59ExecutionProofSha256 == admission.phase11_59ExecutionProofSha256)
        require(result.activationExecutionPlanSha256 == admission.activationExecutionPlanSha256)
        require(result.phase1174ExecutionResult.admissionSha256 == admission.phase1174Admission.admissionSha256)
        require(
            result.phase1174ExecutionResult.freshCredentialResolutionProofSha256 ==
                result.freshCredentialResolutionProofSha256,
        )
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
    ) {
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
            .validateAgainst(
                result = phase1188AuthorityPreparation,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
                phase1187Execution = phase1187Execution,
            )
        require(phase1188AuthorityPreparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(
            phase1188AuthorityPreparation.phase1187ExecutionResultSha256 ==
                phase1187Execution.executionResultSha256,
        )
        require(phase1188AuthorityPreparation.exactConfigActivationAuthorized)
        require(!phase1188AuthorityPreparation.webServerReloadAuthorized)
        require(!phase1188AuthorityPreparation.coordinatorReinvocationAuthorized)
        require(!phase1188AuthorityPreparation.staticPublicationReplayAuthorized)
        require(!phase1188AuthorityPreparation.automaticRetryAuthorized)
    }

    private fun admissionSha256(
        value: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmission,
    ): String = digest(buildString {
        append("phase=11.89-admission\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1188AuthorityPreparation=").append(value.phase1188AuthorityPreparationResultSha256).append('\n')
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
        append("phase1174Admission=").append(value.phase1174Admission.admissionSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(value.phase11_59ExecutionProofSha256).append('\n')
        append("activationExecutionPlan=").append(value.activationExecutionPlanSha256).append('\n')
        append("requiresFreshCredentialResolution=").append(value.requiresFreshCredentialResolution).append('\n')
        append("requiresLiveRemoteHostKeyVerification=").append(value.requiresLiveRemoteHostKeyVerification).append('\n')
        append("realVpsExecutionEligible=").append(value.realVpsExecutionEligible).append('\n')
        append("exactConfigActivationAuthorized=").append(value.exactConfigActivationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(value.webServerReloadAuthorized).append('\n')
        append("coordinatorReinvocationAuthorized=").append(value.coordinatorReinvocationAuthorized).append('\n')
        append("staticPublicationReplayAuthorized=").append(value.staticPublicationReplayAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun executionResultSha256(
        value: SiteProductionDeploymentPostCoordinatorConfigActivationExecutionResult,
    ): String = digest(buildString {
        append("phase=11.89-result\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1189Admission=").append(value.phase1189AdmissionSha256).append('\n')
        append("phase1188AuthorityPreparation=").append(value.phase1188AuthorityPreparationResultSha256).append('\n')
        append("phase1187Execution=").append(value.phase1187ExecutionResultSha256).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
        append("phase1185Preparation=").append(value.phase1185PreparationResultSha256).append('\n')
        append("phase1186AuthorityPreparation=").append(value.phase1186AuthorityPreparationResultSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Execution=").append(value.phase1169ExecutionResultSha256).append('\n')
        append("phase1170Preparation=").append(value.phase1170PreparationResultSha256).append('\n')
        append("phase1171AuthorityPreparation=").append(value.phase1171AuthorityPreparationResultSha256).append('\n')
        append("phase1172Execution=").append(value.phase1172ExecutionResultSha256).append('\n')
        append("phase1174Execution=").append(value.phase1174ExecutionResult.executionResultSha256).append('\n')
        append("freshCredentialResolution=").append(value.freshCredentialResolutionProofSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(value.phase11_59ExecutionProofSha256).append('\n')
        append("activationExecutionPlan=").append(value.activationExecutionPlanSha256).append('\n')
        append("exactPostCoordinatorChainBindingVerified=").append(value.exactPostCoordinatorChainBindingVerified).append('\n')
        append("durablePreactivationCheckpointRecorded=").append(value.durablePreactivationCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(value.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(value.productionNetworkTouched).append('\n')
        append("liveHostKeyPinVerified=").append(value.liveHostKeyPinVerified).append('\n')
        append("exactConfigActivationPerformed=").append(value.exactConfigActivationPerformed).append('\n')
        append("exactConfigSha256Verified=").append(value.exactConfigSha256Verified).append('\n')
        append("nginxSyntaxValidationPassed=").append(value.nginxSyntaxValidationPassed).append('\n')
        append("exactConfigPathPresentAfterActivation=").append(value.exactConfigPathPresentAfterActivation).append('\n')
        append("stagingConfigAbsentAfterActivation=").append(value.stagingConfigAbsentAfterActivation).append('\n')
        append("listenerStillFreeAfterActivation=").append(value.listenerStillFreeAfterActivation).append('\n')
        append("rollbackToAbsentPerformed=").append(value.rollbackToAbsentPerformed).append('\n')
        append("webServerReloadPerformed=").append(value.webServerReloadPerformed).append('\n')
        append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
        append("automaticRetryPerformed=").append(value.automaticRetryPerformed).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
