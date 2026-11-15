package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort
import java.security.MessageDigest

/**
 * Phase 11.74 makes the exact READY Phase 11.73 production-chain result mandatory before the
 * existing Phase 11.60 live exact-config activation executor may run.
 *
 * This boundary delegates exactly once to Phase 11.60 under its durable preactivation replay
 * fence. Exact config activation + SHA verification + nginx syntax validation are allowed;
 * nginx reload/restart and every later mutation class remain forbidden.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        authorityPreparation:
            SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
    ): SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmission {
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validate(authorityPreparation)

        val plan = authorityPreparation.activationExecutionPlan
        val base = SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
            policyBoundConfigActivationAuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            policyBoundStagingSyntaxExecutionResultSha256 =
                authorityPreparation.policyBoundStagingSyntaxExecutionResultSha256,
            servingPolicySelectionSha256 = authorityPreparation.servingPolicySelectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                authorityPreparation.policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                authorityPreparation.policyBoundConfigMutationPreparationResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                authorityPreparation.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            publicationPlanSha256 = authorityPreparation.publicationPlanSha256,
            selectedProtocol = authorityPreparation.selectedProtocol,
            readOnlyPreflightSha256 = authorityPreparation.readOnlyPreflightSha256,
            mutationTransactionId = authorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = authorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 =
                authorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = authorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = plan.activationPlanSha256,
            requiresFreshCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            realVpsExecutionEligible = true,
            exactConfigActivationAuthorized = true,
            webServerReloadAuthorized = false,
            certificateMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution:
            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort:
            SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort,
    ): SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.74 execution attempt id must be canonical"
        }
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validateAgainst(
                result = activationAuthorityPreparation,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
            )

        val expectedAdmission = admit(activationAuthorityPreparation)
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.74 admission does not match the exact Phase 11.73 result"
        }
        require(
            admission.status ==
                SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
        )
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.exactConfigActivationAuthorized)
        require(!admission.webServerReloadAuthorized)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        val mutationPreparation =
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
        val stagingSyntaxPlan =
            requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan)
        val phase1159Proof = stagingSyntaxExecution.phase11_59ExecutionProof
        val activationPlan = activationAuthorityPreparation.activationExecutionPlan

        require(
            activationAuthorityPreparation.authorityPreparationResultSha256 ==
                admission.policyBoundConfigActivationAuthorityPreparationResultSha256,
        )
        require(
            stagingSyntaxExecution.executionResultSha256 ==
                admission.policyBoundStagingSyntaxExecutionResultSha256,
        )
        require(selection.selectionSha256 == admission.servingPolicySelectionSha256)
        require(
            policyBoundPreflightExecution.executionResultSha256 ==
                admission.policyBoundPreflightExecutionResultSha256,
        )
        require(
            policyBoundConfigMutationPreparation.preparationResultSha256 ==
                admission.policyBoundConfigMutationPreparationResultSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256 ==
                admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
        )
        require(publicationPlan.publicationPlanSha256 == admission.publicationPlanSha256)
        require(requireNotNull(selection.selectedProtocol) == admission.selectedProtocol)
        require(readOnlyPreflight.preflightSha256 == admission.readOnlyPreflightSha256)
        require(
            policyBoundConfigMutationPreparation.mutationTransactionId ==
                admission.mutationTransactionId,
        )
        require(
            mutationPreparation.mutationPreparationSha256 ==
                admission.mutationPreparationSha256,
        )
        require(
            stagingSyntaxPlan.executionPlanSha256 ==
                admission.stagingSyntaxExecutionPlanSha256,
        )
        require(
            phase1159Proof.executionProofSha256 ==
                admission.phase11_59ExecutionProofSha256,
        )
        require(activationPlan.activationPlanSha256 == admission.activationExecutionPlanSha256)

        val phase1160Proof =
            SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
                .executeOnce(
                    publicationPlan = publicationPlan,
                    readOnlyPreflight = readOnlyPreflight,
                    mutationPreparation = mutationPreparation,
                    stagingSyntaxPlan = stagingSyntaxPlan,
                    stagingSyntaxProof = phase1159Proof,
                    activationPlan = activationPlan,
                    freshResolutionProof = freshResolutionProof,
                    freshCredentialLease = freshCredentialLease,
                    serverAccess = serverAccess,
                    executionAttemptId = executionAttemptId,
                    executedAtEpochMillis = executedAtEpochMillis,
                    executionUsePort = executionUsePort,
                )
        SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
            .validateProof(phase1160Proof)

        require(phase1160Proof.activationPlanSha256 == activationPlan.activationPlanSha256)
        require(
            phase1160Proof.stagingSyntaxExecutionPlanSha256 ==
                stagingSyntaxPlan.executionPlanSha256,
        )
        require(
            phase1160Proof.stagingSyntaxExecutionProofSha256 ==
                phase1159Proof.executionProofSha256,
        )
        require(
            phase1160Proof.mutationPreparationSha256 ==
                mutationPreparation.mutationPreparationSha256,
        )
        require(phase1160Proof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(phase1160Proof.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(
            phase1160Proof.freshCredentialResolutionProofSha256 ==
                freshResolutionProof.resolutionProofSha256,
        )

        val base = SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPolicyBoundConfigActivationExecutionStatus
                    .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD,
            admissionSha256 = admission.admissionSha256,
            policyBoundConfigActivationAuthorityPreparationResultSha256 =
                activationAuthorityPreparation.authorityPreparationResultSha256,
            policyBoundStagingSyntaxExecutionResultSha256 =
                stagingSyntaxExecution.executionResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecution.executionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                policyBoundConfigMutationPreparation.preparationResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = requireNotNull(selection.selectedProtocol),
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            mutationTransactionId = policyBoundConfigMutationPreparation.mutationTransactionId,
            mutationPreparationSha256 = mutationPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = stagingSyntaxPlan.executionPlanSha256,
            phase11_59ExecutionProofSha256 = phase1159Proof.executionProofSha256,
            activationExecutionPlanSha256 = activationPlan.activationPlanSha256,
            phase11_60ExecutionProof = phase1160Proof,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            exactProductionChainBindingVerified = true,
            successfulStagingSyntaxExecutionProofValidated =
                phase1160Proof.successfulStagingSyntaxProofValidated,
            durablePreactivationCheckpointRecorded =
                phase1160Proof.durablePreactivationCheckpointRecorded,
            credentialLeaseMaterialConsumed = phase1160Proof.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1160Proof.productionNetworkTouched,
            liveHostKeyPinVerified = phase1160Proof.hostKeyPinVerifiedAgainstRemote,
            exactConfigActivationPerformed = phase1160Proof.exactConfigActivationPerformed,
            exactConfigSha256Verified = phase1160Proof.exactConfigSha256Verified,
            nginxSyntaxValidationPassed = phase1160Proof.nginxSyntaxValidationPassed,
            exactConfigPathPresentAfterActivation =
                phase1160Proof.exactConfigPathPresentAfterActivation,
            stagingConfigAbsentAfterActivation = phase1160Proof.stagingConfigAbsentAfterActivation,
            listenerStillFreeAfterActivation = phase1160Proof.listenerStillFreeAfterActivation,
            rollbackToAbsentPerformed = phase1160Proof.rollbackToAbsentPerformed,
            webServerReloadPerformed = phase1160Proof.webServerReloadPerformed,
            certificateMutationPerformed = false,
            dnsMutationPerformed = phase1160Proof.dnsMutationPerformed,
            firewallMutationPerformed = phase1160Proof.firewallMutationPerformed,
            packageInstallPerformed = phase1160Proof.packageInstallPerformed,
            privateKeyContentReadPerformed = phase1160Proof.privateKeyContentReadPerformed,
            automaticRetryPerformed = phase1160Proof.automaticRetryPerformed,
            coordinatorInvoked = phase1160Proof.coordinatorInvoked,
            exposesDeployUiAction = phase1160Proof.exposesDeployUiAction,
            executionResultSha256 = "",
        )
        return base.copy(
            executionResultSha256 = executionResultSha256(base),
        ).also {
            validateExecutionResult(it)
            validateExecutionResultAgainst(
                result = it,
                admission = admission,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
            )
        }
    }

    fun validateAdmission(
        admission: SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmission,
    ) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(
            admission.status ==
                SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
        )
        listOf(
            admission.policyBoundConfigActivationAuthorityPreparationResultSha256,
            admission.policyBoundStagingSyntaxExecutionResultSha256,
            admission.servingPolicySelectionSha256,
            admission.policyBoundPreflightExecutionResultSha256,
            admission.policyBoundConfigMutationPreparationResultSha256,
            admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            admission.publicationPlanSha256,
            admission.readOnlyPreflightSha256,
            admission.mutationPreparationSha256,
            admission.stagingSyntaxExecutionPlanSha256,
            admission.phase11_59ExecutionProofSha256,
            admission.activationExecutionPlanSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.realVpsExecutionEligible)
        require(admission.exactConfigActivationAuthorized)
        require(!admission.webServerReloadAuthorized)
        require(!admission.certificateMutationAuthorized)
        require(!admission.dnsMutationAuthorized)
        require(!admission.firewallMutationAuthorized)
        require(!admission.packageInstallAuthorized)
        require(!admission.privateKeyContentReadAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(!admission.coordinatorInvoked)
        require(!admission.exposesDeployUiAction)
        require(
            admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = "")),
        ) { "Phase 11.74 admission SHA-256 mismatch" }
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPolicyBoundConfigActivationExecutionStatus
                    .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD,
        )
        listOf(
            result.admissionSha256,
            result.policyBoundConfigActivationAuthorityPreparationResultSha256,
            result.policyBoundStagingSyntaxExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.policyBoundPreflightExecutionResultSha256,
            result.policyBoundConfigMutationPreparationResultSha256,
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            result.publicationPlanSha256,
            result.readOnlyPreflightSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.activationExecutionPlanSha256,
            result.freshCredentialResolutionProofSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
            .validateProof(result.phase11_60ExecutionProof)
        require(result.exactProductionChainBindingVerified)
        require(result.successfulStagingSyntaxExecutionProofValidated)
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
        require(!result.certificateMutationPerformed)
        require(!result.dnsMutationPerformed)
        require(!result.firewallMutationPerformed)
        require(!result.packageInstallPerformed)
        require(!result.privateKeyContentReadPerformed)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(
            result.executionResultSha256 ==
                executionResultSha256(result.copy(executionResultSha256 = "")),
        ) { "Phase 11.74 execution-result SHA-256 mismatch" }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution:
            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validateAgainst(
                result = activationAuthorityPreparation,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
            )
        val publicationPlan = requireNotNull(selection.publicationPlan)
        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        val mutationPreparation =
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
        val stagingSyntaxPlan =
            requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan)

        require(result.admissionSha256 == admission.admissionSha256)
        require(
            result.policyBoundConfigActivationAuthorityPreparationResultSha256 ==
                activationAuthorityPreparation.authorityPreparationResultSha256,
        )
        require(
            result.policyBoundStagingSyntaxExecutionResultSha256 ==
                stagingSyntaxExecution.executionResultSha256,
        )
        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(
            result.policyBoundPreflightExecutionResultSha256 ==
                policyBoundPreflightExecution.executionResultSha256,
        )
        require(
            result.policyBoundConfigMutationPreparationResultSha256 ==
                policyBoundConfigMutationPreparation.preparationResultSha256,
        )
        require(
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256 ==
                stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256,
        )
        require(result.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(result.selectedProtocol == requireNotNull(selection.selectedProtocol))
        require(result.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(
            result.mutationTransactionId ==
                policyBoundConfigMutationPreparation.mutationTransactionId,
        )
        require(
            result.mutationPreparationSha256 ==
                mutationPreparation.mutationPreparationSha256,
        )
        require(
            result.stagingSyntaxExecutionPlanSha256 ==
                stagingSyntaxPlan.executionPlanSha256,
        )
        require(
            result.phase11_59ExecutionProofSha256 ==
                stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256,
        )
        require(
            result.activationExecutionPlanSha256 ==
                activationAuthorityPreparation.activationExecutionPlan.activationPlanSha256,
        )
        require(
            result.phase11_60ExecutionProof.activationPlanSha256 ==
                activationAuthorityPreparation.activationExecutionPlan.activationPlanSha256,
        )
        require(
            result.phase11_60ExecutionProof.stagingSyntaxExecutionProofSha256 ==
                stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256,
        )
    }

    private fun admissionSha256(
        admission: SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmission,
    ): String = digest(buildString {
        append("phase=11.74-admission\n")
        append("contractVersion=").append(admission.contractVersion).append('\n')
        append("status=").append(admission.status.name).append('\n')
        append("activationAuthority=").append(admission.policyBoundConfigActivationAuthorityPreparationResultSha256).append('\n')
        append("stagingExecution=").append(admission.policyBoundStagingSyntaxExecutionResultSha256).append('\n')
        append("selection=").append(admission.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(admission.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(admission.policyBoundConfigMutationPreparationResultSha256).append('\n')
        append("stagingAuthority=").append(admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256).append('\n')
        append("publicationPlan=").append(admission.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(admission.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(admission.readOnlyPreflightSha256).append('\n')
        append("mutationTransactionId=").append(admission.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(admission.mutationPreparationSha256).append('\n')
        append("stagingPlan=").append(admission.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(admission.phase11_59ExecutionProofSha256).append('\n')
        append("activationPlan=").append(admission.activationExecutionPlanSha256).append('\n')
        append("requiresFreshCredentialResolution=").append(admission.requiresFreshCredentialResolution).append('\n')
        append("requiresLiveRemoteHostKeyVerification=").append(admission.requiresLiveRemoteHostKeyVerification).append('\n')
        append("realVpsExecutionEligible=").append(admission.realVpsExecutionEligible).append('\n')
        append("exactConfigActivationAuthorized=").append(admission.exactConfigActivationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(admission.webServerReloadAuthorized).append('\n')
        append("certificateMutationAuthorized=").append(admission.certificateMutationAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(admission.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(admission.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(admission.packageInstallAuthorized).append('\n')
        append("privateKeyContentReadAuthorized=").append(admission.privateKeyContentReadAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(admission.automaticRetryAuthorized).append('\n')
        append("coordinatorInvoked=").append(admission.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(admission.exposesDeployUiAction).append('\n')
    })

    private fun executionResultSha256(
        result: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
    ): String = digest(buildString {
        append("phase=11.74-execution\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("admission=").append(result.admissionSha256).append('\n')
        append("activationAuthority=").append(result.policyBoundConfigActivationAuthorityPreparationResultSha256).append('\n')
        append("stagingExecution=").append(result.policyBoundStagingSyntaxExecutionResultSha256).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(result.policyBoundConfigMutationPreparationResultSha256).append('\n')
        append("stagingAuthority=").append(result.policyBoundStagingSyntaxAuthorityPreparationResultSha256).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
        append("mutationTransactionId=").append(result.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(result.mutationPreparationSha256).append('\n')
        append("stagingPlan=").append(result.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(result.phase11_59ExecutionProofSha256).append('\n')
        append("activationPlan=").append(result.activationExecutionPlanSha256).append('\n')
        append("phase11_60Proof=").append(result.phase11_60ExecutionProof.executionProofSha256).append('\n')
        append("freshCredentialResolutionProof=").append(result.freshCredentialResolutionProofSha256).append('\n')
        append("exactProductionChainBindingVerified=").append(result.exactProductionChainBindingVerified).append('\n')
        append("successfulStagingSyntaxExecutionProofValidated=").append(result.successfulStagingSyntaxExecutionProofValidated).append('\n')
        append("durablePreactivationCheckpointRecorded=").append(result.durablePreactivationCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(result.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(result.productionNetworkTouched).append('\n')
        append("liveHostKeyPinVerified=").append(result.liveHostKeyPinVerified).append('\n')
        append("exactConfigActivationPerformed=").append(result.exactConfigActivationPerformed).append('\n')
        append("exactConfigSha256Verified=").append(result.exactConfigSha256Verified).append('\n')
        append("nginxSyntaxValidationPassed=").append(result.nginxSyntaxValidationPassed).append('\n')
        append("exactConfigPathPresentAfterActivation=").append(result.exactConfigPathPresentAfterActivation).append('\n')
        append("stagingConfigAbsentAfterActivation=").append(result.stagingConfigAbsentAfterActivation).append('\n')
        append("listenerStillFreeAfterActivation=").append(result.listenerStillFreeAfterActivation).append('\n')
        append("rollbackToAbsentPerformed=").append(result.rollbackToAbsentPerformed).append('\n')
        append("webServerReloadPerformed=").append(result.webServerReloadPerformed).append('\n')
        append("certificateMutationPerformed=").append(result.certificateMutationPerformed).append('\n')
        append("dnsMutationPerformed=").append(result.dnsMutationPerformed).append('\n')
        append("firewallMutationPerformed=").append(result.firewallMutationPerformed).append('\n')
        append("packageInstallPerformed=").append(result.packageInstallPerformed).append('\n')
        append("privateKeyContentReadPerformed=").append(result.privateKeyContentReadPerformed).append('\n')
        append("automaticRetryPerformed=").append(result.automaticRetryPerformed).append('\n')
        append("coordinatorInvoked=").append(result.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(result.exposesDeployUiAction).append('\n')
    })

    private fun digest(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.encodeToByteArray())
            .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
