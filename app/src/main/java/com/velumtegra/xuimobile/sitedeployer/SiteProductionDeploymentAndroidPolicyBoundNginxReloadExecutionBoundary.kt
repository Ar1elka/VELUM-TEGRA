package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort
import java.security.MessageDigest

/**
 * Phase 11.76 makes the exact READY Phase 11.75 production-chain result mandatory before the
 * existing Phase 11.61 live nginx-reload executor may run.
 *
 * This boundary delegates exactly once to Phase 11.61 under its durable pre-reload replay fence.
 * It authorizes only one nginx reload with exact-config and listener verification. It performs no
 * config/certificate/DNS/firewall/package mutation and grants no retry/coordinator/UI authority.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        authorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
    ): SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmission {
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
            .validate(authorityPreparation)
        val reloadPlan = authorityPreparation.nginxReloadExecutionPlan
        val base = SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmissionStatus
                .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
            policyBoundNginxReloadAuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            policyBoundConfigActivationExecutionResultSha256 =
                authorityPreparation.policyBoundConfigActivationExecutionResultSha256,
            policyBoundConfigActivationAuthorityPreparationResultSha256 =
                authorityPreparation.policyBoundConfigActivationAuthorityPreparationResultSha256,
            policyBoundStagingSyntaxExecutionResultSha256 =
                authorityPreparation.policyBoundStagingSyntaxExecutionResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                authorityPreparation.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            servingPolicySelectionSha256 = authorityPreparation.servingPolicySelectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                authorityPreparation.policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                authorityPreparation.policyBoundConfigMutationPreparationResultSha256,
            publicationPlanSha256 = authorityPreparation.publicationPlanSha256,
            selectedProtocol = authorityPreparation.selectedProtocol,
            readOnlyPreflightSha256 = authorityPreparation.readOnlyPreflightSha256,
            mutationTransactionId = authorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = authorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = authorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = authorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = authorityPreparation.activationExecutionPlanSha256,
            phase11_60ExecutionProofSha256 = authorityPreparation.phase11_60ExecutionProofSha256,
            nginxReloadExecutionPlanSha256 = reloadPlan.reloadPlanSha256,
            requiresFreshCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            realVpsExecutionEligible = true,
            nginxReloadAuthorized = true,
            configMutationAuthorized = false,
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
        admission: SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort,
    ): SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.76 execution attempt id must be canonical"
        }
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
            .validateAgainst(
                result = reloadAuthorityPreparation,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
                activationExecution = activationExecution,
            )

        val expectedAdmission = admit(reloadAuthorityPreparation)
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.76 admission does not match the exact Phase 11.75 result"
        }
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.nginxReloadAuthorized)
        require(!admission.configMutationAuthorized)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val activationPlan = activationAuthorityPreparation.activationExecutionPlan
        val phase1160Proof = activationExecution.phase11_60ExecutionProof
        val reloadPlan = reloadAuthorityPreparation.nginxReloadExecutionPlan

        require(reloadAuthorityPreparation.authorityPreparationResultSha256 ==
            admission.policyBoundNginxReloadAuthorityPreparationResultSha256)
        require(activationExecution.executionResultSha256 ==
            admission.policyBoundConfigActivationExecutionResultSha256)
        require(activationAuthorityPreparation.authorityPreparationResultSha256 ==
            admission.policyBoundConfigActivationAuthorityPreparationResultSha256)
        require(stagingSyntaxExecution.executionResultSha256 ==
            admission.policyBoundStagingSyntaxExecutionResultSha256)
        require(stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256 ==
            admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256)
        require(selection.selectionSha256 == admission.servingPolicySelectionSha256)
        require(policyBoundPreflightExecution.executionResultSha256 ==
            admission.policyBoundPreflightExecutionResultSha256)
        require(policyBoundConfigMutationPreparation.preparationResultSha256 ==
            admission.policyBoundConfigMutationPreparationResultSha256)
        require(publicationPlan.publicationPlanSha256 == admission.publicationPlanSha256)
        require(requireNotNull(selection.selectedProtocol) == admission.selectedProtocol)
        require(policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256 ==
            admission.readOnlyPreflightSha256)
        require(policyBoundConfigMutationPreparation.mutationTransactionId == admission.mutationTransactionId)
        require(requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation).mutationPreparationSha256 ==
            admission.mutationPreparationSha256)
        require(requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan).executionPlanSha256 ==
            admission.stagingSyntaxExecutionPlanSha256)
        require(stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256 ==
            admission.phase11_59ExecutionProofSha256)
        require(activationPlan.activationPlanSha256 == admission.activationExecutionPlanSha256)
        require(phase1160Proof.executionProofSha256 == admission.phase11_60ExecutionProofSha256)
        require(reloadPlan.reloadPlanSha256 == admission.nginxReloadExecutionPlanSha256)

        val phase1161Proof =
            SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary.executeOnce(
                publicationPlan = publicationPlan,
                activationPlan = activationPlan,
                activationProof = phase1160Proof,
                reloadPlan = reloadPlan,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
                executionUsePort = executionUsePort,
            )
        SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
            .validateProof(phase1161Proof)

        val base = SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundNginxReloadExecutionStatus
                .NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE,
            admissionSha256 = admission.admissionSha256,
            policyBoundNginxReloadAuthorityPreparationResultSha256 =
                reloadAuthorityPreparation.authorityPreparationResultSha256,
            policyBoundConfigActivationExecutionResultSha256 = activationExecution.executionResultSha256,
            policyBoundConfigActivationAuthorityPreparationResultSha256 =
                activationAuthorityPreparation.authorityPreparationResultSha256,
            policyBoundStagingSyntaxExecutionResultSha256 = stagingSyntaxExecution.executionResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 = policyBoundPreflightExecution.executionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                policyBoundConfigMutationPreparation.preparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = requireNotNull(selection.selectedProtocol),
            readOnlyPreflightSha256 =
                policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256,
            mutationTransactionId = policyBoundConfigMutationPreparation.mutationTransactionId,
            mutationPreparationSha256 =
                requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation).mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 =
                requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan).executionPlanSha256,
            phase11_59ExecutionProofSha256 = stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256,
            activationExecutionPlanSha256 = activationPlan.activationPlanSha256,
            phase11_60ExecutionProofSha256 = phase1160Proof.executionProofSha256,
            nginxReloadExecutionPlanSha256 = reloadPlan.reloadPlanSha256,
            phase11_61ExecutionProof = phase1161Proof,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            exactProductionChainBindingVerified = true,
            successfulConfigActivationExecutionProofValidated = phase1161Proof.successfulActivationProofValidated,
            durablePreReloadCheckpointRecorded = phase1161Proof.durablePreReloadCheckpointRecorded,
            credentialLeaseMaterialConsumed = phase1161Proof.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1161Proof.productionNetworkTouched,
            liveHostKeyPinVerified = phase1161Proof.hostKeyPinVerifiedAgainstRemote,
            nginxReloadPerformed = phase1161Proof.nginxReloadPerformed,
            exactConfigSha256VerifiedBeforeReload = phase1161Proof.exactConfigSha256VerifiedBeforeReload,
            nginxSyntaxValidationPassedBeforeReload = phase1161Proof.nginxSyntaxValidationPassedBeforeReload,
            listenerFreeBeforeReload = phase1161Proof.listenerFreeBeforeReload,
            exactConfigSha256VerifiedAfterReload = phase1161Proof.exactConfigSha256VerifiedAfterReload,
            nginxMasterRunningAfterReload = phase1161Proof.nginxMasterRunningAfterReload,
            expectedListenerLiveAfterReload = phase1161Proof.expectedListenerLiveAfterReload,
            configMutationPerformed = phase1161Proof.configMutationPerformed,
            certificateMutationPerformed = false,
            dnsMutationPerformed = phase1161Proof.dnsMutationPerformed,
            firewallMutationPerformed = phase1161Proof.firewallMutationPerformed,
            packageInstallPerformed = phase1161Proof.packageInstallPerformed,
            privateKeyContentReadPerformed = phase1161Proof.privateKeyContentReadPerformed,
            automaticRetryPerformed = phase1161Proof.automaticRetryPerformed,
            coordinatorInvoked = phase1161Proof.coordinatorInvoked,
            exposesDeployUiAction = phase1161Proof.exposesDeployUiAction,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
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
                activationExecution = activationExecution,
                reloadAuthorityPreparation = reloadAuthorityPreparation,
            )
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmissionStatus
            .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION)
        listOf(
            admission.policyBoundNginxReloadAuthorityPreparationResultSha256,
            admission.policyBoundConfigActivationExecutionResultSha256,
            admission.policyBoundConfigActivationAuthorityPreparationResultSha256,
            admission.policyBoundStagingSyntaxExecutionResultSha256,
            admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            admission.servingPolicySelectionSha256,
            admission.policyBoundPreflightExecutionResultSha256,
            admission.policyBoundConfigMutationPreparationResultSha256,
            admission.publicationPlanSha256,
            admission.readOnlyPreflightSha256,
            admission.mutationPreparationSha256,
            admission.stagingSyntaxExecutionPlanSha256,
            admission.phase11_59ExecutionProofSha256,
            admission.activationExecutionPlanSha256,
            admission.phase11_60ExecutionProofSha256,
            admission.nginxReloadExecutionPlanSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.realVpsExecutionEligible)
        require(admission.nginxReloadAuthorized)
        require(!admission.configMutationAuthorized)
        require(!admission.certificateMutationAuthorized)
        require(!admission.dnsMutationAuthorized)
        require(!admission.firewallMutationAuthorized)
        require(!admission.packageInstallAuthorized)
        require(!admission.privateKeyContentReadAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(!admission.coordinatorInvoked)
        require(!admission.exposesDeployUiAction)
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = ""))) {
            "Phase 11.76 admission SHA-256 mismatch"
        }
    }

    fun validateExecutionResult(result: SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(result.status == SiteProductionDeploymentPolicyBoundNginxReloadExecutionStatus
            .NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE)
        listOf(
            result.admissionSha256,
            result.policyBoundNginxReloadAuthorityPreparationResultSha256,
            result.policyBoundConfigActivationExecutionResultSha256,
            result.policyBoundConfigActivationAuthorityPreparationResultSha256,
            result.policyBoundStagingSyntaxExecutionResultSha256,
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            result.servingPolicySelectionSha256,
            result.policyBoundPreflightExecutionResultSha256,
            result.policyBoundConfigMutationPreparationResultSha256,
            result.publicationPlanSha256,
            result.readOnlyPreflightSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.activationExecutionPlanSha256,
            result.phase11_60ExecutionProofSha256,
            result.nginxReloadExecutionPlanSha256,
            result.freshCredentialResolutionProofSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
            .validateProof(result.phase11_61ExecutionProof)
        require(result.exactProductionChainBindingVerified)
        require(result.successfulConfigActivationExecutionProofValidated)
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
        require(!result.certificateMutationPerformed)
        require(!result.dnsMutationPerformed)
        require(!result.firewallMutationPerformed)
        require(!result.packageInstallPerformed)
        require(!result.privateKeyContentReadPerformed)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(result.executionResultSha256 == executionResultSha256(result.copy(executionResultSha256 = ""))) {
            "Phase 11.76 execution-result SHA-256 mismatch"
        }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary.validateAgainst(
            result = reloadAuthorityPreparation,
            selection = selection,
            policyBoundPreflightExecution = policyBoundPreflightExecution,
            policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
            stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
            stagingSyntaxExecution = stagingSyntaxExecution,
            activationAuthorityPreparation = activationAuthorityPreparation,
            activationExecution = activationExecution,
        )
        require(result.admissionSha256 == admission.admissionSha256)
        require(result.policyBoundNginxReloadAuthorityPreparationResultSha256 ==
            reloadAuthorityPreparation.authorityPreparationResultSha256)
        val publicationPlan = requireNotNull(selection.publicationPlan)
        require(result.policyBoundConfigActivationExecutionResultSha256 == activationExecution.executionResultSha256)
        require(result.policyBoundConfigActivationAuthorityPreparationResultSha256 ==
            activationAuthorityPreparation.authorityPreparationResultSha256)
        require(result.policyBoundStagingSyntaxExecutionResultSha256 == stagingSyntaxExecution.executionResultSha256)
        require(result.policyBoundStagingSyntaxAuthorityPreparationResultSha256 ==
            stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256)
        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(result.policyBoundPreflightExecutionResultSha256 == policyBoundPreflightExecution.executionResultSha256)
        require(result.policyBoundConfigMutationPreparationResultSha256 ==
            policyBoundConfigMutationPreparation.preparationResultSha256)
        require(result.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(result.selectedProtocol == requireNotNull(selection.selectedProtocol))
        require(result.readOnlyPreflightSha256 ==
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256)
        require(result.mutationTransactionId == policyBoundConfigMutationPreparation.mutationTransactionId)
        require(result.mutationPreparationSha256 ==
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation).mutationPreparationSha256)
        require(result.stagingSyntaxExecutionPlanSha256 ==
            requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan).executionPlanSha256)
        require(result.phase11_59ExecutionProofSha256 == stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256)
        require(result.activationExecutionPlanSha256 == activationAuthorityPreparation.activationExecutionPlan.activationPlanSha256)
        require(result.phase11_60ExecutionProofSha256 == activationExecution.phase11_60ExecutionProof.executionProofSha256)
        require(result.nginxReloadExecutionPlanSha256 == reloadAuthorityPreparation.nginxReloadExecutionPlan.reloadPlanSha256)
        require(result.phase11_61ExecutionProof.reloadPlanSha256 == result.nginxReloadExecutionPlanSha256)
        require(result.phase11_61ExecutionProof.activationPlanSha256 == result.activationExecutionPlanSha256)
        require(result.phase11_61ExecutionProof.activationExecutionProofSha256 == result.phase11_60ExecutionProofSha256)
        require(result.phase11_61ExecutionProof.publicationPlanSha256 == result.publicationPlanSha256)
    }

    private fun admissionSha256(admission: SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmission): String =
        digest(buildString {
            append("phase=11.76-admission\n")
            append("contractVersion=").append(admission.contractVersion).append('\n')
            append("status=").append(admission.status.name).append('\n')
            append("reloadAuthority=").append(admission.policyBoundNginxReloadAuthorityPreparationResultSha256).append('\n')
            append("activationExecution=").append(admission.policyBoundConfigActivationExecutionResultSha256).append('\n')
            append("activationAuthority=").append(admission.policyBoundConfigActivationAuthorityPreparationResultSha256).append('\n')
            append("stagingExecution=").append(admission.policyBoundStagingSyntaxExecutionResultSha256).append('\n')
            append("stagingAuthority=").append(admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256).append('\n')
            append("selection=").append(admission.servingPolicySelectionSha256).append('\n')
            append("preflight=").append(admission.policyBoundPreflightExecutionResultSha256).append('\n')
            append("mutationPreparationResult=").append(admission.policyBoundConfigMutationPreparationResultSha256).append('\n')
            append("publicationPlan=").append(admission.publicationPlanSha256).append('\n')
            append("protocol=").append(admission.selectedProtocol.name).append('\n')
            append("readOnlyPreflight=").append(admission.readOnlyPreflightSha256).append('\n')
            append("transaction=").append(admission.mutationTransactionId).append('\n')
            append("mutationPreparation=").append(admission.mutationPreparationSha256).append('\n')
            append("stagingPlan=").append(admission.stagingSyntaxExecutionPlanSha256).append('\n')
            append("phase11_59=").append(admission.phase11_59ExecutionProofSha256).append('\n')
            append("activationPlan=").append(admission.activationExecutionPlanSha256).append('\n')
            append("phase11_60=").append(admission.phase11_60ExecutionProofSha256).append('\n')
            append("reloadPlan=").append(admission.nginxReloadExecutionPlanSha256).append('\n')
            append("requiresFreshCredential=").append(admission.requiresFreshCredentialResolution).append('\n')
            append("requiresLiveHostKey=").append(admission.requiresLiveRemoteHostKeyVerification).append('\n')
            append("realVpsEligible=").append(admission.realVpsExecutionEligible).append('\n')
            append("reloadAuthorized=").append(admission.nginxReloadAuthorized).append('\n')
            append("configMutationAuthorized=").append(admission.configMutationAuthorized).append('\n')
            append("certificateMutationAuthorized=").append(admission.certificateMutationAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(admission.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(admission.firewallMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(admission.packageInstallAuthorized).append('\n')
            append("privateKeyReadAuthorized=").append(admission.privateKeyContentReadAuthorized).append('\n')
            append("retryAuthorized=").append(admission.automaticRetryAuthorized).append('\n')
            append("coordinator=").append(admission.coordinatorInvoked).append('\n')
            append("deployUi=").append(admission.exposesDeployUiAction).append('\n')
        })

    private fun executionResultSha256(result: SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult): String =
        digest(buildString {
            append("phase=11.76-execution\n")
            append("contractVersion=").append(result.contractVersion).append('\n')
            append("status=").append(result.status.name).append('\n')
            append("admission=").append(result.admissionSha256).append('\n')
            append("reloadAuthority=").append(result.policyBoundNginxReloadAuthorityPreparationResultSha256).append('\n')
            append("activationExecution=").append(result.policyBoundConfigActivationExecutionResultSha256).append('\n')
            append("activationAuthority=").append(result.policyBoundConfigActivationAuthorityPreparationResultSha256).append('\n')
            append("stagingExecution=").append(result.policyBoundStagingSyntaxExecutionResultSha256).append('\n')
            append("stagingAuthority=").append(result.policyBoundStagingSyntaxAuthorityPreparationResultSha256).append('\n')
            append("selection=").append(result.servingPolicySelectionSha256).append('\n')
            append("preflight=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
            append("mutationPreparationResult=").append(result.policyBoundConfigMutationPreparationResultSha256).append('\n')
            append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
            append("protocol=").append(result.selectedProtocol.name).append('\n')
            append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
            append("transaction=").append(result.mutationTransactionId).append('\n')
            append("mutationPreparation=").append(result.mutationPreparationSha256).append('\n')
            append("stagingPlan=").append(result.stagingSyntaxExecutionPlanSha256).append('\n')
            append("phase11_59=").append(result.phase11_59ExecutionProofSha256).append('\n')
            append("activationPlan=").append(result.activationExecutionPlanSha256).append('\n')
            append("phase11_60=").append(result.phase11_60ExecutionProofSha256).append('\n')
            append("reloadPlan=").append(result.nginxReloadExecutionPlanSha256).append('\n')
            append("phase11_61=").append(result.phase11_61ExecutionProof.executionProofSha256).append('\n')
            append("freshResolution=").append(result.freshCredentialResolutionProofSha256).append('\n')
            append("chain=").append(result.exactProductionChainBindingVerified).append('\n')
            append("activationProof=").append(result.successfulConfigActivationExecutionProofValidated).append('\n')
            append("checkpoint=").append(result.durablePreReloadCheckpointRecorded).append('\n')
            append("credentialConsumed=").append(result.credentialLeaseMaterialConsumed).append('\n')
            append("network=").append(result.productionNetworkTouched).append('\n')
            append("hostKey=").append(result.liveHostKeyPinVerified).append('\n')
            append("reload=").append(result.nginxReloadPerformed).append('\n')
            append("shaBefore=").append(result.exactConfigSha256VerifiedBeforeReload).append('\n')
            append("syntaxBefore=").append(result.nginxSyntaxValidationPassedBeforeReload).append('\n')
            append("listenerFreeBefore=").append(result.listenerFreeBeforeReload).append('\n')
            append("shaAfter=").append(result.exactConfigSha256VerifiedAfterReload).append('\n')
            append("masterRunning=").append(result.nginxMasterRunningAfterReload).append('\n')
            append("listenerLive=").append(result.expectedListenerLiveAfterReload).append('\n')
            append("configMutation=").append(result.configMutationPerformed).append('\n')
            append("certificateMutation=").append(result.certificateMutationPerformed).append('\n')
            append("dnsMutation=").append(result.dnsMutationPerformed).append('\n')
            append("firewallMutation=").append(result.firewallMutationPerformed).append('\n')
            append("packageInstall=").append(result.packageInstallPerformed).append('\n')
            append("privateKeyRead=").append(result.privateKeyContentReadPerformed).append('\n')
            append("retry=").append(result.automaticRetryPerformed).append('\n')
            append("coordinator=").append(result.coordinatorInvoked).append('\n')
            append("deployUi=").append(result.exposesDeployUiAction).append('\n')
        })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
