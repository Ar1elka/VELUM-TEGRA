package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.security.MessageDigest

/**
 * Phase 11.77 makes the completed Phase 11.76 policy-bound reload result mandatory before the
 * existing Phase 11.62 live HTTP verification executor may run.
 *
 * The boundary is read-only with respect to the remote VPS. It binds the exact Phase 11.68-11.76
 * chain to the exact generated index.html and delegates exactly once to the bounded Phase 11.62
 * remote-loopback HTTP GET. It does not claim public Internet reachability and grants no config,
 * certificate, DNS, firewall, package, retry, coordinator or Deploy-UI authority.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        preparation: SiteDeployerLocalPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        reloadExecution: SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult,
    ): SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        val reloadAdmission =
            SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary.admit(
                reloadAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
            .validateExecutionResultAgainst(
                result = reloadExecution,
                admission = reloadAdmission,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
                activationExecution = activationExecution,
                reloadAuthorityPreparation = reloadAuthorityPreparation,
            )
        return admitValidated(
            preparation = preparation,
            selection = selection,
            reloadAuthorityPreparation = reloadAuthorityPreparation,
            policyBoundNginxReloadExecutionResultSha256 = reloadExecution.executionResultSha256,
            phase11_61ExecutionProofSha256 = reloadExecution.phase11_61ExecutionProof.executionProofSha256,
        ).also {
            require(it.policyBoundPreflightExecutionResultSha256 == policyBoundPreflightExecution.executionResultSha256)
            require(it.policyBoundConfigMutationPreparationResultSha256 == policyBoundConfigMutationPreparation.preparationResultSha256)
            require(it.policyBoundStagingSyntaxAuthorityPreparationResultSha256 == stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256)
            require(it.policyBoundStagingSyntaxExecutionResultSha256 == stagingSyntaxExecution.executionResultSha256)
            require(it.policyBoundConfigActivationAuthorityPreparationResultSha256 == activationAuthorityPreparation.authorityPreparationResultSha256)
            require(it.policyBoundConfigActivationExecutionResultSha256 == activationExecution.executionResultSha256)
        }
    }

    /** Deterministic zero-network seam after prior chain objects were validated by their owners. */
    internal fun admitValidated(
        preparation: SiteDeployerLocalPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        policyBoundNginxReloadExecutionResultSha256: String,
        phase11_61ExecutionProofSha256: String,
    ): SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary.validate(
            reloadAuthorityPreparation,
        )
        require(sha256.matches(policyBoundNginxReloadExecutionResultSha256))
        require(sha256.matches(phase11_61ExecutionProofSha256))
        require(selection.publicationPlanSelected)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val selectedProtocol = requireNotNull(selection.selectedProtocol)
        val reloadPlan = reloadAuthorityPreparation.nginxReloadExecutionPlan
        require(selectedProtocol == SiteWebServingProtocol.HTTP)
        require(publicationPlan.protocol == selectedProtocol)
        require(publicationPlan.preparationSha256 == preparation.preparationSha256)
        require(publicationPlan.sourceTreeSha256 == preparation.bundle.manifest.treeSha256)
        require(publicationPlan.targetRoot == preparation.remoteDeployPlan.publish.targetRoot)
        require(publicationPlan.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity)
        require(reloadAuthorityPreparation.publicationPlanSha256 == publicationPlan.publicationPlanSha256)

        val verificationPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
        )
        SiteWebServingLiveHttpVerificationBoundary.validateAgainst(
            verificationPlan,
            preparation,
            publicationPlan,
            reloadPlan,
        )

        val base = SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmissionStatus
                .READY_FOR_SEPARATE_REAL_VPS_LIVE_HTTP_VERIFICATION,
            policyBoundNginxReloadExecutionResultSha256 = policyBoundNginxReloadExecutionResultSha256,
            policyBoundNginxReloadAuthorityPreparationResultSha256 =
                reloadAuthorityPreparation.authorityPreparationResultSha256,
            policyBoundConfigActivationExecutionResultSha256 =
                reloadAuthorityPreparation.policyBoundConfigActivationExecutionResultSha256,
            policyBoundConfigActivationAuthorityPreparationResultSha256 =
                reloadAuthorityPreparation.policyBoundConfigActivationAuthorityPreparationResultSha256,
            policyBoundStagingSyntaxExecutionResultSha256 =
                reloadAuthorityPreparation.policyBoundStagingSyntaxExecutionResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                reloadAuthorityPreparation.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                reloadAuthorityPreparation.policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                reloadAuthorityPreparation.policyBoundConfigMutationPreparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = selectedProtocol,
            readOnlyPreflightSha256 = reloadAuthorityPreparation.readOnlyPreflightSha256,
            mutationTransactionId = reloadAuthorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = reloadAuthorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = reloadAuthorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 = reloadAuthorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = reloadAuthorityPreparation.activationExecutionPlanSha256,
            phase11_60ExecutionProofSha256 = reloadAuthorityPreparation.phase11_60ExecutionProofSha256,
            nginxReloadExecutionPlanSha256 = reloadPlan.reloadPlanSha256,
            phase11_61ExecutionProofSha256 = phase11_61ExecutionProofSha256,
            liveHttpVerificationPlanSha256 = verificationPlan.verificationPlanSha256,
            localPreparationSha256 = preparation.preparationSha256,
            expectedBodySha256 = verificationPlan.expectedBodySha256,
            expectedBodyBytes = verificationPlan.expectedBodyBytes,
            requiresFreshCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            realVpsExecutionEligible = true,
            loopbackHttpGetAuthorized = true,
            externalReachabilityClaimAuthorized = false,
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
        admission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission,
        preparation: SiteDeployerLocalPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        reloadExecution: SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.77 execution attempt id must be canonical"
        }
        validateAdmission(admission)
        val expectedAdmission = admit(
            preparation,
            selection,
            policyBoundPreflightExecution,
            policyBoundConfigMutationPreparation,
            stagingSyntaxAuthorityPreparation,
            stagingSyntaxExecution,
            activationAuthorityPreparation,
            activationExecution,
            reloadAuthorityPreparation,
            reloadExecution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.77 admission does not match the exact completed Phase 11.76 chain"
        }
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.loopbackHttpGetAuthorized)
        require(!admission.externalReachabilityClaimAuthorized)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val reloadPlan = reloadAuthorityPreparation.nginxReloadExecutionPlan
        val verificationPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
        )
        require(verificationPlan.verificationPlanSha256 == admission.liveHttpVerificationPlanSha256)
        require(verificationPlan.expectedBodySha256 == admission.expectedBodySha256)
        require(verificationPlan.expectedBodyBytes == admission.expectedBodyBytes)
        require(reloadExecution.phase11_61ExecutionProof.executionProofSha256 == admission.phase11_61ExecutionProofSha256)

        val phase1162Proof =
            SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary
                .executeOnce(
                    publicationPlan = publicationPlan,
                    reloadPlan = reloadPlan,
                    reloadProof = reloadExecution.phase11_61ExecutionProof,
                    verificationPlan = verificationPlan,
                    freshResolutionProof = freshResolutionProof,
                    freshCredentialLease = freshCredentialLease,
                    serverAccess = serverAccess,
                    executionAttemptId = executionAttemptId,
                    executedAtEpochMillis = executedAtEpochMillis,
                )
        SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary
            .validateProof(phase1162Proof)

        val base = SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionStatus
                .LIVE_HTTP_INDEX_VERIFIED_OVER_REMOTE_LOOPBACK_EXACT_BODY,
            admissionSha256 = admission.admissionSha256,
            policyBoundNginxReloadExecutionResultSha256 = reloadExecution.executionResultSha256,
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
            activationExecutionPlanSha256 = activationAuthorityPreparation.activationExecutionPlan.activationPlanSha256,
            phase11_60ExecutionProofSha256 = activationExecution.phase11_60ExecutionProof.executionProofSha256,
            nginxReloadExecutionPlanSha256 = reloadPlan.reloadPlanSha256,
            phase11_61ExecutionProofSha256 = reloadExecution.phase11_61ExecutionProof.executionProofSha256,
            liveHttpVerificationPlanSha256 = verificationPlan.verificationPlanSha256,
            localPreparationSha256 = preparation.preparationSha256,
            phase11_62ExecutionProof = phase1162Proof,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            exactProductionChainBindingVerified = true,
            successfulNginxReloadExecutionProofValidated = phase1162Proof.successfulReloadProofValidated,
            credentialLeaseMaterialConsumed = phase1162Proof.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1162Proof.productionNetworkTouched,
            liveHostKeyPinVerified = phase1162Proof.hostKeyPinVerifiedAgainstRemote,
            remoteCommandCount = phase1162Proof.remoteCommandCount,
            exactConfigSha256Verified = phase1162Proof.exactConfigSha256Verified,
            nginxMasterRunning = phase1162Proof.nginxMasterRunning,
            expectedListenerLive = phase1162Proof.expectedListenerLive,
            loopbackHttpGetPerformed = phase1162Proof.loopbackHttpGetPerformed,
            httpStatusCode = phase1162Proof.httpStatusCode,
            contentLength = phase1162Proof.contentLength,
            expectedBodyBytes = verificationPlan.expectedBodyBytes,
            expectedBodySha256 = phase1162Proof.expectedBodySha256,
            observedBodySha256 = phase1162Proof.observedBodySha256,
            exactBodySha256Verified = phase1162Proof.exactBodySha256Verified,
            externalReachabilityClaimed = phase1162Proof.externalReachabilityClaimed,
            configMutationPerformed = phase1162Proof.configMutationPerformed,
            certificateMutationPerformed = false,
            dnsMutationPerformed = phase1162Proof.dnsMutationPerformed,
            firewallMutationPerformed = phase1162Proof.firewallMutationPerformed,
            packageInstallPerformed = phase1162Proof.packageInstallPerformed,
            privateKeyContentReadPerformed = phase1162Proof.privateKeyContentReadPerformed,
            automaticRetryPerformed = phase1162Proof.automaticRetryPerformed,
            coordinatorInvoked = phase1162Proof.coordinatorInvoked,
            exposesDeployUiAction = phase1162Proof.exposesDeployUiAction,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
            validateExecutionResult(it)
            validateExecutionResultAgainst(
                result = it,
                admission = admission,
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
                activationExecution = activationExecution,
                reloadAuthorityPreparation = reloadAuthorityPreparation,
                reloadExecution = reloadExecution,
            )
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmissionStatus
            .READY_FOR_SEPARATE_REAL_VPS_LIVE_HTTP_VERIFICATION)
        listOf(
            admission.policyBoundNginxReloadExecutionResultSha256,
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
            admission.phase11_61ExecutionProofSha256,
            admission.liveHttpVerificationPlanSha256,
            admission.localPreparationSha256,
            admission.expectedBodySha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        require(admission.selectedProtocol == SiteWebServingProtocol.HTTP)
        require(admission.expectedBodyBytes > 0)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.realVpsExecutionEligible)
        require(admission.loopbackHttpGetAuthorized)
        require(!admission.externalReachabilityClaimAuthorized)
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
            "Phase 11.77 admission SHA-256 mismatch"
        }
    }

    fun validateExecutionResult(result: SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(result.status == SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionStatus
            .LIVE_HTTP_INDEX_VERIFIED_OVER_REMOTE_LOOPBACK_EXACT_BODY)
        listOf(
            result.admissionSha256,
            result.policyBoundNginxReloadExecutionResultSha256,
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
            result.phase11_61ExecutionProofSha256,
            result.liveHttpVerificationPlanSha256,
            result.localPreparationSha256,
            result.freshCredentialResolutionProofSha256,
            result.expectedBodySha256,
            result.observedBodySha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        require(result.selectedProtocol == SiteWebServingProtocol.HTTP)
        SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary
            .validateProof(result.phase11_62ExecutionProof)
        require(result.exactProductionChainBindingVerified)
        require(result.successfulNginxReloadExecutionProofValidated)
        require(result.credentialLeaseMaterialConsumed)
        require(result.productionNetworkTouched)
        require(result.liveHostKeyPinVerified)
        require(result.remoteCommandCount == 1)
        require(result.exactConfigSha256Verified)
        require(result.nginxMasterRunning)
        require(result.expectedListenerLive)
        require(result.loopbackHttpGetPerformed)
        require(result.httpStatusCode == 200)
        require(result.expectedBodyBytes > 0)
        require(result.contentLength == result.expectedBodyBytes)
        require(result.expectedBodySha256 == result.observedBodySha256)
        require(result.exactBodySha256Verified)
        require(!result.externalReachabilityClaimed)
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
            "Phase 11.77 execution-result SHA-256 mismatch"
        }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission,
        preparation: SiteDeployerLocalPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution: SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        reloadExecution: SiteProductionDeploymentPolicyBoundNginxReloadExecutionResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        val expectedAdmission = admit(
            preparation,
            selection,
            policyBoundPreflightExecution,
            policyBoundConfigMutationPreparation,
            stagingSyntaxAuthorityPreparation,
            stagingSyntaxExecution,
            activationAuthorityPreparation,
            activationExecution,
            reloadAuthorityPreparation,
            reloadExecution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256)
        val publicationPlan = requireNotNull(selection.publicationPlan)
        val reloadPlan = reloadAuthorityPreparation.nginxReloadExecutionPlan
        val verificationPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
            preparation,
            publicationPlan,
            reloadPlan,
        )
        require(result.admissionSha256 == admission.admissionSha256)
        require(result.policyBoundNginxReloadExecutionResultSha256 == reloadExecution.executionResultSha256)
        require(result.policyBoundNginxReloadAuthorityPreparationResultSha256 == reloadAuthorityPreparation.authorityPreparationResultSha256)
        require(result.policyBoundConfigActivationExecutionResultSha256 == activationExecution.executionResultSha256)
        require(result.policyBoundConfigActivationAuthorityPreparationResultSha256 == activationAuthorityPreparation.authorityPreparationResultSha256)
        require(result.policyBoundStagingSyntaxExecutionResultSha256 == stagingSyntaxExecution.executionResultSha256)
        require(result.policyBoundStagingSyntaxAuthorityPreparationResultSha256 == stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256)
        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(result.policyBoundPreflightExecutionResultSha256 == policyBoundPreflightExecution.executionResultSha256)
        require(result.policyBoundConfigMutationPreparationResultSha256 == policyBoundConfigMutationPreparation.preparationResultSha256)
        require(result.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(result.selectedProtocol == requireNotNull(selection.selectedProtocol))
        require(result.readOnlyPreflightSha256 == policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256)
        require(result.mutationTransactionId == policyBoundConfigMutationPreparation.mutationTransactionId)
        require(result.mutationPreparationSha256 == requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation).mutationPreparationSha256)
        require(result.stagingSyntaxExecutionPlanSha256 == requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan).executionPlanSha256)
        require(result.phase11_59ExecutionProofSha256 == stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256)
        require(result.activationExecutionPlanSha256 == activationAuthorityPreparation.activationExecutionPlan.activationPlanSha256)
        require(result.phase11_60ExecutionProofSha256 == activationExecution.phase11_60ExecutionProof.executionProofSha256)
        require(result.nginxReloadExecutionPlanSha256 == reloadPlan.reloadPlanSha256)
        require(result.phase11_61ExecutionProofSha256 == reloadExecution.phase11_61ExecutionProof.executionProofSha256)
        require(result.liveHttpVerificationPlanSha256 == verificationPlan.verificationPlanSha256)
        require(result.localPreparationSha256 == preparation.preparationSha256)
        require(result.phase11_62ExecutionProof.verificationPlanSha256 == verificationPlan.verificationPlanSha256)
        require(result.phase11_62ExecutionProof.reloadExecutionProofSha256 == reloadExecution.phase11_61ExecutionProof.executionProofSha256)
        require(result.phase11_62ExecutionProof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(result.expectedBodyBytes == verificationPlan.expectedBodyBytes)
        require(result.expectedBodySha256 == verificationPlan.expectedBodySha256)
    }

    private fun admissionSha256(admission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission): String =
        digest(buildString {
            append("phase=11.77-admission\n")
            append("contractVersion=").append(admission.contractVersion).append('\n')
            append("status=").append(admission.status.name).append('\n')
            append("reloadExecution=").append(admission.policyBoundNginxReloadExecutionResultSha256).append('\n')
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
            append("phase11_61=").append(admission.phase11_61ExecutionProofSha256).append('\n')
            append("verificationPlan=").append(admission.liveHttpVerificationPlanSha256).append('\n')
            append("preparation=").append(admission.localPreparationSha256).append('\n')
            append("expectedBodySha=").append(admission.expectedBodySha256).append('\n')
            append("expectedBodyBytes=").append(admission.expectedBodyBytes).append('\n')
            append("requiresFreshCredential=").append(admission.requiresFreshCredentialResolution).append('\n')
            append("requiresLiveHostKey=").append(admission.requiresLiveRemoteHostKeyVerification).append('\n')
            append("realVpsEligible=").append(admission.realVpsExecutionEligible).append('\n')
            append("loopbackGet=").append(admission.loopbackHttpGetAuthorized).append('\n')
            append("externalClaim=").append(admission.externalReachabilityClaimAuthorized).append('\n')
            append("configMutation=").append(admission.configMutationAuthorized).append('\n')
            append("certificateMutation=").append(admission.certificateMutationAuthorized).append('\n')
            append("dnsMutation=").append(admission.dnsMutationAuthorized).append('\n')
            append("firewallMutation=").append(admission.firewallMutationAuthorized).append('\n')
            append("packageInstall=").append(admission.packageInstallAuthorized).append('\n')
            append("privateKeyRead=").append(admission.privateKeyContentReadAuthorized).append('\n')
            append("retry=").append(admission.automaticRetryAuthorized).append('\n')
            append("coordinator=").append(admission.coordinatorInvoked).append('\n')
            append("deployUi=").append(admission.exposesDeployUiAction).append('\n')
        })

    private fun executionResultSha256(result: SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult): String =
        digest(buildString {
            append("phase=11.77-execution\n")
            append("contractVersion=").append(result.contractVersion).append('\n')
            append("status=").append(result.status.name).append('\n')
            append("admission=").append(result.admissionSha256).append('\n')
            append("reloadExecution=").append(result.policyBoundNginxReloadExecutionResultSha256).append('\n')
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
            append("phase11_61=").append(result.phase11_61ExecutionProofSha256).append('\n')
            append("verificationPlan=").append(result.liveHttpVerificationPlanSha256).append('\n')
            append("preparation=").append(result.localPreparationSha256).append('\n')
            append("phase11_62=").append(result.phase11_62ExecutionProof.executionProofSha256).append('\n')
            append("freshResolution=").append(result.freshCredentialResolutionProofSha256).append('\n')
            append("chain=").append(result.exactProductionChainBindingVerified).append('\n')
            append("reloadProof=").append(result.successfulNginxReloadExecutionProofValidated).append('\n')
            append("credentialConsumed=").append(result.credentialLeaseMaterialConsumed).append('\n')
            append("network=").append(result.productionNetworkTouched).append('\n')
            append("hostKey=").append(result.liveHostKeyPinVerified).append('\n')
            append("remoteCommands=").append(result.remoteCommandCount).append('\n')
            append("configSha=").append(result.exactConfigSha256Verified).append('\n')
            append("master=").append(result.nginxMasterRunning).append('\n')
            append("listener=").append(result.expectedListenerLive).append('\n')
            append("loopbackGet=").append(result.loopbackHttpGetPerformed).append('\n')
            append("httpStatus=").append(result.httpStatusCode).append('\n')
            append("contentLength=").append(result.contentLength).append('\n')
            append("expectedBytes=").append(result.expectedBodyBytes).append('\n')
            append("expectedBodySha=").append(result.expectedBodySha256).append('\n')
            append("observedBodySha=").append(result.observedBodySha256).append('\n')
            append("bodyVerified=").append(result.exactBodySha256Verified).append('\n')
            append("externalClaim=").append(result.externalReachabilityClaimed).append('\n')
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
