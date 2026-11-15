package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteWebServingExternalHttpReachabilityVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.security.MessageDigest

/**
 * Phase 11.78 makes the completed Phase 11.77 policy-bound loopback exact-body proof mandatory
 * before exactly one existing Phase 11.63 Android external IPv4 HTTP verifier may run.
 *
 * The socket target is the exact literal VPS IPv4 already bound into the accepted publication plan;
 * therefore this boundary performs no DNS resolution. It grants no config/certificate/DNS/firewall/
 * package/TLS mutation, no arbitrary remote command, no automatic retry, no coordinator and no UI.
 * Success proves only one external network path from this Android device at that moment, not general
 * Internet availability from other networks.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary {
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
        liveHttpVerificationAdmission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission,
        liveHttpVerificationExecution: SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult,
    ): SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission {
        SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary
            .validateExecutionResultAgainst(
                result = liveHttpVerificationExecution,
                admission = liveHttpVerificationAdmission,
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
        require(liveHttpVerificationExecution.admissionSha256 == liveHttpVerificationAdmission.admissionSha256)
        return admitValidated(
            preparation = preparation,
            selection = selection,
            reloadAuthorityPreparation = reloadAuthorityPreparation,
            liveHttpVerificationAdmission = liveHttpVerificationAdmission,
            policyBoundLiveHttpVerificationExecutionResultSha256 =
                liveHttpVerificationExecution.executionResultSha256,
            phase11_62ExecutionProofSha256 =
                liveHttpVerificationExecution.phase11_62ExecutionProof.executionProofSha256,
        )
    }

    /** Deterministic zero-network seam after the accepted Phase 11.77 identity has been validated. */
    internal fun admitValidated(
        preparation: SiteDeployerLocalPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        liveHttpVerificationAdmission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission,
        policyBoundLiveHttpVerificationExecutionResultSha256: String,
        phase11_62ExecutionProofSha256: String,
    ): SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary.validate(
            reloadAuthorityPreparation,
        )
        SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary
            .validateAdmission(liveHttpVerificationAdmission)
        require(sha256.matches(policyBoundLiveHttpVerificationExecutionResultSha256))
        require(sha256.matches(phase11_62ExecutionProofSha256))
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

        val loopbackPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
        )
        SiteWebServingLiveHttpVerificationBoundary.validateAgainst(
            loopbackPlan,
            preparation,
            publicationPlan,
            reloadPlan,
        )
        require(liveHttpVerificationAdmission.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(liveHttpVerificationAdmission.liveHttpVerificationPlanSha256 == loopbackPlan.verificationPlanSha256)
        require(liveHttpVerificationAdmission.localPreparationSha256 == preparation.preparationSha256)
        require(liveHttpVerificationAdmission.expectedBodySha256 == loopbackPlan.expectedBodySha256)
        require(liveHttpVerificationAdmission.expectedBodyBytes == loopbackPlan.expectedBodyBytes)
        require(!liveHttpVerificationAdmission.externalReachabilityClaimAuthorized)

        val externalPlan = SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            loopbackVerificationPlan = loopbackPlan,
        )
        SiteWebServingExternalHttpReachabilityVerificationBoundary.validateAgainst(
            externalPlan,
            preparation,
            publicationPlan,
            reloadPlan,
            loopbackPlan,
        )

        val base = SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmissionStatus
                .READY_FOR_ONE_ANDROID_EXTERNAL_IPV4_HTTP_VERIFICATION,
            policyBoundLiveHttpVerificationExecutionResultSha256 =
                policyBoundLiveHttpVerificationExecutionResultSha256,
            policyBoundLiveHttpVerificationAdmissionSha256 = liveHttpVerificationAdmission.admissionSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            liveHttpVerificationPlanSha256 = loopbackPlan.verificationPlanSha256,
            phase11_62ExecutionProofSha256 = phase11_62ExecutionProofSha256,
            externalHttpVerificationPlanSha256 = externalPlan.verificationPlanSha256,
            localPreparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = externalPlan.remoteHostIdentity,
            targetIpv4Literal = externalPlan.targetIpv4Literal,
            domain = externalPlan.domain,
            port = externalPlan.port,
            requestPath = externalPlan.requestPath,
            expectedBodySha256 = externalPlan.expectedBodySha256,
            expectedBodyBytes = externalPlan.expectedBodyBytes,
            requiresSuccessfulPolicyBoundLoopbackProof = true,
            literalIpv4TargetRequired = true,
            externalTcpConnectOnceAuthorized = true,
            externalHttpGetOnceAuthorized = true,
            exactHostHeaderRequired = true,
            acceptEncodingIdentityRequired = true,
            requiresHttpStatus200 = true,
            requiresContentLengthMatch = true,
            requiresNoTransferEncoding = true,
            requiresIdentityContentEncoding = true,
            requiresExactBodySha256 = true,
            externalNetworkPathReachabilityClaimAuthorized = true,
            broaderInternetAvailabilityClaimAuthorized = false,
            dnsResolutionAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            httpsAuthorized = false,
            configMutationAuthorized = false,
            certificateMutationAuthorized = false,
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
        admission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission,
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
        liveHttpVerificationAdmission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission,
        liveHttpVerificationExecution: SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult {
        require(canonicalId.matches(executionAttemptId)) { "Phase 11.78 execution attempt id must be canonical" }
        require(executedAtEpochMillis > 0L)
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
            liveHttpVerificationAdmission,
            liveHttpVerificationExecution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.78 admission does not match the exact completed Phase 11.77 chain"
        }
        require(admission.externalTcpConnectOnceAuthorized)
        require(admission.externalHttpGetOnceAuthorized)
        require(admission.externalNetworkPathReachabilityClaimAuthorized)
        require(!admission.broaderInternetAvailabilityClaimAuthorized)
        require(!admission.dnsResolutionAuthorized)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val reloadPlan = reloadAuthorityPreparation.nginxReloadExecutionPlan
        val loopbackPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
            preparation,
            publicationPlan,
            reloadPlan,
        )
        val externalPlan = SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
            preparation,
            publicationPlan,
            reloadPlan,
            loopbackPlan,
        )
        require(externalPlan.verificationPlanSha256 == admission.externalHttpVerificationPlanSha256)
        require(externalPlan.targetIpv4Literal == admission.targetIpv4Literal)
        require(externalPlan.expectedBodySha256 == admission.expectedBodySha256)
        require(externalPlan.expectedBodyBytes == admission.expectedBodyBytes)
        require(liveHttpVerificationExecution.phase11_62ExecutionProof.executionProofSha256 == admission.phase11_62ExecutionProofSha256)

        val phase1163Proof =
            SiteProductionDeploymentAndroidExternalHttpReachabilityVerificationExecutionBoundary.executeOnce(
                publicationPlan = publicationPlan,
                loopbackVerificationPlan = loopbackPlan,
                loopbackProof = liveHttpVerificationExecution.phase11_62ExecutionProof,
                verificationPlan = externalPlan,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidExternalHttpReachabilityVerificationExecutionBoundary
            .validateProof(phase1163Proof)

        val base = SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionStatus
                .EXTERNAL_HTTP_INDEX_VERIFIED_FROM_ANDROID_IPV4_EXACT_BODY,
            admissionSha256 = admission.admissionSha256,
            policyBoundLiveHttpVerificationExecutionResultSha256 = liveHttpVerificationExecution.executionResultSha256,
            policyBoundLiveHttpVerificationAdmissionSha256 = liveHttpVerificationAdmission.admissionSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            liveHttpVerificationPlanSha256 = loopbackPlan.verificationPlanSha256,
            phase11_62ExecutionProofSha256 = liveHttpVerificationExecution.phase11_62ExecutionProof.executionProofSha256,
            externalHttpVerificationPlanSha256 = externalPlan.verificationPlanSha256,
            phase11_63ExecutionProof = phase1163Proof,
            localPreparationSha256 = preparation.preparationSha256,
            exactProductionChainBindingVerified = true,
            externalTcpConnectPerformed = phase1163Proof.externalTcpConnectPerformed,
            externalHttpGetPerformed = phase1163Proof.externalHttpGetPerformed,
            httpStatusCode = phase1163Proof.httpStatusCode,
            contentLength = phase1163Proof.contentLength,
            expectedBodyBytes = phase1163Proof.expectedBodyBytes,
            expectedBodySha256 = phase1163Proof.expectedBodySha256,
            observedBodySha256 = phase1163Proof.observedBodySha256,
            exactBodySha256Verified = phase1163Proof.exactBodySha256Verified,
            externalNetworkPathReachabilityProved = phase1163Proof.externalNetworkPathReachabilityProved,
            dnsResolutionPerformed = phase1163Proof.dnsResolutionPerformed,
            dnsResolutionClaimed = phase1163Proof.dnsResolutionClaimed,
            broaderInternetAvailabilityClaimed = false,
            dnsMutationPerformed = phase1163Proof.dnsMutationPerformed,
            firewallMutationPerformed = phase1163Proof.firewallMutationPerformed,
            httpsUsed = phase1163Proof.httpsUsed,
            httpsClaimed = phase1163Proof.httpsClaimed,
            configMutationPerformed = phase1163Proof.configMutationPerformed,
            certificateMutationPerformed = false,
            packageInstallPerformed = phase1163Proof.packageInstallPerformed,
            privateKeyContentReadPerformed = false,
            automaticRetryPerformed = phase1163Proof.automaticRetryPerformed,
            coordinatorInvoked = phase1163Proof.coordinatorInvoked,
            exposesDeployUiAction = phase1163Proof.exposesDeployUiAction,
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
                liveHttpVerificationAdmission = liveHttpVerificationAdmission,
                liveHttpVerificationExecution = liveHttpVerificationExecution,
            )
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmissionStatus
            .READY_FOR_ONE_ANDROID_EXTERNAL_IPV4_HTTP_VERIFICATION)
        listOf(
            admission.policyBoundLiveHttpVerificationExecutionResultSha256,
            admission.policyBoundLiveHttpVerificationAdmissionSha256,
            admission.publicationPlanSha256,
            admission.liveHttpVerificationPlanSha256,
            admission.phase11_62ExecutionProofSha256,
            admission.externalHttpVerificationPlanSha256,
            admission.localPreparationSha256,
            admission.expectedBodySha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(admission.remoteHostIdentity == admission.targetIpv4Literal)
        SiteWebServingExternalHttpReachabilityVerificationBoundary.literalIpv4Bytes(admission.targetIpv4Literal)
        require(admission.domain.isNotBlank())
        require(admission.port in 1..65535)
        require(admission.requestPath == "/index.html")
        require(admission.expectedBodyBytes > 0)
        require(admission.requiresSuccessfulPolicyBoundLoopbackProof)
        require(admission.literalIpv4TargetRequired)
        require(admission.externalTcpConnectOnceAuthorized)
        require(admission.externalHttpGetOnceAuthorized)
        require(admission.exactHostHeaderRequired)
        require(admission.acceptEncodingIdentityRequired)
        require(admission.requiresHttpStatus200)
        require(admission.requiresContentLengthMatch)
        require(admission.requiresNoTransferEncoding)
        require(admission.requiresIdentityContentEncoding)
        require(admission.requiresExactBodySha256)
        require(admission.externalNetworkPathReachabilityClaimAuthorized)
        require(!admission.broaderInternetAvailabilityClaimAuthorized)
        require(!admission.dnsResolutionAuthorized)
        require(!admission.dnsMutationAuthorized)
        require(!admission.firewallMutationAuthorized)
        require(!admission.httpsAuthorized)
        require(!admission.configMutationAuthorized)
        require(!admission.certificateMutationAuthorized)
        require(!admission.packageInstallAuthorized)
        require(!admission.privateKeyContentReadAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(!admission.coordinatorInvoked)
        require(!admission.exposesDeployUiAction)
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = "")))
    }

    fun validateExecutionResult(result: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(result.status == SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionStatus
            .EXTERNAL_HTTP_INDEX_VERIFIED_FROM_ANDROID_IPV4_EXACT_BODY)
        listOf(
            result.admissionSha256,
            result.policyBoundLiveHttpVerificationExecutionResultSha256,
            result.policyBoundLiveHttpVerificationAdmissionSha256,
            result.publicationPlanSha256,
            result.liveHttpVerificationPlanSha256,
            result.phase11_62ExecutionProofSha256,
            result.externalHttpVerificationPlanSha256,
            result.localPreparationSha256,
            result.expectedBodySha256,
            result.observedBodySha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        SiteProductionDeploymentAndroidExternalHttpReachabilityVerificationExecutionBoundary
            .validateProof(result.phase11_63ExecutionProof)
        require(result.phase11_63ExecutionProof.verificationPlanSha256 == result.externalHttpVerificationPlanSha256)
        require(result.phase11_63ExecutionProof.publicationPlanSha256 == result.publicationPlanSha256)
        require(result.phase11_63ExecutionProof.loopbackVerificationPlanSha256 == result.liveHttpVerificationPlanSha256)
        require(result.phase11_63ExecutionProof.loopbackExecutionProofSha256 == result.phase11_62ExecutionProofSha256)
        require(result.exactProductionChainBindingVerified)
        require(result.externalTcpConnectPerformed)
        require(result.externalHttpGetPerformed)
        require(result.httpStatusCode == 200)
        require(result.expectedBodyBytes > 0)
        require(result.contentLength == result.expectedBodyBytes)
        require(result.expectedBodySha256 == result.observedBodySha256)
        require(result.exactBodySha256Verified)
        require(result.externalNetworkPathReachabilityProved)
        require(!result.dnsResolutionPerformed)
        require(!result.dnsResolutionClaimed)
        require(!result.broaderInternetAvailabilityClaimed)
        require(!result.dnsMutationPerformed)
        require(!result.firewallMutationPerformed)
        require(!result.httpsUsed)
        require(!result.httpsClaimed)
        require(!result.configMutationPerformed)
        require(!result.certificateMutationPerformed)
        require(!result.packageInstallPerformed)
        require(!result.privateKeyContentReadPerformed)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(result.executionResultSha256 == executionResultSha256(result.copy(executionResultSha256 = "")))
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission,
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
        liveHttpVerificationAdmission: SiteProductionDeploymentPolicyBoundLiveHttpVerificationAdmission,
        liveHttpVerificationExecution: SiteProductionDeploymentPolicyBoundLiveHttpVerificationExecutionResult,
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
            liveHttpVerificationAdmission,
            liveHttpVerificationExecution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256)
        require(result.admissionSha256 == admission.admissionSha256)
        require(result.policyBoundLiveHttpVerificationExecutionResultSha256 == liveHttpVerificationExecution.executionResultSha256)
        require(result.policyBoundLiveHttpVerificationAdmissionSha256 == liveHttpVerificationAdmission.admissionSha256)
        require(result.publicationPlanSha256 == admission.publicationPlanSha256)
        require(result.liveHttpVerificationPlanSha256 == admission.liveHttpVerificationPlanSha256)
        require(result.phase11_62ExecutionProofSha256 == liveHttpVerificationExecution.phase11_62ExecutionProof.executionProofSha256)
        require(result.externalHttpVerificationPlanSha256 == admission.externalHttpVerificationPlanSha256)
        require(result.localPreparationSha256 == preparation.preparationSha256)
        require(result.expectedBodySha256 == admission.expectedBodySha256)
        require(result.expectedBodyBytes == admission.expectedBodyBytes)
        require(result.phase11_63ExecutionProof.expectedBodySha256 == admission.expectedBodySha256)
        require(result.phase11_63ExecutionProof.expectedBodyBytes == admission.expectedBodyBytes)
    }

    private fun admissionSha256(admission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission): String =
        digest(buildString {
            append("phase=11.78-admission\n")
            append("contractVersion=").append(admission.contractVersion).append('\n')
            append("status=").append(admission.status.name).append('\n')
            append("phase11_77Execution=").append(admission.policyBoundLiveHttpVerificationExecutionResultSha256).append('\n')
            append("phase11_77Admission=").append(admission.policyBoundLiveHttpVerificationAdmissionSha256).append('\n')
            append("publicationPlan=").append(admission.publicationPlanSha256).append('\n')
            append("loopbackPlan=").append(admission.liveHttpVerificationPlanSha256).append('\n')
            append("phase11_62=").append(admission.phase11_62ExecutionProofSha256).append('\n')
            append("externalPlan=").append(admission.externalHttpVerificationPlanSha256).append('\n')
            append("preparation=").append(admission.localPreparationSha256).append('\n')
            append("remoteHost=").append(admission.remoteHostIdentity).append('\n')
            append("targetIpv4=").append(admission.targetIpv4Literal).append('\n')
            append("domain=").append(admission.domain).append('\n')
            append("port=").append(admission.port).append('\n')
            append("path=").append(admission.requestPath).append('\n')
            append("expectedSha=").append(admission.expectedBodySha256).append('\n')
            append("expectedBytes=").append(admission.expectedBodyBytes).append('\n')
            append("requiresLoopback=").append(admission.requiresSuccessfulPolicyBoundLoopbackProof).append('\n')
            append("literalIpv4=").append(admission.literalIpv4TargetRequired).append('\n')
            append("tcpOnce=").append(admission.externalTcpConnectOnceAuthorized).append('\n')
            append("getOnce=").append(admission.externalHttpGetOnceAuthorized).append('\n')
            append("hostHeader=").append(admission.exactHostHeaderRequired).append('\n')
            append("identityRequest=").append(admission.acceptEncodingIdentityRequired).append('\n')
            append("status200=").append(admission.requiresHttpStatus200).append('\n')
            append("contentLength=").append(admission.requiresContentLengthMatch).append('\n')
            append("noTransferEncoding=").append(admission.requiresNoTransferEncoding).append('\n')
            append("identityContent=").append(admission.requiresIdentityContentEncoding).append('\n')
            append("bodySha=").append(admission.requiresExactBodySha256).append('\n')
            append("externalClaim=").append(admission.externalNetworkPathReachabilityClaimAuthorized).append('\n')
            append("broadInternetClaim=").append(admission.broaderInternetAvailabilityClaimAuthorized).append('\n')
            append("dnsResolution=").append(admission.dnsResolutionAuthorized).append('\n')
            append("dnsMutation=").append(admission.dnsMutationAuthorized).append('\n')
            append("firewallMutation=").append(admission.firewallMutationAuthorized).append('\n')
            append("https=").append(admission.httpsAuthorized).append('\n')
            append("configMutation=").append(admission.configMutationAuthorized).append('\n')
            append("certificateMutation=").append(admission.certificateMutationAuthorized).append('\n')
            append("packageInstall=").append(admission.packageInstallAuthorized).append('\n')
            append("privateKeyRead=").append(admission.privateKeyContentReadAuthorized).append('\n')
            append("retry=").append(admission.automaticRetryAuthorized).append('\n')
            append("coordinator=").append(admission.coordinatorInvoked).append('\n')
            append("deployUi=").append(admission.exposesDeployUiAction).append('\n')
        })

    private fun executionResultSha256(result: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult): String =
        digest(buildString {
            append("phase=11.78-execution\n")
            append("contractVersion=").append(result.contractVersion).append('\n')
            append("status=").append(result.status.name).append('\n')
            append("admission=").append(result.admissionSha256).append('\n')
            append("phase11_77Execution=").append(result.policyBoundLiveHttpVerificationExecutionResultSha256).append('\n')
            append("phase11_77Admission=").append(result.policyBoundLiveHttpVerificationAdmissionSha256).append('\n')
            append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
            append("loopbackPlan=").append(result.liveHttpVerificationPlanSha256).append('\n')
            append("phase11_62=").append(result.phase11_62ExecutionProofSha256).append('\n')
            append("externalPlan=").append(result.externalHttpVerificationPlanSha256).append('\n')
            append("phase11_63=").append(result.phase11_63ExecutionProof.executionProofSha256).append('\n')
            append("preparation=").append(result.localPreparationSha256).append('\n')
            append("chain=").append(result.exactProductionChainBindingVerified).append('\n')
            append("tcp=").append(result.externalTcpConnectPerformed).append('\n')
            append("get=").append(result.externalHttpGetPerformed).append('\n')
            append("statusCode=").append(result.httpStatusCode).append('\n')
            append("contentLength=").append(result.contentLength).append('\n')
            append("expectedBytes=").append(result.expectedBodyBytes).append('\n')
            append("expectedSha=").append(result.expectedBodySha256).append('\n')
            append("observedSha=").append(result.observedBodySha256).append('\n')
            append("bodyVerified=").append(result.exactBodySha256Verified).append('\n')
            append("externalPath=").append(result.externalNetworkPathReachabilityProved).append('\n')
            append("dnsResolution=").append(result.dnsResolutionPerformed).append('\n')
            append("dnsClaim=").append(result.dnsResolutionClaimed).append('\n')
            append("broadInternetClaim=").append(result.broaderInternetAvailabilityClaimed).append('\n')
            append("dnsMutation=").append(result.dnsMutationPerformed).append('\n')
            append("firewallMutation=").append(result.firewallMutationPerformed).append('\n')
            append("httpsUsed=").append(result.httpsUsed).append('\n')
            append("httpsClaimed=").append(result.httpsClaimed).append('\n')
            append("configMutation=").append(result.configMutationPerformed).append('\n')
            append("certificateMutation=").append(result.certificateMutationPerformed).append('\n')
            append("packageInstall=").append(result.packageInstallPerformed).append('\n')
            append("privateKeyRead=").append(result.privateKeyContentReadPerformed).append('\n')
            append("retry=").append(result.automaticRetryPerformed).append('\n')
            append("coordinator=").append(result.coordinatorInvoked).append('\n')
            append("deployUi=").append(result.exposesDeployUiAction).append('\n')
        })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
