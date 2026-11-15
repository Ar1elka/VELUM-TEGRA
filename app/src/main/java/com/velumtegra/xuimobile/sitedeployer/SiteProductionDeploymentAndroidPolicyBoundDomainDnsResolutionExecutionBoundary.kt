package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteWebServingDomainDnsResolutionVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingExternalHttpReachabilityVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.security.MessageDigest

/**
 * Phase 11.79 makes the completed Phase 11.78 literal-IPv4 external exact-body proof mandatory
 * before exactly one existing Phase 11.64 Android DNS/domain HTTP verifier may run.
 *
 * This boundary authorizes one bounded resolution of the exact normalized publication domain and
 * one HTTP GET through the matching resolved InetAddress. It does not authorize DNS-provider
 * mutation/automation, general resolver-consistency claims, config/firewall/package/TLS mutation,
 * arbitrary commands, automatic retry, coordinator or Deploy UI authority.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary {
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
        externalHttpReachabilityAdmission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission,
        externalHttpReachabilityExecution: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult,
    ): SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission {
        SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary
            .validateExecutionResultAgainst(
                result = externalHttpReachabilityExecution,
                admission = externalHttpReachabilityAdmission,
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
        require(externalHttpReachabilityExecution.admissionSha256 == externalHttpReachabilityAdmission.admissionSha256)
        return admitValidated(
            preparation = preparation,
            selection = selection,
            reloadAuthorityPreparation = reloadAuthorityPreparation,
            externalHttpReachabilityAdmission = externalHttpReachabilityAdmission,
            policyBoundExternalHttpReachabilityExecutionResultSha256 =
                externalHttpReachabilityExecution.executionResultSha256,
            phase11_63ExecutionProofSha256 =
                externalHttpReachabilityExecution.phase11_63ExecutionProof.executionProofSha256,
        )
    }

    /** Deterministic zero-network seam after the accepted Phase 11.78 identity has been validated. */
    internal fun admitValidated(
        preparation: SiteDeployerLocalPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        reloadAuthorityPreparation: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        externalHttpReachabilityAdmission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission,
        policyBoundExternalHttpReachabilityExecutionResultSha256: String,
        phase11_63ExecutionProofSha256: String,
    ): SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary.validate(
            reloadAuthorityPreparation,
        )
        SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary
            .validateAdmission(externalHttpReachabilityAdmission)
        require(sha256.matches(policyBoundExternalHttpReachabilityExecutionResultSha256))
        require(sha256.matches(phase11_63ExecutionProofSha256))
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
        val externalPlan = SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            loopbackVerificationPlan = loopbackPlan,
        )
        require(externalHttpReachabilityAdmission.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(externalHttpReachabilityAdmission.liveHttpVerificationPlanSha256 == loopbackPlan.verificationPlanSha256)
        require(externalHttpReachabilityAdmission.externalHttpVerificationPlanSha256 == externalPlan.verificationPlanSha256)
        require(externalHttpReachabilityAdmission.localPreparationSha256 == preparation.preparationSha256)
        require(externalHttpReachabilityAdmission.expectedBodySha256 == externalPlan.expectedBodySha256)
        require(externalHttpReachabilityAdmission.expectedBodyBytes == externalPlan.expectedBodyBytes)
        require(externalHttpReachabilityAdmission.externalNetworkPathReachabilityClaimAuthorized)
        require(!externalHttpReachabilityAdmission.dnsResolutionAuthorized)

        val dnsPlan = SiteWebServingDomainDnsResolutionVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            loopbackVerificationPlan = loopbackPlan,
            externalVerificationPlan = externalPlan,
        )
        SiteWebServingDomainDnsResolutionVerificationBoundary.validateAgainst(
            plan = dnsPlan,
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            loopbackVerificationPlan = loopbackPlan,
            externalVerificationPlan = externalPlan,
        )

        val base = SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmissionStatus
                .READY_FOR_ONE_ANDROID_DOMAIN_DNS_AND_HTTP_VERIFICATION,
            policyBoundExternalHttpReachabilityExecutionResultSha256 =
                policyBoundExternalHttpReachabilityExecutionResultSha256,
            policyBoundExternalHttpReachabilityAdmissionSha256 = externalHttpReachabilityAdmission.admissionSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            liveHttpVerificationPlanSha256 = loopbackPlan.verificationPlanSha256,
            externalHttpVerificationPlanSha256 = externalPlan.verificationPlanSha256,
            phase11_63ExecutionProofSha256 = phase11_63ExecutionProofSha256,
            domainDnsVerificationPlanSha256 = dnsPlan.verificationPlanSha256,
            localPreparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = dnsPlan.remoteHostIdentity,
            acceptedTargetIpv4Literal = dnsPlan.acceptedTargetIpv4Literal,
            domain = dnsPlan.domain,
            port = dnsPlan.port,
            requestPath = dnsPlan.requestPath,
            expectedBodySha256 = dnsPlan.expectedBodySha256,
            expectedBodyBytes = dnsPlan.expectedBodyBytes,
            requiresSuccessfulPolicyBoundExternalIpv4Proof = true,
            normalizedPublicationDomainRequired = true,
            dnsResolutionOnceAuthorized = true,
            maxResolvedAddresses = dnsPlan.maxResolvedAddresses,
            requiresResolvedAddressSetContainsAcceptedIpv4 = true,
            domainAddressedTcpConnectOnceAuthorized = true,
            domainAddressedHttpGetOnceAuthorized = true,
            exactHostHeaderRequired = true,
            acceptEncodingIdentityRequired = true,
            requiresHttpStatus200 = true,
            requiresContentLengthMatch = true,
            requiresNoTransferEncoding = true,
            requiresIdentityContentEncoding = true,
            requiresExactBodySha256 = true,
            dnsResolutionClaimAuthorized = true,
            externalDomainHttpReachabilityClaimAuthorized = true,
            generalResolverConsistencyClaimAuthorized = false,
            broaderInternetAvailabilityClaimAuthorized = false,
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
        admission: SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission,
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
        externalHttpReachabilityAdmission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission,
        externalHttpReachabilityExecution: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionResult {
        require(canonicalId.matches(executionAttemptId)) { "Phase 11.79 execution attempt id must be canonical" }
        require(executedAtEpochMillis > 0L)
        validateAdmission(admission)
        val expectedAdmission = admit(
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
            externalHttpReachabilityAdmission = externalHttpReachabilityAdmission,
            externalHttpReachabilityExecution = externalHttpReachabilityExecution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.79 admission does not match the exact completed Phase 11.78 chain"
        }
        require(admission.dnsResolutionOnceAuthorized)
        require(admission.domainAddressedTcpConnectOnceAuthorized)
        require(admission.domainAddressedHttpGetOnceAuthorized)
        require(admission.dnsResolutionClaimAuthorized)
        require(admission.externalDomainHttpReachabilityClaimAuthorized)
        require(!admission.generalResolverConsistencyClaimAuthorized)
        require(!admission.broaderInternetAvailabilityClaimAuthorized)
        require(!admission.dnsMutationAuthorized)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val reloadPlan = reloadAuthorityPreparation.nginxReloadExecutionPlan
        val loopbackPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
        )
        val externalPlan = SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            loopbackVerificationPlan = loopbackPlan,
        )
        val dnsPlan = SiteWebServingDomainDnsResolutionVerificationBoundary.prepare(
            preparation = preparation,
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            loopbackVerificationPlan = loopbackPlan,
            externalVerificationPlan = externalPlan,
        )
        require(dnsPlan.verificationPlanSha256 == admission.domainDnsVerificationPlanSha256)
        require(externalHttpReachabilityExecution.phase11_63ExecutionProof.executionProofSha256 == admission.phase11_63ExecutionProofSha256)
        require(externalHttpReachabilityExecution.executionResultSha256 == admission.policyBoundExternalHttpReachabilityExecutionResultSha256)

        val phase1164Proof =
            SiteProductionDeploymentAndroidDomainDnsResolutionVerificationExecutionBoundary.executeOnce(
                publicationPlan = publicationPlan,
                loopbackVerificationPlan = loopbackPlan,
                externalVerificationPlan = externalPlan,
                externalProof = externalHttpReachabilityExecution.phase11_63ExecutionProof,
                verificationPlan = dnsPlan,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidDomainDnsResolutionVerificationExecutionBoundary.validateProof(phase1164Proof)

        val base = SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionStatus
                .DOMAIN_DNS_AND_HTTP_INDEX_VERIFIED_FROM_ANDROID_EXACT_BODY,
            admissionSha256 = admission.admissionSha256,
            policyBoundExternalHttpReachabilityExecutionResultSha256 = externalHttpReachabilityExecution.executionResultSha256,
            policyBoundExternalHttpReachabilityAdmissionSha256 = externalHttpReachabilityAdmission.admissionSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            liveHttpVerificationPlanSha256 = loopbackPlan.verificationPlanSha256,
            externalHttpVerificationPlanSha256 = externalPlan.verificationPlanSha256,
            phase11_63ExecutionProofSha256 = externalHttpReachabilityExecution.phase11_63ExecutionProof.executionProofSha256,
            domainDnsVerificationPlanSha256 = dnsPlan.verificationPlanSha256,
            phase11_64ExecutionProof = phase1164Proof,
            localPreparationSha256 = preparation.preparationSha256,
            exactProductionChainBindingVerified = true,
            dnsResolutionPerformed = phase1164Proof.dnsResolutionPerformed,
            dnsResolutionClaimed = phase1164Proof.dnsResolutionClaimed,
            dnsResolutionInvocationCount = phase1164Proof.dnsResolutionInvocationCount,
            resolvedAddresses = phase1164Proof.resolvedAddresses,
            resolvedAddressSetContainsAcceptedIpv4 = phase1164Proof.resolvedAddressSetContainsAcceptedIpv4,
            selectedResolvedAddress = phase1164Proof.selectedResolvedAddress,
            domainAddressedTcpConnectPerformed = phase1164Proof.domainAddressedTcpConnectPerformed,
            domainAddressedHttpGetPerformed = phase1164Proof.domainAddressedHttpGetPerformed,
            httpStatusCode = phase1164Proof.httpStatusCode,
            contentLength = phase1164Proof.contentLength,
            expectedBodyBytes = phase1164Proof.expectedBodyBytes,
            expectedBodySha256 = phase1164Proof.expectedBodySha256,
            observedBodySha256 = phase1164Proof.observedBodySha256,
            exactBodySha256Verified = phase1164Proof.exactBodySha256Verified,
            externalDomainHttpReachabilityProved = phase1164Proof.externalDomainHttpReachabilityProved,
            generalResolverConsistencyClaimed = false,
            broaderInternetAvailabilityClaimed = false,
            dnsMutationPerformed = phase1164Proof.dnsMutationPerformed,
            firewallMutationPerformed = phase1164Proof.firewallMutationPerformed,
            httpsUsed = phase1164Proof.httpsUsed,
            httpsClaimed = phase1164Proof.httpsClaimed,
            configMutationPerformed = phase1164Proof.configMutationPerformed,
            certificateMutationPerformed = false,
            packageInstallPerformed = phase1164Proof.packageInstallPerformed,
            privateKeyContentReadPerformed = false,
            automaticRetryPerformed = phase1164Proof.automaticRetryPerformed,
            coordinatorInvoked = phase1164Proof.coordinatorInvoked,
            exposesDeployUiAction = phase1164Proof.exposesDeployUiAction,
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
                externalHttpReachabilityAdmission = externalHttpReachabilityAdmission,
                externalHttpReachabilityExecution = externalHttpReachabilityExecution,
            )
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmissionStatus
            .READY_FOR_ONE_ANDROID_DOMAIN_DNS_AND_HTTP_VERIFICATION)
        listOf(
            admission.policyBoundExternalHttpReachabilityExecutionResultSha256,
            admission.policyBoundExternalHttpReachabilityAdmissionSha256,
            admission.publicationPlanSha256,
            admission.liveHttpVerificationPlanSha256,
            admission.externalHttpVerificationPlanSha256,
            admission.phase11_63ExecutionProofSha256,
            admission.domainDnsVerificationPlanSha256,
            admission.localPreparationSha256,
            admission.expectedBodySha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(admission.remoteHostIdentity == admission.acceptedTargetIpv4Literal)
        SiteWebServingExternalHttpReachabilityVerificationBoundary.literalIpv4Bytes(admission.acceptedTargetIpv4Literal)
        require(admission.domain.isNotBlank() && admission.domain != admission.acceptedTargetIpv4Literal)
        require(admission.port in 1..65535)
        require(admission.requestPath == "/index.html")
        require(admission.expectedBodyBytes > 0)
        require(admission.requiresSuccessfulPolicyBoundExternalIpv4Proof)
        require(admission.normalizedPublicationDomainRequired)
        require(admission.dnsResolutionOnceAuthorized)
        require(admission.maxResolvedAddresses == SiteWebServingDomainDnsResolutionVerificationBoundary.MAX_RESOLVED_ADDRESSES)
        require(admission.requiresResolvedAddressSetContainsAcceptedIpv4)
        require(admission.domainAddressedTcpConnectOnceAuthorized)
        require(admission.domainAddressedHttpGetOnceAuthorized)
        require(admission.exactHostHeaderRequired)
        require(admission.acceptEncodingIdentityRequired)
        require(admission.requiresHttpStatus200)
        require(admission.requiresContentLengthMatch)
        require(admission.requiresNoTransferEncoding)
        require(admission.requiresIdentityContentEncoding)
        require(admission.requiresExactBodySha256)
        require(admission.dnsResolutionClaimAuthorized)
        require(admission.externalDomainHttpReachabilityClaimAuthorized)
        require(!admission.generalResolverConsistencyClaimAuthorized)
        require(!admission.broaderInternetAvailabilityClaimAuthorized)
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

    fun validateExecutionResult(result: SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(result.status == SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionStatus
            .DOMAIN_DNS_AND_HTTP_INDEX_VERIFIED_FROM_ANDROID_EXACT_BODY)
        listOf(
            result.admissionSha256,
            result.policyBoundExternalHttpReachabilityExecutionResultSha256,
            result.policyBoundExternalHttpReachabilityAdmissionSha256,
            result.publicationPlanSha256,
            result.liveHttpVerificationPlanSha256,
            result.externalHttpVerificationPlanSha256,
            result.phase11_63ExecutionProofSha256,
            result.domainDnsVerificationPlanSha256,
            result.localPreparationSha256,
            result.expectedBodySha256,
            result.observedBodySha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        SiteProductionDeploymentAndroidDomainDnsResolutionVerificationExecutionBoundary
            .validateProof(result.phase11_64ExecutionProof)
        require(result.phase11_64ExecutionProof.verificationPlanSha256 == result.domainDnsVerificationPlanSha256)
        require(result.phase11_64ExecutionProof.publicationPlanSha256 == result.publicationPlanSha256)
        require(result.phase11_64ExecutionProof.externalVerificationPlanSha256 == result.externalHttpVerificationPlanSha256)
        require(result.phase11_64ExecutionProof.externalExecutionProofSha256 == result.phase11_63ExecutionProofSha256)
        require(result.exactProductionChainBindingVerified)
        require(result.dnsResolutionPerformed)
        require(result.dnsResolutionClaimed)
        require(result.dnsResolutionInvocationCount == 1)
        require(result.resolvedAddresses.isNotEmpty())
        require(result.resolvedAddresses.size <= SiteWebServingDomainDnsResolutionVerificationBoundary.MAX_RESOLVED_ADDRESSES)
        require(result.resolvedAddresses == result.resolvedAddresses.distinct().sorted())
        require(result.resolvedAddressSetContainsAcceptedIpv4)
        require(result.selectedResolvedAddress == result.phase11_64ExecutionProof.acceptedTargetIpv4Literal)
        require(result.domainAddressedTcpConnectPerformed)
        require(result.domainAddressedHttpGetPerformed)
        require(result.httpStatusCode == 200)
        require(result.expectedBodyBytes > 0)
        require(result.contentLength == result.expectedBodyBytes)
        require(result.expectedBodySha256 == result.observedBodySha256)
        require(result.exactBodySha256Verified)
        require(result.externalDomainHttpReachabilityProved)
        require(!result.generalResolverConsistencyClaimed)
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
        result: SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission,
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
        externalHttpReachabilityAdmission: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityAdmission,
        externalHttpReachabilityExecution: SiteProductionDeploymentPolicyBoundExternalHttpReachabilityExecutionResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        val expectedAdmission = admit(
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
            externalHttpReachabilityAdmission = externalHttpReachabilityAdmission,
            externalHttpReachabilityExecution = externalHttpReachabilityExecution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256)
        require(result.admissionSha256 == admission.admissionSha256)
        require(result.policyBoundExternalHttpReachabilityExecutionResultSha256 == externalHttpReachabilityExecution.executionResultSha256)
        require(result.policyBoundExternalHttpReachabilityAdmissionSha256 == externalHttpReachabilityAdmission.admissionSha256)
        require(result.publicationPlanSha256 == admission.publicationPlanSha256)
        require(result.liveHttpVerificationPlanSha256 == admission.liveHttpVerificationPlanSha256)
        require(result.externalHttpVerificationPlanSha256 == admission.externalHttpVerificationPlanSha256)
        require(result.phase11_63ExecutionProofSha256 == externalHttpReachabilityExecution.phase11_63ExecutionProof.executionProofSha256)
        require(result.domainDnsVerificationPlanSha256 == admission.domainDnsVerificationPlanSha256)
        require(result.localPreparationSha256 == preparation.preparationSha256)
        require(result.expectedBodySha256 == admission.expectedBodySha256)
        require(result.expectedBodyBytes == admission.expectedBodyBytes)
        require(result.phase11_64ExecutionProof.expectedBodySha256 == admission.expectedBodySha256)
        require(result.phase11_64ExecutionProof.expectedBodyBytes == admission.expectedBodyBytes)
    }

    private fun admissionSha256(admission: SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmission): String =
        digest(buildString {
            append("phase=11.79-admission\n")
            append("contractVersion=").append(admission.contractVersion).append('\n')
            append("status=").append(admission.status.name).append('\n')
            append("phase11_78Execution=").append(admission.policyBoundExternalHttpReachabilityExecutionResultSha256).append('\n')
            append("phase11_78Admission=").append(admission.policyBoundExternalHttpReachabilityAdmissionSha256).append('\n')
            append("publicationPlan=").append(admission.publicationPlanSha256).append('\n')
            append("loopbackPlan=").append(admission.liveHttpVerificationPlanSha256).append('\n')
            append("externalPlan=").append(admission.externalHttpVerificationPlanSha256).append('\n')
            append("phase11_63=").append(admission.phase11_63ExecutionProofSha256).append('\n')
            append("dnsPlan=").append(admission.domainDnsVerificationPlanSha256).append('\n')
            append("preparation=").append(admission.localPreparationSha256).append('\n')
            append("remoteHost=").append(admission.remoteHostIdentity).append('\n')
            append("acceptedIpv4=").append(admission.acceptedTargetIpv4Literal).append('\n')
            append("domain=").append(admission.domain).append('\n')
            append("port=").append(admission.port).append('\n')
            append("path=").append(admission.requestPath).append('\n')
            append("expectedSha=").append(admission.expectedBodySha256).append('\n')
            append("expectedBytes=").append(admission.expectedBodyBytes).append('\n')
            append("requiresExternal=").append(admission.requiresSuccessfulPolicyBoundExternalIpv4Proof).append('\n')
            append("normalizedDomain=").append(admission.normalizedPublicationDomainRequired).append('\n')
            append("dnsOnce=").append(admission.dnsResolutionOnceAuthorized).append('\n')
            append("maxAddresses=").append(admission.maxResolvedAddresses).append('\n')
            append("containsIpv4=").append(admission.requiresResolvedAddressSetContainsAcceptedIpv4).append('\n')
            append("tcpOnce=").append(admission.domainAddressedTcpConnectOnceAuthorized).append('\n')
            append("getOnce=").append(admission.domainAddressedHttpGetOnceAuthorized).append('\n')
            append("hostHeader=").append(admission.exactHostHeaderRequired).append('\n')
            append("identityRequest=").append(admission.acceptEncodingIdentityRequired).append('\n')
            append("status200=").append(admission.requiresHttpStatus200).append('\n')
            append("contentLength=").append(admission.requiresContentLengthMatch).append('\n')
            append("noTransferEncoding=").append(admission.requiresNoTransferEncoding).append('\n')
            append("identityContent=").append(admission.requiresIdentityContentEncoding).append('\n')
            append("bodySha=").append(admission.requiresExactBodySha256).append('\n')
            append("dnsClaim=").append(admission.dnsResolutionClaimAuthorized).append('\n')
            append("domainClaim=").append(admission.externalDomainHttpReachabilityClaimAuthorized).append('\n')
            append("resolverConsistencyClaim=").append(admission.generalResolverConsistencyClaimAuthorized).append('\n')
            append("broadInternetClaim=").append(admission.broaderInternetAvailabilityClaimAuthorized).append('\n')
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

    private fun executionResultSha256(result: SiteProductionDeploymentPolicyBoundDomainDnsResolutionExecutionResult): String =
        digest(buildString {
            append("phase=11.79-execution\n")
            append("contractVersion=").append(result.contractVersion).append('\n')
            append("status=").append(result.status.name).append('\n')
            append("admission=").append(result.admissionSha256).append('\n')
            append("phase11_78Execution=").append(result.policyBoundExternalHttpReachabilityExecutionResultSha256).append('\n')
            append("phase11_78Admission=").append(result.policyBoundExternalHttpReachabilityAdmissionSha256).append('\n')
            append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
            append("loopbackPlan=").append(result.liveHttpVerificationPlanSha256).append('\n')
            append("externalPlan=").append(result.externalHttpVerificationPlanSha256).append('\n')
            append("phase11_63=").append(result.phase11_63ExecutionProofSha256).append('\n')
            append("dnsPlan=").append(result.domainDnsVerificationPlanSha256).append('\n')
            append("phase11_64=").append(result.phase11_64ExecutionProof.executionProofSha256).append('\n')
            append("preparation=").append(result.localPreparationSha256).append('\n')
            append("chain=").append(result.exactProductionChainBindingVerified).append('\n')
            append("dnsPerformed=").append(result.dnsResolutionPerformed).append('\n')
            append("dnsClaimed=").append(result.dnsResolutionClaimed).append('\n')
            append("dnsCount=").append(result.dnsResolutionInvocationCount).append('\n')
            append("addresses=").append(result.resolvedAddresses.joinToString(",")).append('\n')
            append("containsIpv4=").append(result.resolvedAddressSetContainsAcceptedIpv4).append('\n')
            append("selected=").append(result.selectedResolvedAddress).append('\n')
            append("tcp=").append(result.domainAddressedTcpConnectPerformed).append('\n')
            append("get=").append(result.domainAddressedHttpGetPerformed).append('\n')
            append("statusCode=").append(result.httpStatusCode).append('\n')
            append("contentLength=").append(result.contentLength).append('\n')
            append("expectedBytes=").append(result.expectedBodyBytes).append('\n')
            append("expectedSha=").append(result.expectedBodySha256).append('\n')
            append("observedSha=").append(result.observedBodySha256).append('\n')
            append("bodyVerified=").append(result.exactBodySha256Verified).append('\n')
            append("domainPath=").append(result.externalDomainHttpReachabilityProved).append('\n')
            append("resolverConsistencyClaim=").append(result.generalResolverConsistencyClaimed).append('\n')
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
