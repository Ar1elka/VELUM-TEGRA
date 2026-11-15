package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.security.MessageDigest

/**
 * Phase 11.92 is the final post-coordinator serving-path verification boundary.
 *
 * It consumes the exact successful Phase 11.91 reload proof and delegates exactly once to the
 * already accepted Phase 11.77, 11.78 and 11.79 read-only verifiers: remote-loopback HTTP,
 * external literal-IPv4 HTTP, then domain DNS + HTTP. No mutation authority is added here.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        preparation: SiteDeployerLocalPreparationResult,
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
        phase1191Admission: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission,
        phase1191Execution: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
    ): SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        validatePhase1191Chain(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            phase1187Execution = phase1187Execution,
            phase1188AuthorityPreparation = phase1188AuthorityPreparation,
            phase1189Execution = phase1189Execution,
            phase1190AuthorityPreparation = phase1190AuthorityPreparation,
            phase1191Admission = phase1191Admission,
            phase1191Execution = phase1191Execution,
        )

        val selection = requireNotNull(handoff.servingPolicySelection)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        require(selection.selectionSha256 == handoff.servingPolicySelectionSha256)
        val publicationPlan = requireNotNull(selection.publicationPlan)
        require(selection.selectedProtocol == SiteWebServingProtocol.HTTP)
        require(publicationPlan.preparationSha256 == preparation.preparationSha256)
        require(publicationPlan.remoteHostIdentity == handoff.remoteHostIdentity)
        require(publicationPlan.targetRoot == handoff.targetRoot)
        require(publicationPlan.publicationPlanSha256 == phase1191Execution.publicationPlanSha256)

        val phase1177Admission =
            SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary.admit(
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                stagingSyntaxAuthorityPreparation = phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                stagingSyntaxExecution = phase1187Execution.phase1172ExecutionResult,
                activationAuthorityPreparation = phase1188AuthorityPreparation.phase1173AuthorityPreparation,
                activationExecution = phase1189Execution.phase1174ExecutionResult,
                reloadAuthorityPreparation = phase1190AuthorityPreparation.phase1175AuthorityPreparation,
                reloadExecution = phase1191Execution.phase1176ExecutionResult,
            )

        val base = SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmissionStatus
                .READY_FOR_FINAL_READ_ONLY_SERVING_PATH_VERIFICATION,
            phase1191ExecutionResultSha256 = phase1191Execution.executionResultSha256,
            phase1191AdmissionSha256 = phase1191Admission.admissionSha256,
            phase1190AuthorityPreparationResultSha256 =
                phase1190AuthorityPreparation.authorityPreparationResultSha256,
            phase1189ExecutionResultSha256 = phase1189Execution.executionResultSha256,
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
            phase1176ExecutionResultSha256 = phase1191Execution.phase1176ExecutionResult.executionResultSha256,
            phase1177AdmissionSha256 = phase1177Admission.admissionSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = SiteWebServingProtocol.HTTP,
            localPreparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            domain = publicationPlan.domain,
            port = publicationPlan.port,
            expectedBodySha256 = phase1177Admission.expectedBodySha256,
            expectedBodyBytes = phase1177Admission.expectedBodyBytes,
            requiresFreshCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            loopbackHttpVerificationAuthorized = true,
            externalIpv4HttpVerificationAuthorized = true,
            domainDnsHttpVerificationAuthorized = true,
            remoteMutationAuthorized = false,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            automaticRetryAuthorized = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission,
        preparation: SiteDeployerLocalPreparationResult,
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
        phase1191Admission: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission,
        phase1191Execution: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        loopbackExecutionAttemptId: String,
        externalExecutionAttemptId: String,
        domainExecutionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentPostCoordinatorServingPathVerificationResult {
        require(canonicalId.matches(loopbackExecutionAttemptId))
        require(canonicalId.matches(externalExecutionAttemptId))
        require(canonicalId.matches(domainExecutionAttemptId))
        require(executedAtEpochMillis > 0L)
        validateAdmission(admission)
        val expectedAdmission = admit(
            preparation,
            handoff,
            phase1184Execution,
            phase1185Preparation,
            phase1186AuthorityPreparation,
            phase1187Execution,
            phase1188AuthorityPreparation,
            phase1189Execution,
            phase1190AuthorityPreparation,
            phase1191Admission,
            phase1191Execution,
        )
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.92 admission does not match the exact successful Phase 11.91 chain"
        }
        require(admission.loopbackHttpVerificationAuthorized)
        require(admission.externalIpv4HttpVerificationAuthorized)
        require(admission.domainDnsHttpVerificationAuthorized)
        require(!admission.remoteMutationAuthorized)
        require(!admission.coordinatorReinvocationAuthorized)
        require(!admission.staticPublicationReplayAuthorized)
        require(!admission.automaticRetryAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val policy69 = phase1184Execution.phase1169ExecutionResult
        val policy70 = phase1185Preparation.phase1170Preparation
        val policy71 = phase1186AuthorityPreparation.phase1171AuthorityPreparation
        val policy72 = phase1187Execution.phase1172ExecutionResult
        val policy73 = phase1188AuthorityPreparation.phase1173AuthorityPreparation
        val policy74 = phase1189Execution.phase1174ExecutionResult
        val policy75 = phase1190AuthorityPreparation.phase1175AuthorityPreparation
        val policy76 = phase1191Execution.phase1176ExecutionResult

        val phase1177Admission =
            SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary.admit(
                preparation,
                selection,
                policy69,
                policy70,
                policy71,
                policy72,
                policy73,
                policy74,
                policy75,
                policy76,
            )
        require(phase1177Admission.admissionSha256 == admission.phase1177AdmissionSha256)
        val phase1177Execution =
            SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary.executeOnce(
                admission = phase1177Admission,
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = policy69,
                policyBoundConfigMutationPreparation = policy70,
                stagingSyntaxAuthorityPreparation = policy71,
                stagingSyntaxExecution = policy72,
                activationAuthorityPreparation = policy73,
                activationExecution = policy74,
                reloadAuthorityPreparation = policy75,
                reloadExecution = policy76,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = loopbackExecutionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
            )

        val phase1178Admission =
            SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary.admit(
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = policy69,
                policyBoundConfigMutationPreparation = policy70,
                stagingSyntaxAuthorityPreparation = policy71,
                stagingSyntaxExecution = policy72,
                activationAuthorityPreparation = policy73,
                activationExecution = policy74,
                reloadAuthorityPreparation = policy75,
                reloadExecution = policy76,
                liveHttpVerificationAdmission = phase1177Admission,
                liveHttpVerificationExecution = phase1177Execution,
            )
        val phase1178Execution =
            SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary.executeOnce(
                admission = phase1178Admission,
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = policy69,
                policyBoundConfigMutationPreparation = policy70,
                stagingSyntaxAuthorityPreparation = policy71,
                stagingSyntaxExecution = policy72,
                activationAuthorityPreparation = policy73,
                activationExecution = policy74,
                reloadAuthorityPreparation = policy75,
                reloadExecution = policy76,
                liveHttpVerificationAdmission = phase1177Admission,
                liveHttpVerificationExecution = phase1177Execution,
                executionAttemptId = externalExecutionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis + 1L,
            )

        val phase1179Admission =
            SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary.admit(
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = policy69,
                policyBoundConfigMutationPreparation = policy70,
                stagingSyntaxAuthorityPreparation = policy71,
                stagingSyntaxExecution = policy72,
                activationAuthorityPreparation = policy73,
                activationExecution = policy74,
                reloadAuthorityPreparation = policy75,
                reloadExecution = policy76,
                liveHttpVerificationAdmission = phase1177Admission,
                liveHttpVerificationExecution = phase1177Execution,
                externalHttpReachabilityAdmission = phase1178Admission,
                externalHttpReachabilityExecution = phase1178Execution,
            )
        val phase1179Execution =
            SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary.executeOnce(
                admission = phase1179Admission,
                preparation = preparation,
                selection = selection,
                policyBoundPreflightExecution = policy69,
                policyBoundConfigMutationPreparation = policy70,
                stagingSyntaxAuthorityPreparation = policy71,
                stagingSyntaxExecution = policy72,
                activationAuthorityPreparation = policy73,
                activationExecution = policy74,
                reloadAuthorityPreparation = policy75,
                reloadExecution = policy76,
                liveHttpVerificationAdmission = phase1177Admission,
                liveHttpVerificationExecution = phase1177Execution,
                externalHttpReachabilityAdmission = phase1178Admission,
                externalHttpReachabilityExecution = phase1178Execution,
                executionAttemptId = domainExecutionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis + 2L,
            )

        SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary
            .validateExecutionResult(phase1177Execution)
        SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary
            .validateExecutionResult(phase1178Execution)
        SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary
            .validateExecutionResult(phase1179Execution)

        val base = SiteProductionDeploymentPostCoordinatorServingPathVerificationResult(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPostCoordinatorServingPathVerificationStatus
                .COMPLETE_SERVING_PATH_VERIFIED_LOOPBACK_EXTERNAL_IPV4_AND_DOMAIN_DNS_EXACT_BODY,
            phase1192AdmissionSha256 = admission.admissionSha256,
            phase1191ExecutionResultSha256 = phase1191Execution.executionResultSha256,
            phase1177ExecutionResultSha256 = phase1177Execution.executionResultSha256,
            phase1178AdmissionSha256 = phase1178Admission.admissionSha256,
            phase1178ExecutionResultSha256 = phase1178Execution.executionResultSha256,
            phase1179AdmissionSha256 = phase1179Admission.admissionSha256,
            phase1179ExecutionResultSha256 = phase1179Execution.executionResultSha256,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            publicationPlanSha256 = admission.publicationPlanSha256,
            selectedProtocol = admission.selectedProtocol,
            localPreparationSha256 = admission.localPreparationSha256,
            remoteHostIdentity = admission.remoteHostIdentity,
            domain = admission.domain,
            port = admission.port,
            exactPostCoordinatorChainBindingVerified = true,
            successfulNginxReloadExecutionProofValidated =
                phase1177Execution.successfulNginxReloadExecutionProofValidated,
            loopbackHttpGetPerformed = phase1177Execution.loopbackHttpGetPerformed,
            loopbackHttpStatusCode = phase1177Execution.httpStatusCode,
            loopbackExactBodySha256Verified = phase1177Execution.exactBodySha256Verified,
            externalIpv4TcpConnectPerformed = phase1178Execution.externalTcpConnectPerformed,
            externalIpv4HttpGetPerformed = phase1178Execution.externalHttpGetPerformed,
            externalIpv4HttpStatusCode = phase1178Execution.httpStatusCode,
            externalIpv4ExactBodySha256Verified = phase1178Execution.exactBodySha256Verified,
            externalIpv4ReachabilityProved = phase1178Execution.externalNetworkPathReachabilityProved,
            dnsResolutionPerformed = phase1179Execution.dnsResolutionPerformed,
            dnsResolutionInvocationCount = phase1179Execution.dnsResolutionInvocationCount,
            resolvedAddresses = phase1179Execution.resolvedAddresses,
            resolvedAddressSetContainsAcceptedIpv4 =
                phase1179Execution.resolvedAddressSetContainsAcceptedIpv4,
            selectedResolvedAddress = phase1179Execution.selectedResolvedAddress,
            domainAddressedTcpConnectPerformed = phase1179Execution.domainAddressedTcpConnectPerformed,
            domainAddressedHttpGetPerformed = phase1179Execution.domainAddressedHttpGetPerformed,
            domainHttpStatusCode = phase1179Execution.httpStatusCode,
            domainExactBodySha256Verified = phase1179Execution.exactBodySha256Verified,
            externalDomainHttpReachabilityProved = phase1179Execution.externalDomainHttpReachabilityProved,
            expectedBodyBytes = phase1179Execution.expectedBodyBytes,
            expectedBodySha256 = phase1179Execution.expectedBodySha256,
            observedBodySha256 = phase1179Execution.observedBodySha256,
            productionNetworkTouched = true,
            remoteMutationPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = false,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
            validateExecutionResult(it)
            validateExecutionResultAgainst(it, admission, phase1191Execution)
        }
    }

    fun validateAdmission(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission,
    ) {
        require(value.contractVersion == CONTRACT_VERSION)
        require(
            value.status == SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmissionStatus
                .READY_FOR_FINAL_READ_ONLY_SERVING_PATH_VERIFICATION,
        )
        listOf(
            value.phase1191ExecutionResultSha256,
            value.phase1191AdmissionSha256,
            value.phase1190AuthorityPreparationResultSha256,
            value.phase1189ExecutionResultSha256,
            value.phase1188AuthorityPreparationResultSha256,
            value.phase1187ExecutionResultSha256,
            value.phase1186AuthorityPreparationResultSha256,
            value.phase1185PreparationResultSha256,
            value.phase1184ExecutionResultSha256,
            value.phase1183HandoffSha256,
            value.phase1180ExecutionResultSha256,
            value.servingPolicySelectionSha256,
            value.phase1169ExecutionResultSha256,
            value.phase1170PreparationResultSha256,
            value.phase1171AuthorityPreparationResultSha256,
            value.phase1172ExecutionResultSha256,
            value.phase1173AuthorityPreparationResultSha256,
            value.phase1174ExecutionResultSha256,
            value.phase1175AuthorityPreparationResultSha256,
            value.phase1176ExecutionResultSha256,
            value.phase1177AdmissionSha256,
            value.publicationPlanSha256,
            value.localPreparationSha256,
            value.expectedBodySha256,
            value.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(value.selectedProtocol == SiteWebServingProtocol.HTTP)
        require(value.remoteHostIdentity.isNotBlank())
        require(value.domain.isNotBlank())
        require(value.port in 1..65535)
        require(value.expectedBodyBytes > 0)
        require(value.requiresFreshCredentialResolution)
        require(value.requiresLiveRemoteHostKeyVerification)
        require(value.loopbackHttpVerificationAuthorized)
        require(value.externalIpv4HttpVerificationAuthorized)
        require(value.domainDnsHttpVerificationAuthorized)
        require(!value.remoteMutationAuthorized)
        require(!value.coordinatorReinvocationAuthorized)
        require(!value.staticPublicationReplayAuthorized)
        require(!value.automaticRetryAuthorized)
        require(value.admissionSha256 == admissionSha256(value.copy(admissionSha256 = "")))
    }

    fun validateExecutionResult(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationResult,
    ) {
        require(value.contractVersion == CONTRACT_VERSION)
        require(
            value.status == SiteProductionDeploymentPostCoordinatorServingPathVerificationStatus
                .COMPLETE_SERVING_PATH_VERIFIED_LOOPBACK_EXTERNAL_IPV4_AND_DOMAIN_DNS_EXACT_BODY,
        )
        listOf(
            value.phase1192AdmissionSha256,
            value.phase1191ExecutionResultSha256,
            value.phase1177ExecutionResultSha256,
            value.phase1178AdmissionSha256,
            value.phase1178ExecutionResultSha256,
            value.phase1179AdmissionSha256,
            value.phase1179ExecutionResultSha256,
            value.freshCredentialResolutionProofSha256,
            value.publicationPlanSha256,
            value.localPreparationSha256,
            value.expectedBodySha256,
            value.observedBodySha256,
            value.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(value.selectedProtocol == SiteWebServingProtocol.HTTP)
        require(value.remoteHostIdentity.isNotBlank())
        require(value.domain.isNotBlank())
        require(value.port in 1..65535)
        require(value.exactPostCoordinatorChainBindingVerified)
        require(value.successfulNginxReloadExecutionProofValidated)
        require(value.loopbackHttpGetPerformed)
        require(value.loopbackHttpStatusCode == 200)
        require(value.loopbackExactBodySha256Verified)
        require(value.externalIpv4TcpConnectPerformed)
        require(value.externalIpv4HttpGetPerformed)
        require(value.externalIpv4HttpStatusCode == 200)
        require(value.externalIpv4ExactBodySha256Verified)
        require(value.externalIpv4ReachabilityProved)
        require(value.dnsResolutionPerformed)
        require(value.dnsResolutionInvocationCount == 1)
        require(value.resolvedAddresses.isNotEmpty())
        require(value.resolvedAddressSetContainsAcceptedIpv4)
        require(value.selectedResolvedAddress.isNotBlank())
        require(value.domainAddressedTcpConnectPerformed)
        require(value.domainAddressedHttpGetPerformed)
        require(value.domainHttpStatusCode == 200)
        require(value.domainExactBodySha256Verified)
        require(value.externalDomainHttpReachabilityProved)
        require(value.expectedBodyBytes > 0)
        require(value.expectedBodySha256 == value.observedBodySha256)
        require(value.productionNetworkTouched)
        require(!value.remoteMutationPerformed)
        require(!value.coordinatorReinvoked)
        require(!value.staticPublicationReplayPerformed)
        require(!value.automaticRetryPerformed)
        require(value.executionResultSha256 == executionResultSha256(value.copy(executionResultSha256 = "")))
    }

    fun validateExecutionResultAgainst(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationResult,
        admission: SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission,
        phase1191Execution: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
    ) {
        validateExecutionResult(value)
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
            .validateExecutionResult(phase1191Execution)
        require(value.phase1192AdmissionSha256 == admission.admissionSha256)
        require(value.phase1191ExecutionResultSha256 == phase1191Execution.executionResultSha256)
        require(value.publicationPlanSha256 == admission.publicationPlanSha256)
        require(value.localPreparationSha256 == admission.localPreparationSha256)
        require(value.remoteHostIdentity == admission.remoteHostIdentity)
        require(value.domain == admission.domain)
        require(value.port == admission.port)
        require(value.expectedBodyBytes == admission.expectedBodyBytes)
        require(value.expectedBodySha256 == admission.expectedBodySha256)
        require(value.phase1177ExecutionResultSha256.matches(sha256))
        require(value.phase1178ExecutionResultSha256.matches(sha256))
        require(value.phase1179ExecutionResultSha256.matches(sha256))
    }

    private fun validatePhase1191Chain(
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
        phase1191Admission: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmission,
        phase1191Execution: SiteProductionDeploymentPostCoordinatorNginxReloadExecutionResult,
    ) {
        SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1191Execution,
                admission = phase1191Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188AuthorityPreparation,
                phase1189Execution = phase1189Execution,
                phase1190AuthorityPreparation = phase1190AuthorityPreparation,
            )
        require(phase1191Execution.expectedListenerLiveAfterReload)
        require(phase1191Execution.exactConfigSha256VerifiedAfterReload)
        require(phase1191Execution.nginxMasterRunningAfterReload)
        require(!phase1191Execution.configMutationPerformed)
        require(!phase1191Execution.coordinatorReinvoked)
        require(!phase1191Execution.staticPublicationReplayPerformed)
        require(!phase1191Execution.automaticRetryPerformed)
    }

    private fun admissionSha256(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission,
    ): String = digest(buildString {
        append("phase=11.92-admission\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1191Execution=").append(value.phase1191ExecutionResultSha256).append('\n')
        append("phase1191Admission=").append(value.phase1191AdmissionSha256).append('\n')
        append("phase1190Authority=").append(value.phase1190AuthorityPreparationResultSha256).append('\n')
        append("phase1189Execution=").append(value.phase1189ExecutionResultSha256).append('\n')
        append("phase1188Authority=").append(value.phase1188AuthorityPreparationResultSha256).append('\n')
        append("phase1187Execution=").append(value.phase1187ExecutionResultSha256).append('\n')
        append("phase1186Authority=").append(value.phase1186AuthorityPreparationResultSha256).append('\n')
        append("phase1185Preparation=").append(value.phase1185PreparationResultSha256).append('\n')
        append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169=").append(value.phase1169ExecutionResultSha256).append('\n')
        append("phase1170=").append(value.phase1170PreparationResultSha256).append('\n')
        append("phase1171=").append(value.phase1171AuthorityPreparationResultSha256).append('\n')
        append("phase1172=").append(value.phase1172ExecutionResultSha256).append('\n')
        append("phase1173=").append(value.phase1173AuthorityPreparationResultSha256).append('\n')
        append("phase1174=").append(value.phase1174ExecutionResultSha256).append('\n')
        append("phase1175=").append(value.phase1175AuthorityPreparationResultSha256).append('\n')
        append("phase1176=").append(value.phase1176ExecutionResultSha256).append('\n')
        append("phase1177Admission=").append(value.phase1177AdmissionSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("protocol=").append(value.selectedProtocol.name).append('\n')
        append("preparation=").append(value.localPreparationSha256).append('\n')
        append("remoteHost=").append(value.remoteHostIdentity).append('\n')
        append("domain=").append(value.domain).append('\n')
        append("port=").append(value.port).append('\n')
        append("expectedBodySha=").append(value.expectedBodySha256).append('\n')
        append("expectedBodyBytes=").append(value.expectedBodyBytes).append('\n')
        append("freshCredential=").append(value.requiresFreshCredentialResolution).append('\n')
        append("hostKey=").append(value.requiresLiveRemoteHostKeyVerification).append('\n')
        append("loopback=").append(value.loopbackHttpVerificationAuthorized).append('\n')
        append("externalIpv4=").append(value.externalIpv4HttpVerificationAuthorized).append('\n')
        append("domainDns=").append(value.domainDnsHttpVerificationAuthorized).append('\n')
        append("mutation=").append(value.remoteMutationAuthorized).append('\n')
        append("coordinator=").append(value.coordinatorReinvocationAuthorized).append('\n')
        append("staticReplay=").append(value.staticPublicationReplayAuthorized).append('\n')
        append("retry=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun executionResultSha256(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationResult,
    ): String = digest(buildString {
        append("phase=11.92-result\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("admission=").append(value.phase1192AdmissionSha256).append('\n')
        append("phase1191=").append(value.phase1191ExecutionResultSha256).append('\n')
        append("phase1177=").append(value.phase1177ExecutionResultSha256).append('\n')
        append("phase1178Admission=").append(value.phase1178AdmissionSha256).append('\n')
        append("phase1178=").append(value.phase1178ExecutionResultSha256).append('\n')
        append("phase1179Admission=").append(value.phase1179AdmissionSha256).append('\n')
        append("phase1179=").append(value.phase1179ExecutionResultSha256).append('\n')
        append("credential=").append(value.freshCredentialResolutionProofSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("protocol=").append(value.selectedProtocol.name).append('\n')
        append("preparation=").append(value.localPreparationSha256).append('\n')
        append("remoteHost=").append(value.remoteHostIdentity).append('\n')
        append("domain=").append(value.domain).append('\n')
        append("port=").append(value.port).append('\n')
        append("chain=").append(value.exactPostCoordinatorChainBindingVerified).append('\n')
        append("reloadProof=").append(value.successfulNginxReloadExecutionProofValidated).append('\n')
        append("loopbackGet=").append(value.loopbackHttpGetPerformed).append('\n')
        append("loopbackStatus=").append(value.loopbackHttpStatusCode).append('\n')
        append("loopbackBody=").append(value.loopbackExactBodySha256Verified).append('\n')
        append("externalTcp=").append(value.externalIpv4TcpConnectPerformed).append('\n')
        append("externalGet=").append(value.externalIpv4HttpGetPerformed).append('\n')
        append("externalStatus=").append(value.externalIpv4HttpStatusCode).append('\n')
        append("externalBody=").append(value.externalIpv4ExactBodySha256Verified).append('\n')
        append("externalReachability=").append(value.externalIpv4ReachabilityProved).append('\n')
        append("dns=").append(value.dnsResolutionPerformed).append('\n')
        append("dnsCount=").append(value.dnsResolutionInvocationCount).append('\n')
        append("resolved=").append(value.resolvedAddresses.joinToString(",")).append('\n')
        append("containsIpv4=").append(value.resolvedAddressSetContainsAcceptedIpv4).append('\n')
        append("selectedAddress=").append(value.selectedResolvedAddress).append('\n')
        append("domainTcp=").append(value.domainAddressedTcpConnectPerformed).append('\n')
        append("domainGet=").append(value.domainAddressedHttpGetPerformed).append('\n')
        append("domainStatus=").append(value.domainHttpStatusCode).append('\n')
        append("domainBody=").append(value.domainExactBodySha256Verified).append('\n')
        append("domainReachability=").append(value.externalDomainHttpReachabilityProved).append('\n')
        append("expectedBytes=").append(value.expectedBodyBytes).append('\n')
        append("expectedSha=").append(value.expectedBodySha256).append('\n')
        append("observedSha=").append(value.observedBodySha256).append('\n')
        append("network=").append(value.productionNetworkTouched).append('\n')
        append("mutation=").append(value.remoteMutationPerformed).append('\n')
        append("coordinator=").append(value.coordinatorReinvoked).append('\n')
        append("staticReplay=").append(value.staticPublicationReplayPerformed).append('\n')
        append("retry=").append(value.automaticRetryPerformed).append('\n')
    })

    internal fun admissionSha256ForTest(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission,
    ): String = admissionSha256(value.copy(admissionSha256 = ""))

    internal fun executionResultSha256ForTest(
        value: SiteProductionDeploymentPostCoordinatorServingPathVerificationResult,
    ): String = executionResultSha256(value.copy(executionResultSha256 = ""))

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
