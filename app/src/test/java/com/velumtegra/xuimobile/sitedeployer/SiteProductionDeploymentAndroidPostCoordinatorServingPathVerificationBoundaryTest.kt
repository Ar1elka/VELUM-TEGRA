package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import org.junit.Assert.assertThrows
import org.junit.Test

class SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundaryTest {
    private fun h(ch: Char): String = ch.toString().repeat(64)

    private fun admission(): SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission {
        val draft = SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission(
            contractVersion = 1,
            status = SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmissionStatus
                .READY_FOR_FINAL_READ_ONLY_SERVING_PATH_VERIFICATION,
            phase1191ExecutionResultSha256 = h('1'),
            phase1191AdmissionSha256 = h('2'),
            phase1190AuthorityPreparationResultSha256 = h('3'),
            phase1189ExecutionResultSha256 = h('4'),
            phase1188AuthorityPreparationResultSha256 = h('5'),
            phase1187ExecutionResultSha256 = h('6'),
            phase1186AuthorityPreparationResultSha256 = h('7'),
            phase1185PreparationResultSha256 = h('8'),
            phase1184ExecutionResultSha256 = h('9'),
            phase1183HandoffSha256 = h('a'),
            phase1180ExecutionResultSha256 = h('b'),
            servingPolicySelectionSha256 = h('c'),
            phase1169ExecutionResultSha256 = h('d'),
            phase1170PreparationResultSha256 = h('e'),
            phase1171AuthorityPreparationResultSha256 = h('f'),
            phase1172ExecutionResultSha256 = h('0'),
            phase1173AuthorityPreparationResultSha256 = h('1'),
            phase1174ExecutionResultSha256 = h('2'),
            phase1175AuthorityPreparationResultSha256 = h('3'),
            phase1176ExecutionResultSha256 = h('4'),
            phase1177AdmissionSha256 = h('5'),
            publicationPlanSha256 = h('6'),
            selectedProtocol = SiteWebServingProtocol.HTTP,
            localPreparationSha256 = h('7'),
            remoteHostIdentity = "192.0.2.169",
            domain = "192-0-2-169.nip.io",
            port = 58492,
            expectedBodySha256 = h('8'),
            expectedBodyBytes = 321,
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
        return draft.copy(
            admissionSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary
                .admissionSha256ForTest(draft),
        )
    }

    private fun result(
        admission: SiteProductionDeploymentPostCoordinatorServingPathVerificationAdmission,
    ): SiteProductionDeploymentPostCoordinatorServingPathVerificationResult {
        val draft = SiteProductionDeploymentPostCoordinatorServingPathVerificationResult(
            contractVersion = 1,
            status = SiteProductionDeploymentPostCoordinatorServingPathVerificationStatus
                .COMPLETE_SERVING_PATH_VERIFIED_LOOPBACK_EXTERNAL_IPV4_AND_DOMAIN_DNS_EXACT_BODY,
            phase1192AdmissionSha256 = admission.admissionSha256,
            phase1191ExecutionResultSha256 = admission.phase1191ExecutionResultSha256,
            phase1177ExecutionResultSha256 = h('9'),
            phase1178AdmissionSha256 = h('a'),
            phase1178ExecutionResultSha256 = h('b'),
            phase1179AdmissionSha256 = h('c'),
            phase1179ExecutionResultSha256 = h('d'),
            freshCredentialResolutionProofSha256 = h('e'),
            publicationPlanSha256 = admission.publicationPlanSha256,
            selectedProtocol = SiteWebServingProtocol.HTTP,
            localPreparationSha256 = admission.localPreparationSha256,
            remoteHostIdentity = admission.remoteHostIdentity,
            domain = admission.domain,
            port = admission.port,
            exactPostCoordinatorChainBindingVerified = true,
            successfulNginxReloadExecutionProofValidated = true,
            loopbackHttpGetPerformed = true,
            loopbackHttpStatusCode = 200,
            loopbackExactBodySha256Verified = true,
            externalIpv4TcpConnectPerformed = true,
            externalIpv4HttpGetPerformed = true,
            externalIpv4HttpStatusCode = 200,
            externalIpv4ExactBodySha256Verified = true,
            externalIpv4ReachabilityProved = true,
            dnsResolutionPerformed = true,
            dnsResolutionInvocationCount = 1,
            resolvedAddresses = listOf("192.0.2.169"),
            resolvedAddressSetContainsAcceptedIpv4 = true,
            selectedResolvedAddress = "192.0.2.169",
            domainAddressedTcpConnectPerformed = true,
            domainAddressedHttpGetPerformed = true,
            domainHttpStatusCode = 200,
            domainExactBodySha256Verified = true,
            externalDomainHttpReachabilityProved = true,
            expectedBodyBytes = admission.expectedBodyBytes,
            expectedBodySha256 = admission.expectedBodySha256,
            observedBodySha256 = admission.expectedBodySha256,
            productionNetworkTouched = true,
            remoteMutationPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = false,
            executionResultSha256 = "",
        )
        return draft.copy(
            executionResultSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary
                .executionResultSha256ForTest(draft),
        )
    }

    @Test
    fun validFinalReadOnlyAdmissionAndResultAreAccepted() {
        val admission = admission()
        val result = result(admission)
        SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.validateAdmission(admission)
        SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.validateExecutionResult(result)
    }

    @Test
    fun admissionRejectsMutationOrRetryAuthority() {
        val original = admission()
        val mutated = original.copy(remoteMutationAuthorized = true, admissionSha256 = "")
        val sealed = mutated.copy(
            admissionSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary
                .admissionSha256ForTest(mutated),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.validateAdmission(sealed)
        }
    }

    @Test
    fun resultRejectsMissingDomainProofOrHashDrift() {
        val admission = admission()
        val original = result(admission)
        val badClaim = original.copy(
            externalDomainHttpReachabilityProved = false,
            executionResultSha256 = "",
        ).let { it.copy(
            executionResultSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary
                .executionResultSha256ForTest(it),
        ) }
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.validateExecutionResult(badClaim)
        }

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.validateExecutionResult(
                original.copy(observedBodySha256 = h('f')),
            )
        }
    }
}
