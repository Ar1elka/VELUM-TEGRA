package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingDomainDnsResolutionVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingExternalHttpReachabilityVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingListenerState
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightTrust
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundaryTest {
    @Test
    fun `validated Phase 11_78 seam creates one exact bounded DNS domain admission`() {
        val (root, local) = prepare()
        try {
            val selection = selection(local)
            val preflightAdmission = SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(selection)
            val report = preflight(selection)
            val preflightSha = "a".repeat(64)
            val phase1170 = SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.prepareValidated(
                selection = selection,
                admission = preflightAdmission,
                readOnlyPreflight = report,
                policyBoundPreflightExecutionResultSha256 = preflightSha,
                mutationTransactionId = "phase11_79_tx_ready",
            )
            val phase1171 = SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary.prepareValidated(
                selection = selection,
                policyBoundPreflightExecutionResultSha256 = preflightSha,
                policyBoundConfigMutationPreparation = phase1170,
                readOnlyPreflight = report,
            )
            val phase1173 = SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary.prepareValidated(
                selection = selection,
                policyBoundPreflightExecutionResultSha256 = preflightSha,
                policyBoundConfigMutationPreparation = phase1170,
                stagingSyntaxAuthorityPreparation = phase1171,
                policyBoundStagingSyntaxExecutionResultSha256 = "b".repeat(64),
                phase11_59ExecutionProofSha256 = "c".repeat(64),
                readOnlyPreflight = report,
            )
            val phase1175 = SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary.prepareValidated(
                selection = selection,
                activationAuthorityPreparation = phase1173,
                policyBoundConfigActivationExecutionResultSha256 = "d".repeat(64),
                phase11_60ExecutionProofSha256 = "e".repeat(64),
            )
            val phase1177Admission = SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary.admitValidated(
                preparation = local,
                selection = selection,
                reloadAuthorityPreparation = phase1175,
                policyBoundNginxReloadExecutionResultSha256 = "f".repeat(64),
                phase11_61ExecutionProofSha256 = "1".repeat(64),
            )
            val phase1178Admission = SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary.admitValidated(
                preparation = local,
                selection = selection,
                reloadAuthorityPreparation = phase1175,
                liveHttpVerificationAdmission = phase1177Admission,
                policyBoundLiveHttpVerificationExecutionResultSha256 = "2".repeat(64),
                phase11_62ExecutionProofSha256 = "3".repeat(64),
            )
            val admission = SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary.admitValidated(
                preparation = local,
                selection = selection,
                reloadAuthorityPreparation = phase1175,
                externalHttpReachabilityAdmission = phase1178Admission,
                policyBoundExternalHttpReachabilityExecutionResultSha256 = "4".repeat(64),
                phase11_63ExecutionProofSha256 = "5".repeat(64),
            )
            val publicationPlan = requireNotNull(selection.publicationPlan)
            val loopbackPlan = SiteWebServingLiveHttpVerificationBoundary.prepare(
                local,
                publicationPlan,
                phase1175.nginxReloadExecutionPlan,
            )
            val externalPlan = SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
                local,
                publicationPlan,
                phase1175.nginxReloadExecutionPlan,
                loopbackPlan,
            )
            val dnsPlan = SiteWebServingDomainDnsResolutionVerificationBoundary.prepare(
                local,
                publicationPlan,
                phase1175.nginxReloadExecutionPlan,
                loopbackPlan,
                externalPlan,
            )

            assertEquals(
                SiteProductionDeploymentPolicyBoundDomainDnsResolutionAdmissionStatus
                    .READY_FOR_ONE_ANDROID_DOMAIN_DNS_AND_HTTP_VERIFICATION,
                admission.status,
            )
            assertEquals("4".repeat(64), admission.policyBoundExternalHttpReachabilityExecutionResultSha256)
            assertEquals("5".repeat(64), admission.phase11_63ExecutionProofSha256)
            assertEquals(phase1178Admission.admissionSha256, admission.policyBoundExternalHttpReachabilityAdmissionSha256)
            assertEquals(dnsPlan.verificationPlanSha256, admission.domainDnsVerificationPlanSha256)
            assertEquals(dnsPlan.acceptedTargetIpv4Literal, admission.acceptedTargetIpv4Literal)
            assertEquals(dnsPlan.domain, admission.domain)
            assertEquals(dnsPlan.port, admission.port)
            assertEquals(dnsPlan.expectedBodySha256, admission.expectedBodySha256)
            assertEquals(dnsPlan.expectedBodyBytes, admission.expectedBodyBytes)
            assertTrue(admission.requiresSuccessfulPolicyBoundExternalIpv4Proof)
            assertTrue(admission.normalizedPublicationDomainRequired)
            assertTrue(admission.dnsResolutionOnceAuthorized)
            assertEquals(SiteWebServingDomainDnsResolutionVerificationBoundary.MAX_RESOLVED_ADDRESSES, admission.maxResolvedAddresses)
            assertTrue(admission.requiresResolvedAddressSetContainsAcceptedIpv4)
            assertTrue(admission.domainAddressedTcpConnectOnceAuthorized)
            assertTrue(admission.domainAddressedHttpGetOnceAuthorized)
            assertTrue(admission.exactHostHeaderRequired)
            assertTrue(admission.acceptEncodingIdentityRequired)
            assertTrue(admission.requiresHttpStatus200)
            assertTrue(admission.requiresContentLengthMatch)
            assertTrue(admission.requiresNoTransferEncoding)
            assertTrue(admission.requiresIdentityContentEncoding)
            assertTrue(admission.requiresExactBodySha256)
            assertTrue(admission.dnsResolutionClaimAuthorized)
            assertTrue(admission.externalDomainHttpReachabilityClaimAuthorized)
            assertFalse(admission.generalResolverConsistencyClaimAuthorized)
            assertFalse(admission.broaderInternetAvailabilityClaimAuthorized)
            assertFalse(admission.dnsMutationAuthorized)
            assertFalse(admission.firewallMutationAuthorized)
            assertFalse(admission.httpsAuthorized)
            assertFalse(admission.configMutationAuthorized)
            assertFalse(admission.certificateMutationAuthorized)
            assertFalse(admission.packageInstallAuthorized)
            assertFalse(admission.privateKeyContentReadAuthorized)
            assertFalse(admission.automaticRetryAuthorized)
            assertFalse(admission.coordinatorInvoked)
            assertFalse(admission.exposesDeployUiAction)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `tampered Phase 11_79 DNS bound fails closed`() {
        val (root, local) = prepare()
        try {
            val selection = selection(local)
            val preflightAdmission = SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(selection)
            val report = preflight(selection)
            val preflightSha = "6".repeat(64)
            val phase1170 = SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.prepareValidated(
                selection = selection,
                admission = preflightAdmission,
                readOnlyPreflight = report,
                policyBoundPreflightExecutionResultSha256 = preflightSha,
                mutationTransactionId = "phase11_79_tx_tamper",
            )
            val phase1171 = SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary.prepareValidated(
                selection = selection,
                policyBoundPreflightExecutionResultSha256 = preflightSha,
                policyBoundConfigMutationPreparation = phase1170,
                readOnlyPreflight = report,
            )
            val phase1173 = SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary.prepareValidated(
                selection = selection,
                policyBoundPreflightExecutionResultSha256 = preflightSha,
                policyBoundConfigMutationPreparation = phase1170,
                stagingSyntaxAuthorityPreparation = phase1171,
                policyBoundStagingSyntaxExecutionResultSha256 = "7".repeat(64),
                phase11_59ExecutionProofSha256 = "8".repeat(64),
                readOnlyPreflight = report,
            )
            val phase1175 = SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary.prepareValidated(
                selection = selection,
                activationAuthorityPreparation = phase1173,
                policyBoundConfigActivationExecutionResultSha256 = "9".repeat(64),
                phase11_60ExecutionProofSha256 = "a".repeat(64),
            )
            val phase1177Admission = SiteProductionDeploymentAndroidPolicyBoundLiveHttpVerificationExecutionBoundary.admitValidated(
                preparation = local,
                selection = selection,
                reloadAuthorityPreparation = phase1175,
                policyBoundNginxReloadExecutionResultSha256 = "b".repeat(64),
                phase11_61ExecutionProofSha256 = "c".repeat(64),
            )
            val phase1178Admission = SiteProductionDeploymentAndroidPolicyBoundExternalHttpReachabilityExecutionBoundary.admitValidated(
                preparation = local,
                selection = selection,
                reloadAuthorityPreparation = phase1175,
                liveHttpVerificationAdmission = phase1177Admission,
                policyBoundLiveHttpVerificationExecutionResultSha256 = "d".repeat(64),
                phase11_62ExecutionProofSha256 = "e".repeat(64),
            )
            val exact = SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary.admitValidated(
                preparation = local,
                selection = selection,
                reloadAuthorityPreparation = phase1175,
                externalHttpReachabilityAdmission = phase1178Admission,
                policyBoundExternalHttpReachabilityExecutionResultSha256 = "f".repeat(64),
                phase11_63ExecutionProofSha256 = "1".repeat(64),
            )
            try {
                SiteProductionDeploymentAndroidPolicyBoundDomainDnsResolutionExecutionBoundary.validateAdmission(
                    exact.copy(maxResolvedAddresses = exact.maxResolvedAddresses + 1),
                )
                fail("tampered Phase 11.79 DNS resolution bound must fail closed")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        } finally {
            deleteTree(root)
        }
    }

    private fun selection(preparation: SiteDeployerLocalPreparationResult) =
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(preparation, evidence(preparation))

    private fun preflight(selection: SiteProductionDeploymentServingPolicySelectionResult) =
        SiteWebServingReadOnlyPreflightBoundary.evaluate(
            plan = requireNotNull(selection.publicationPlan),
            trust = SiteWebServingReadOnlyPreflightTrust("a".repeat(64)),
            observation = SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = requireNotNull(selection.publicationPlan).remoteHostIdentity,
                verifiedHostKeySha256 = "a".repeat(64),
                nginxExecutablePath = "/usr/sbin/nginx",
                confDPathType = SiteWebServingObservedPathType.DIRECTORY,
                configPath = requireNotNull(selection.publicationPlan).configPath,
                configPathType = SiteWebServingObservedPathType.ABSENT,
                existingConfigSha256 = null,
                listenerState = SiteWebServingListenerState.FREE,
                certificatePathType = null,
                observedCertificateSha256 = null,
                privateKeyPathType = null,
                remoteCommandCount = 4,
                mutationOperationPerformed = false,
                arbitraryCommandAccepted = false,
                privateKeyContentReadPerformed = false,
            ),
        )

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) = SiteStaticPublicationEvidence(
        preparationSha256 = preparation.preparationSha256,
        remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
        targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
        finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
        committedClean = true,
        remoteResidualStateClean = true,
    )

    private fun prepare(): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_79-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1179L),
                domain = "phase1179.example.com",
                servicePort = 58489,
                remoteHostIdentity = "203.0.113.10",
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = false,
            ),
            root,
        )
        return root to preparation
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
