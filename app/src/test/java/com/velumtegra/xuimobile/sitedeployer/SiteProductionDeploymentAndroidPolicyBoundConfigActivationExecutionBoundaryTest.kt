package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingListenerState
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

class SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundaryTest {
    @Test
    fun `validated Phase 11_73 authority creates exact bounded Phase 11_74 live activation admission`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val preflightAdmission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection)
            val preflightSha = "a".repeat(64)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = preflightAdmission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        mutationTransactionId = "phase11_74_tx_ready",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )
            val phase1173 =
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = phase1171,
                        policyBoundStagingSyntaxExecutionResultSha256 = "b".repeat(64),
                        phase11_59ExecutionProofSha256 = "c".repeat(64),
                        readOnlyPreflight = report,
                    )

            val admission =
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                    .admit(phase1173)

            assertEquals(
                SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
                admission.status,
            )
            assertEquals(
                phase1173.authorityPreparationResultSha256,
                admission.policyBoundConfigActivationAuthorityPreparationResultSha256,
            )
            assertEquals(
                phase1173.activationExecutionPlan.activationPlanSha256,
                admission.activationExecutionPlanSha256,
            )
            assertEquals(
                phase1173.phase11_59ExecutionProofSha256,
                admission.phase11_59ExecutionProofSha256,
            )
            assertTrue(admission.requiresFreshCredentialResolution)
            assertTrue(admission.requiresLiveRemoteHostKeyVerification)
            assertTrue(admission.realVpsExecutionEligible)
            assertTrue(admission.exactConfigActivationAuthorized)
            assertFalse(admission.webServerReloadAuthorized)
            assertFalse(admission.certificateMutationAuthorized)
            assertFalse(admission.dnsMutationAuthorized)
            assertFalse(admission.firewallMutationAuthorized)
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
    fun `tampered Phase 11_74 admission fails closed before live execution`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val preflightAdmission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection)
            val preflightSha = "d".repeat(64)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = preflightAdmission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        mutationTransactionId = "phase11_74_tx_tamper",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )
            val phase1173 =
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = phase1171,
                        policyBoundStagingSyntaxExecutionResultSha256 = "e".repeat(64),
                        phase11_59ExecutionProofSha256 = "f".repeat(64),
                        readOnlyPreflight = report,
                    )
            val exact =
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                    .admit(phase1173)
            try {
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                    .validateAdmission(
                        exact.copy(activationExecutionPlanSha256 = "1".repeat(64)),
                    )
                fail("tampered Phase 11.74 activation plan identity must fail closed")
            } catch (_: IllegalArgumentException) {
                // Expected SHA-bound fail-closed admission.
            }
        } finally {
            deleteTree(root)
        }
    }

    private fun selection(preparation: SiteDeployerLocalPreparationResult) =
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
            preparation = preparation,
            staticPublicationEvidence = evidence(preparation),
        )

    private fun preflight(selection: SiteProductionDeploymentServingPolicySelectionResult) =
        SiteWebServingReadOnlyPreflightBoundary.evaluate(
            plan = requireNotNull(selection.publicationPlan),
            trust = SiteWebServingReadOnlyPreflightTrust("7".repeat(64)),
            observation = SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = requireNotNull(selection.publicationPlan).remoteHostIdentity,
                verifiedHostKeySha256 = "7".repeat(64),
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

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) =
        SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )

    private fun prepare(): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_74-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1174L),
                domain = "site.example.com",
                servicePort = 58485,
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
