package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
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

class SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundaryTest {
    @Test
    fun `validated Phase 11_72 identity creates exact bounded Phase 11_60 activation plan locally`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection)
            val preflightSha = "a".repeat(64)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = admission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        mutationTransactionId = "phase11_73_tx_ready",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )

            val result =
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

            assertEquals(
                SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
                result.status,
            )
            assertTrue(result.exactProductionChainBindingVerified)
            assertTrue(result.successfulStagingSyntaxExecutionProofValidated)
            assertTrue(result.activationExecutionPlanCreated)
            assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertTrue(result.stagingConfigWriteAuthorized)
            assertTrue(result.exactConfigActivationAuthorized)
            assertTrue(result.nginxSyntaxValidationAuthorized)
            assertFalse(result.webServerReloadAuthorized)
            assertFalse(result.certificateMutationAuthorized)
            assertFalse(result.dnsMutationAuthorized)
            assertFalse(result.firewallMutationAuthorized)
            assertFalse(result.packageInstallAuthorized)
            assertFalse(result.privateKeyContentReadAuthorized)
            assertFalse(result.automaticRetryAuthorized)
            val mutation = requireNotNull(phase1170.mutationPreparation)
            val stagingPlan = requireNotNull(phase1171.stagingSyntaxExecutionPlan)
            SiteWebServingConfigActivationExecutionBoundary.validateAgainst(
                result.activationExecutionPlan,
                mutation,
                stagingPlan,
                requireNotNull(selection.publicationPlan),
                report,
            )
            assertEquals(
                stagingPlan.executionPlanSha256,
                result.activationExecutionPlan.stagingSyntaxExecutionPlanSha256,
            )
            assertFalse(result.activationExecutionPlan.webServerReloadAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `stale preflight identity cannot be rebound into Phase 11_73 activation authority`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection)
            val exactPreflightSha = "d".repeat(64)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = admission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = exactPreflightSha,
                        mutationTransactionId = "phase11_73_tx_stale",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = exactPreflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )

            try {
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = "e".repeat(64),
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = phase1171,
                        policyBoundStagingSyntaxExecutionResultSha256 = "f".repeat(64),
                        phase11_59ExecutionProofSha256 = "1".repeat(64),
                        readOnlyPreflight = report,
                    )
                fail("stale Phase 11.69 identity must fail closed")
            } catch (_: IllegalArgumentException) {
                // Expected fail-closed identity mismatch.
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
        val root = Files.createTempDirectory("phase11_73-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1173L),
                domain = "site.example.com",
                servicePort = 58484,
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
