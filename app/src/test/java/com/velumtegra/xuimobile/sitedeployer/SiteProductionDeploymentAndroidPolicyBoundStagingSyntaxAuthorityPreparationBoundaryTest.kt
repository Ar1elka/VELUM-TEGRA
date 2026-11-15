package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundaryTest {
    @Test
    fun `ready Phase 11_70 preparation creates exact bounded Phase 11_59 execution plan`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection, nginxPresent = true)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = admission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = "a".repeat(64),
                        mutationTransactionId = "phase11_71_tx_ready",
                    )
            val result =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = "a".repeat(64),
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )

            assertEquals(
                SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                result.status,
            )
            assertTrue(result.stagingSyntaxExecutionPlanCreated)
            val plan = requireNotNull(result.stagingSyntaxExecutionPlan)
            val mutation = requireNotNull(phase1170.mutationPreparation)
            SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
                plan,
                mutation,
                requireNotNull(selection.publicationPlan),
                report,
            )
            assertEquals(phase1170.preparationResultSha256, result.policyBoundConfigMutationPreparationResultSha256)
            assertEquals(mutation.mutationPreparationSha256, result.mutationPreparationSha256)
            assertEquals(phase1170.mutationTransactionId, plan.mutationTransactionId)
            assertTrue(result.stagingConfigWriteAuthorized)
            assertTrue(result.validationConfigWriteAuthorized)
            assertTrue(result.isolatedNginxSyntaxValidationAuthorized)
            assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.exactConfigActivationAuthorized)
            assertFalse(result.webServerReloadAuthorized)
            assertFalse(result.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked Phase 11_70 preparation creates no staging or syntax authority plan`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection, nginxPresent = false)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = admission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = "b".repeat(64),
                        mutationTransactionId = "phase11_71_tx_blocked",
                    )
            val result =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = "b".repeat(64),
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )

            assertEquals(
                SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                    .BLOCKED_BY_POLICY_BOUND_CONFIG_MUTATION_PREPARATION,
                result.status,
            )
            assertFalse(result.stagingSyntaxExecutionPlanCreated)
            assertNull(result.stagingSyntaxExecutionPlan)
            assertNull(result.mutationPreparationSha256)
            assertFalse(result.stagingConfigWriteAuthorized)
            assertFalse(result.validationConfigWriteAuthorized)
            assertFalse(result.isolatedNginxSyntaxValidationAuthorized)
            assertFalse(result.exactConfigActivationAuthorized)
            assertFalse(result.webServerReloadAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    private fun selection(preparation: SiteDeployerLocalPreparationResult) =
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
            preparation = preparation,
            staticPublicationEvidence = evidence(preparation),
        )

    private fun preflight(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        nginxPresent: Boolean,
    ) = SiteWebServingReadOnlyPreflightBoundary.evaluate(
        plan = requireNotNull(selection.publicationPlan),
        trust = SiteWebServingReadOnlyPreflightTrust("7".repeat(64)),
        observation = SiteWebServingReadOnlyPreflightObservation(
            remoteHostIdentity = requireNotNull(selection.publicationPlan).remoteHostIdentity,
            verifiedHostKeySha256 = "7".repeat(64),
            nginxExecutablePath = if (nginxPresent) "/usr/sbin/nginx" else null,
            confDPathType = if (nginxPresent) {
                SiteWebServingObservedPathType.DIRECTORY
            } else {
                SiteWebServingObservedPathType.ABSENT
            },
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
        val root = Files.createTempDirectory("phase11_71-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1171L),
                domain = "site.example.com",
                servicePort = 58482,
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
