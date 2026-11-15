package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingListenerState
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
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

class SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundaryTest {
    @Test
    fun `ready policy-bound HTTP preflight creates exact Phase 11_58 transaction preparation`() {
        val (root, preparation) = prepare()
        try {
            val selection = selection(preparation)
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection, nginxPresent = true)
            val result =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = admission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = "a".repeat(64),
                        mutationTransactionId = "phase11_70_tx_ready",
                    )

            assertEquals(
                SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                    .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY,
                result.status,
            )
            assertEquals(SiteWebServingProtocol.HTTP, result.selectedProtocol)
            assertTrue(result.mutationPreparationCreated)
            val mutation = requireNotNull(result.mutationPreparation)
            assertEquals("phase11_70_tx_ready", mutation.mutationTransactionId)
            assertEquals(selection.publicationPlan?.publicationPlanSha256, mutation.publicationPlanSha256)
            assertEquals(report.preflightSha256, mutation.readOnlyPreflightSha256)
            assertTrue(mutation.stagingConfigPath.endsWith(".stage"))
            assertFalse(mutation.stagingConfigPath.endsWith(".conf"))
            assertFalse(mutation.configMutationAuthorized)
            assertFalse(mutation.webServerReloadAuthorized)
            assertFalse(result.productionNetworkTouchedByPreparation)
            assertFalse(result.configMutationAuthorized)
            assertFalse(result.webServerReloadAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked live preflight creates no mutation transaction preparation`() {
        val (root, preparation) = prepare()
        try {
            val selection = selection(preparation)
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection, nginxPresent = false)
            val result =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = admission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = "b".repeat(64),
                        mutationTransactionId = "phase11_70_tx_blocked",
                    )

            assertEquals(
                SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                    .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT,
                result.status,
            )
            assertFalse(result.mutationPreparationCreated)
            assertNull(result.mutationPreparation)
            assertFalse(result.configMutationAuthorized)
            assertFalse(result.webServerReloadAuthorized)
            assertFalse(result.automaticRetryAuthorized)
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
        val root = Files.createTempDirectory("phase11_70-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1170L),
                domain = "site.example.com",
                servicePort = 58481,
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
