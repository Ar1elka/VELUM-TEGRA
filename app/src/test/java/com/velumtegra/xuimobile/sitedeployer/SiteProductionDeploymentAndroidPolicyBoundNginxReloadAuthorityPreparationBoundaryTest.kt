package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingListenerState
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionBoundary
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

class SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundaryTest {
    @Test
    fun `validated Phase 11_74 identity creates exact bounded Phase 11_61 reload plan locally`() {
        val (root, localPreparation) = prepare(1175L, "site.example.com")
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
                        mutationTransactionId = "phase11_75_tx_ready",
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

            val result =
                SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        activationAuthorityPreparation = phase1173,
                        policyBoundConfigActivationExecutionResultSha256 = "d".repeat(64),
                        phase11_60ExecutionProofSha256 = "e".repeat(64),
                    )

            assertEquals(
                SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
                result.status,
            )
            assertTrue(result.exactProductionChainBindingVerified)
            assertTrue(result.successfulConfigActivationExecutionProofValidated)
            assertTrue(result.nginxReloadExecutionPlanCreated)
            assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.exactConfigActivationPerformedByAuthorityPreparation)
            assertTrue(result.nginxReloadExecutionAuthorized)
            assertFalse(result.nginxReloadPerformed)
            assertFalse(result.configMutationAuthorized)
            assertFalse(result.certificateMutationAuthorized)
            assertFalse(result.dnsMutationAuthorized)
            assertFalse(result.firewallMutationAuthorized)
            assertFalse(result.packageInstallAuthorized)
            assertFalse(result.privateKeyContentReadAuthorized)
            assertFalse(result.automaticRetryAuthorized)
            SiteWebServingNginxReloadExecutionBoundary.validateAgainst(
                result.nginxReloadExecutionPlan,
                phase1173.activationExecutionPlan,
                requireNotNull(selection.publicationPlan),
            )
            assertTrue(result.nginxReloadExecutionPlan.reloadNginxOnceAuthorized)
            assertFalse(result.nginxReloadExecutionPlan.configMutationAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `different serving selection cannot be rebound into Phase 11_75 reload authority`() {
        val (rootA, localA) = prepare(1176L, "site-a.example.com")
        val (rootB, localB) = prepare(1177L, "site-b.example.com")
        try {
            val selectionA = selection(localA)
            val admissionA =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selectionA)
            val reportA = preflight(selectionA)
            val preflightSha = "1".repeat(64)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selectionA,
                        admission = admissionA,
                        readOnlyPreflight = reportA,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        mutationTransactionId = "phase11_75_tx_stale",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selectionA,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = reportA,
                    )
            val phase1173 =
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selectionA,
                        policyBoundPreflightExecutionResultSha256 = preflightSha,
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = phase1171,
                        policyBoundStagingSyntaxExecutionResultSha256 = "2".repeat(64),
                        phase11_59ExecutionProofSha256 = "3".repeat(64),
                        readOnlyPreflight = reportA,
                    )
            val selectionB = selection(localB)

            try {
                SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selectionB,
                        activationAuthorityPreparation = phase1173,
                        policyBoundConfigActivationExecutionResultSha256 = "4".repeat(64),
                        phase11_60ExecutionProofSha256 = "5".repeat(64),
                    )
                fail("cross-selection Phase 11.74 proof must fail closed")
            } catch (_: IllegalArgumentException) {
                // Expected fail-closed chain mismatch.
            }
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
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

    private fun prepare(seed: Long, domain: String): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_75-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
                domain = domain,
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
