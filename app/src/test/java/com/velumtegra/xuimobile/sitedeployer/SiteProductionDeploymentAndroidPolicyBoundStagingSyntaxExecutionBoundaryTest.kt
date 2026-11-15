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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundaryTest {
    @Test
    fun `ready Phase 11_71 result admits only exact live staging syntax execution`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val preflightAdmission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection, nginxPresent = true)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = preflightAdmission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = "a".repeat(64),
                        mutationTransactionId = "phase11_72_tx_ready",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = "a".repeat(64),
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )

            val admission =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
                    .admit(phase1171)

            assertEquals(
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                admission.status,
            )
            assertTrue(admission.realVpsExecutionEligible)
            assertTrue(admission.requiresFreshCredentialResolution)
            assertTrue(admission.requiresLiveRemoteHostKeyVerification)
            assertEquals(
                phase1171.authorityPreparationResultSha256,
                admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            )
            assertEquals(
                phase1171.stagingSyntaxExecutionPlan?.executionPlanSha256,
                admission.stagingSyntaxExecutionPlanSha256,
            )
            assertEquals(
                phase1170.mutationPreparation?.mutationPreparationSha256,
                admission.mutationPreparationSha256,
            )
            assertFalse(admission.exactConfigActivationAuthorized)
            assertFalse(admission.webServerReloadAuthorized)
            assertFalse(admission.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked Phase 11_71 result cannot become network eligible`() {
        val (root, localPreparation) = prepare()
        try {
            val selection = selection(localPreparation)
            val preflightAdmission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .admit(selection)
            val report = preflight(selection, nginxPresent = false)
            val phase1170 =
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        admission = preflightAdmission,
                        readOnlyPreflight = report,
                        policyBoundPreflightExecutionResultSha256 = "b".repeat(64),
                        mutationTransactionId = "phase11_72_tx_blocked",
                    )
            val phase1171 =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        selection = selection,
                        policyBoundPreflightExecutionResultSha256 = "b".repeat(64),
                        policyBoundConfigMutationPreparation = phase1170,
                        readOnlyPreflight = report,
                    )

            val admission =
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
                    .admit(phase1171)

            assertEquals(
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                    .BLOCKED_BY_POLICY_BOUND_STAGING_SYNTAX_AUTHORITY_PREPARATION,
                admission.status,
            )
            assertFalse(admission.realVpsExecutionEligible)
            assertFalse(admission.requiresFreshCredentialResolution)
            assertFalse(admission.requiresLiveRemoteHostKeyVerification)
            assertNull(admission.mutationPreparationSha256)
            assertNull(admission.stagingSyntaxExecutionPlanSha256)
            assertFalse(admission.exactConfigActivationAuthorized)
            assertFalse(admission.webServerReloadAuthorized)
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
        val root = Files.createTempDirectory("phase11_72-")
        val preparation =
            SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1172L),
                    domain = "site.example.com",
                    servicePort = 58483,
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
