package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundaryTest {
    @Test
    fun `ready handoff binds exact committed tree and phase1168 selection without granting live authority`() {
        val (root, preparation) = prepare()
        try {
            val evidence = evidence(preparation)
            val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence,
            )
            val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
                contractVersion = 1,
                status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                    .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
                phase1180AdmissionSha256 = "1".repeat(64),
                phase1180ExecutionResultSha256 = "2".repeat(64),
                localPreparationSha256 = preparation.preparationSha256,
                sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
                targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                staticPublicationEvidence = evidence,
                servingPolicySelection = selection,
                servingPolicySelectionSha256 = selection.selectionSha256,
                requiresFreshPolicyBoundWebServingPreflight = true,
                authorizesWebServingNetworkExecution = false,
                authorizesWebServingMutation = false,
                authorizesCoordinatorReinvocation = false,
                automaticRetryAuthorized = false,
                handoffSha256 = "",
            )
            val handoff = base.copy(
                handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                    .handoffSha256ForTest(base),
            )

            SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)

            assertTrue(handoff.requiresFreshPolicyBoundWebServingPreflight)
            assertFalse(handoff.authorizesWebServingNetworkExecution)
            assertFalse(handoff.authorizesWebServingMutation)
            assertFalse(handoff.authorizesCoordinatorReinvocation)
            assertFalse(handoff.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `tampering exact target after handoff fails closed`() {
        val (root, preparation) = prepare()
        try {
            val evidence = evidence(preparation)
            val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence,
            )
            val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
                contractVersion = 1,
                status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                    .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
                phase1180AdmissionSha256 = "3".repeat(64),
                phase1180ExecutionResultSha256 = "4".repeat(64),
                localPreparationSha256 = preparation.preparationSha256,
                sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
                targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                staticPublicationEvidence = evidence,
                servingPolicySelection = selection,
                servingPolicySelectionSha256 = selection.selectionSha256,
                requiresFreshPolicyBoundWebServingPreflight = true,
                authorizesWebServingNetworkExecution = false,
                authorizesWebServingMutation = false,
                authorizesCoordinatorReinvocation = false,
                automaticRetryAuthorized = false,
                handoffSha256 = "",
            )
            val valid = base.copy(
                handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                    .handoffSha256ForTest(base),
            )

            var rejected = false
            try {
                SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(
                    valid.copy(targetRoot = "/srv/www/other"),
                )
            } catch (_: IllegalArgumentException) {
                rejected = true
            }
            assertTrue(rejected)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `clean rollback handoff exposes no static evidence and no web-serving authority`() {
        val (root, preparation) = prepare()
        try {
            val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
                contractVersion = 1,
                status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                    .BLOCKED_COORDINATOR_ROLLED_BACK_CLEAN,
                phase1180AdmissionSha256 = "5".repeat(64),
                phase1180ExecutionResultSha256 = "6".repeat(64),
                localPreparationSha256 = preparation.preparationSha256,
                sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
                targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                staticPublicationEvidence = null,
                servingPolicySelection = null,
                servingPolicySelectionSha256 = null,
                requiresFreshPolicyBoundWebServingPreflight = false,
                authorizesWebServingNetworkExecution = false,
                authorizesWebServingMutation = false,
                authorizesCoordinatorReinvocation = false,
                automaticRetryAuthorized = false,
                handoffSha256 = "",
            )
            val handoff = base.copy(
                handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                    .handoffSha256ForTest(base),
            )

            SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
            assertFalse(handoff.requiresFreshPolicyBoundWebServingPreflight)
            assertFalse(handoff.authorizesWebServingNetworkExecution)
            assertFalse(handoff.authorizesWebServingMutation)
        } finally {
            deleteTree(root)
        }
    }

    private fun prepare(): Pair<Path, com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_83-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1183L),
                domain = "site.example.com",
                servicePort = 8443,
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

    private fun evidence(
        preparation: com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult,
    ) = SiteStaticPublicationEvidence(
        preparationSha256 = preparation.preparationSha256,
        remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
        targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
        finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
        committedClean = true,
        remoteResidualStateClean = true,
    )

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
