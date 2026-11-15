package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundaryTest {
    @Test
    fun `ready phase1183 handoff maps exactly to phase1169 admission without replay authority`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val admission =
                SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(handoff)

            assertEquals(
                SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus
                    .READY_FOR_FRESH_POLICY_BOUND_READ_ONLY_PREFLIGHT,
                admission.status,
            )
            assertEquals(handoff.handoffSha256, admission.phase1183HandoffSha256)
            assertEquals(handoff.phase1180ExecutionResultSha256, admission.phase1180ExecutionResultSha256)
            assertEquals(handoff.servingPolicySelectionSha256, admission.servingPolicySelectionSha256)
            assertEquals(SiteWebServingProtocol.HTTP, admission.selectedProtocol)
            assertTrue(admission.requiresFreshCredentialResolution)
            assertTrue(admission.requiresLiveHostKeyVerification)
            assertFalse(admission.authorizesCoordinatorReinvocation)
            assertFalse(admission.authorizesStaticPublicationReplay)
            assertFalse(admission.authorizesWebServingMutation)
            assertFalse(admission.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                .validateAdmission(admission)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked phase1183 handoff cannot enter phase1184 preflight admission`() {
        val (root, preparation) = prepare()
        try {
            val blockedBase = SiteProductionDeploymentPostCoordinatorServingHandoff(
                contractVersion = 1,
                status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                    .BLOCKED_COORDINATOR_ROLLED_BACK_CLEAN,
                phase1180AdmissionSha256 = "3".repeat(64),
                phase1180ExecutionResultSha256 = "4".repeat(64),
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
            val blocked = blockedBase.copy(
                handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                    .handoffSha256ForTest(blockedBase),
            )

            var rejected = false
            try {
                SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(blocked)
            } catch (_: IllegalArgumentException) {
                rejected = true
            }
            assertTrue(rejected)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `tampered phase1183 handoff fails before phase1169 admission can be projected`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            var rejected = false
            try {
                SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(
                    handoff.copy(remoteHostIdentity = "203.0.113.11"),
                )
            } catch (_: IllegalArgumentException) {
                rejected = true
            }
            assertTrue(rejected)
        } finally {
            deleteTree(root)
        }
    }

    private fun readyHandoff(
        preparation: SiteDeployerLocalPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorServingHandoff {
        val evidence = SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )
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
        return base.copy(
            handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                .handoffSha256ForTest(base),
        )
    }

    private fun prepare(): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_84-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1184L),
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
