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
import org.junit.Test

class SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundaryTest {
    @Test
    fun `ready post-coordinator preflight projects exact phase1170 preparation without authority`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = true)
            val result = SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1184ExecutionResultSha256 = "8".repeat(64),
                    phase1169ExecutionResultSha256 = "9".repeat(64),
                    readOnlyPreflight = report,
                    mutationTransactionId = "phase11_85_tx_ready",
                )
            assertEquals(
                SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus
                    .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION,
                result.status,
            )
            assertTrue(result.mutationPreparationCreated)
            assertTrue(result.phase1170Preparation.mutationPreparationCreated)
            assertFalse(result.productionNetworkTouchedByPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.coordinatorReinvoked)
            assertFalse(result.staticPublicationReplayPerformed)
            assertFalse(result.webServingMutationAuthorized)
            assertFalse(result.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary.validate(result)
        } finally { deleteTree(root) }
    }

    @Test
    fun `blocked post-coordinator preflight creates no mutation preparation`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = false)
            val result = SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1184ExecutionResultSha256 = "a".repeat(64),
                    phase1169ExecutionResultSha256 = "b".repeat(64),
                    readOnlyPreflight = report,
                    mutationTransactionId = "phase11_85_tx_blocked",
                )
            assertEquals(
                SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus
                    .BLOCKED_BY_POST_COORDINATOR_READ_ONLY_PREFLIGHT,
                result.status,
            )
            assertFalse(result.mutationPreparationCreated)
            assertFalse(result.phase1170Preparation.mutationPreparationCreated)
            assertFalse(result.webServingMutationAuthorized)
            assertFalse(result.automaticRetryAuthorized)
        } finally { deleteTree(root) }
    }

    private fun preflight(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        nginxPresent: Boolean,
    ) = SiteWebServingReadOnlyPreflightBoundary.evaluate(
        plan = requireNotNull(requireNotNull(handoff.servingPolicySelection).publicationPlan),
        trust = SiteWebServingReadOnlyPreflightTrust("7".repeat(64)),
        observation = SiteWebServingReadOnlyPreflightObservation(
            remoteHostIdentity = handoff.remoteHostIdentity,
            verifiedHostKeySha256 = "7".repeat(64),
            nginxExecutablePath = if (nginxPresent) "/usr/sbin/nginx" else null,
            confDPathType = if (nginxPresent) SiteWebServingObservedPathType.DIRECTORY else SiteWebServingObservedPathType.ABSENT,
            configPath = requireNotNull(requireNotNull(handoff.servingPolicySelection).publicationPlan).configPath,
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

    private fun readyHandoff(preparation: SiteDeployerLocalPreparationResult): SiteProductionDeploymentPostCoordinatorServingHandoff {
        val evidence = SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )
        val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(preparation, evidence)
        val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
            contractVersion = 1,
            status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus.READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
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
        return base.copy(handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.handoffSha256ForTest(base))
    }

    private fun prepare(): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_85-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1185L),
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
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
