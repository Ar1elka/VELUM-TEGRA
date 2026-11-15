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

class SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundaryTest {
    @Test
    fun `ready phase1185 projects exact phase1171 staging syntax plan without network execution`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = true)
            val phase1185 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1184ExecutionResultSha256 = "8".repeat(64),
                        phase1169ExecutionResultSha256 = "9".repeat(64),
                        readOnlyPreflight = report,
                        mutationTransactionId = "phase11_86_tx_ready",
                    )
            val result =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        readOnlyPreflight = report,
                    )

            assertEquals(
                SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
                result.status,
            )
            assertEquals(phase1185.preparationResultSha256, result.phase1185PreparationResultSha256)
            assertEquals(phase1185.phase1170Preparation.preparationResultSha256, result.phase1170PreparationResultSha256)
            assertTrue(result.stagingSyntaxExecutionPlanCreated)
            assertTrue(result.stagingSyntaxExecutionPlanSha256 != null)
            assertTrue(result.stagingConfigWriteAuthorized)
            assertTrue(result.validationConfigWriteAuthorized)
            assertTrue(result.isolatedNginxSyntaxValidationAuthorized)
            assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.coordinatorReinvoked)
            assertFalse(result.staticPublicationReplayPerformed)
            assertFalse(result.exactConfigActivationAuthorized)
            assertFalse(result.webServerReloadAuthorized)
            assertFalse(result.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary.validate(result)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked phase1185 creates no staging syntax execution plan or write authority`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = false)
            val phase1185 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1184ExecutionResultSha256 = "a".repeat(64),
                        phase1169ExecutionResultSha256 = "b".repeat(64),
                        readOnlyPreflight = report,
                        mutationTransactionId = "phase11_86_tx_blocked",
                    )
            val result =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        readOnlyPreflight = report,
                    )

            assertEquals(
                SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                    .BLOCKED_BY_POST_COORDINATOR_CONFIG_MUTATION_PREPARATION,
                result.status,
            )
            assertFalse(result.stagingSyntaxExecutionPlanCreated)
            assertNull(result.stagingSyntaxExecutionPlanSha256)
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

    @Test(expected = IllegalArgumentException::class)
    fun `phase1185 from another handoff is rejected before phase1171 projection`() {
        val (rootA, preparationA) = prepare(11861L, "site-a.example.com")
        val (rootB, preparationB) = prepare(11862L, "site-b.example.com")
        try {
            val handoffA = readyHandoff(preparationA)
            val handoffB = readyHandoff(preparationB)
            val reportA = preflight(handoffA, nginxPresent = true)
            val phase1185A =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoffA,
                        phase1184ExecutionResultSha256 = "c".repeat(64),
                        phase1169ExecutionResultSha256 = "d".repeat(64),
                        readOnlyPreflight = reportA,
                        mutationTransactionId = "phase11_86_tx_foreign",
                    )
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoffB,
                    phase1185Preparation = phase1185A,
                    readOnlyPreflight = reportA,
                )
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
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
            confDPathType = if (nginxPresent) {
                SiteWebServingObservedPathType.DIRECTORY
            } else {
                SiteWebServingObservedPathType.ABSENT
            },
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
        return base.copy(
            handoffSha256 =
                SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.handoffSha256ForTest(base),
        )
    }

    private fun prepare(
        seed: Long = 1186L,
        domain: String = "site.example.com",
    ): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_86-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
                domain = domain,
                servicePort = 58486,
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
