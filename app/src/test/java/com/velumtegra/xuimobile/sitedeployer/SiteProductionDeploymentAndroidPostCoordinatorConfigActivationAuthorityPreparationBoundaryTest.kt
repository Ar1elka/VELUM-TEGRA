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

class SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundaryTest {
    @Test
    fun `validated phase1187 proof projects exact phase1173 activation plan without network execution`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff)
            val phase1185 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1184ExecutionResultSha256 = "8".repeat(64),
                        phase1169ExecutionResultSha256 = "9".repeat(64),
                        readOnlyPreflight = report,
                        mutationTransactionId = "phase11_88_tx_ready",
                    )
            val phase1186 =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        readOnlyPreflight = report,
                    )
            val result =
                SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                        phase1187ExecutionResultSha256 = "a".repeat(64),
                        phase1187AdmissionSha256 = "b".repeat(64),
                        phase1172ExecutionResultSha256 = "c".repeat(64),
                        phase11_59ExecutionProofSha256 = "d".repeat(64),
                        readOnlyPreflight = report,
                    )

            assertEquals(
                SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
                result.status,
            )
            assertEquals("a".repeat(64), result.phase1187ExecutionResultSha256)
            assertEquals("c".repeat(64), result.phase1172ExecutionResultSha256)
            assertEquals(
                SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
                result.phase1173AuthorityPreparation.status,
            )
            assertTrue(result.successfulPostCoordinatorStagingSyntaxExecutionProofValidated)
            assertTrue(result.activationExecutionPlanCreated)
            assertTrue(result.stagingConfigWriteAuthorized)
            assertTrue(result.exactConfigActivationAuthorized)
            assertTrue(result.nginxSyntaxValidationAuthorized)
            assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.webServerReloadAuthorized)
            assertFalse(result.coordinatorReinvocationAuthorized)
            assertFalse(result.staticPublicationReplayAuthorized)
            assertFalse(result.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                .validate(result)
        } finally {
            deleteTree(root)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `phase1186 from another handoff is rejected before phase1173 projection`() {
        val (rootA, preparationA) = prepare(11881L, "site-a.example.com")
        val (rootB, preparationB) = prepare(11882L, "site-b.example.com")
        try {
            val handoffA = readyHandoff(preparationA)
            val handoffB = readyHandoff(preparationB)
            val reportA = preflight(handoffA)
            val phase1185A =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoffA,
                        phase1184ExecutionResultSha256 = "1".repeat(64),
                        phase1169ExecutionResultSha256 = "2".repeat(64),
                        readOnlyPreflight = reportA,
                        mutationTransactionId = "phase11_88_tx_foreign",
                    )
            val phase1186A =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoffA,
                        phase1185Preparation = phase1185A,
                        readOnlyPreflight = reportA,
                    )
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoffB,
                    phase1185Preparation = phase1185A,
                    phase1186AuthorityPreparation = phase1186A,
                    phase1187ExecutionResultSha256 = "3".repeat(64),
                    phase1187AdmissionSha256 = "4".repeat(64),
                    phase1172ExecutionResultSha256 = "5".repeat(64),
                    phase11_59ExecutionProofSha256 = "6".repeat(64),
                    readOnlyPreflight = reportA,
                )
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `malformed phase1187 execution proof hash is rejected before activation authority exists`() {
        val (root, preparation) = prepare(11883L, "site-c.example.com")
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff)
            val phase1185 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1184ExecutionResultSha256 = "7".repeat(64),
                        phase1169ExecutionResultSha256 = "8".repeat(64),
                        readOnlyPreflight = report,
                        mutationTransactionId = "phase11_88_tx_bad_hash",
                    )
            val phase1186 =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        readOnlyPreflight = report,
                    )
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1185Preparation = phase1185,
                    phase1186AuthorityPreparation = phase1186,
                    phase1187ExecutionResultSha256 = "not-a-sha",
                    phase1187AdmissionSha256 = "9".repeat(64),
                    phase1172ExecutionResultSha256 = "a".repeat(64),
                    phase11_59ExecutionProofSha256 = "b".repeat(64),
                    readOnlyPreflight = report,
                )
        } finally {
            deleteTree(root)
        }
    }

    private fun preflight(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
    ) = SiteWebServingReadOnlyPreflightBoundary.evaluate(
        plan = requireNotNull(requireNotNull(handoff.servingPolicySelection).publicationPlan),
        trust = SiteWebServingReadOnlyPreflightTrust("7".repeat(64)),
        observation = SiteWebServingReadOnlyPreflightObservation(
            remoteHostIdentity = handoff.remoteHostIdentity,
            verifiedHostKeySha256 = "7".repeat(64),
            nginxExecutablePath = "/usr/sbin/nginx",
            confDPathType = SiteWebServingObservedPathType.DIRECTORY,
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
                SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                    .handoffSha256ForTest(base),
        )
    }

    private fun prepare(
        seed: Long = 1188L,
        domain: String = "site.example.com",
    ): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_88-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
                domain = domain,
                servicePort = 58488,
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
