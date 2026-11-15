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

class SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundaryTest {
    @Test
    fun `validated phase1189 proof projects exact phase1175 reload plan without network execution`() {
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
                        mutationTransactionId = "phase11_90_tx_ready",
                    )
            val phase1186 =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        readOnlyPreflight = report,
                    )
            val phase1188 =
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
            val result =
                SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1188AuthorityPreparation = phase1188,
                        phase1189ExecutionResultSha256 = "e".repeat(64),
                        phase1189AdmissionSha256 = "f".repeat(64),
                        phase1174ExecutionResultSha256 = "1".repeat(64),
                        phase11_60ExecutionProofSha256 = "2".repeat(64),
                    )

            assertEquals(
                SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
                result.status,
            )
            assertEquals("e".repeat(64), result.phase1189ExecutionResultSha256)
            assertEquals("1".repeat(64), result.phase1174ExecutionResultSha256)
            assertEquals(
                SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
                result.phase1175AuthorityPreparation.status,
            )
            assertTrue(result.successfulPostCoordinatorConfigActivationExecutionProofValidated)
            assertTrue(result.nginxReloadExecutionPlanCreated)
            assertTrue(result.nginxReloadExecutionAuthorized)
            assertTrue(result.nginxReloadExecutionPlan.reloadNginxOnceAuthorized)
            assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.exactConfigActivationPerformedByAuthorityPreparation)
            assertFalse(result.nginxReloadPerformed)
            assertFalse(result.coordinatorReinvocationAuthorized)
            assertFalse(result.staticPublicationReplayAuthorized)
            assertFalse(result.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
                .validate(result)
        } finally {
            deleteTree(root)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `phase1188 from another handoff is rejected before phase1175 projection`() {
        val (rootA, preparationA) = prepare(11901L, "site-a.example.com")
        val (rootB, preparationB) = prepare(11902L, "site-b.example.com")
        try {
            val handoffA = readyHandoff(preparationA)
            val handoffB = readyHandoff(preparationB)
            val reportA = preflight(handoffA)
            val phase1185A =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoffA,
                        phase1184ExecutionResultSha256 = "3".repeat(64),
                        phase1169ExecutionResultSha256 = "4".repeat(64),
                        readOnlyPreflight = reportA,
                        mutationTransactionId = "phase11_90_tx_foreign",
                    )
            val phase1186A =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoffA,
                        phase1185Preparation = phase1185A,
                        readOnlyPreflight = reportA,
                    )
            val phase1188A =
                SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoffA,
                        phase1185Preparation = phase1185A,
                        phase1186AuthorityPreparation = phase1186A,
                        phase1187ExecutionResultSha256 = "5".repeat(64),
                        phase1187AdmissionSha256 = "6".repeat(64),
                        phase1172ExecutionResultSha256 = "7".repeat(64),
                        phase11_59ExecutionProofSha256 = "8".repeat(64),
                        readOnlyPreflight = reportA,
                    )
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoffB,
                    phase1188AuthorityPreparation = phase1188A,
                    phase1189ExecutionResultSha256 = "9".repeat(64),
                    phase1189AdmissionSha256 = "a".repeat(64),
                    phase1174ExecutionResultSha256 = "b".repeat(64),
                    phase11_60ExecutionProofSha256 = "c".repeat(64),
                )
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `malformed phase1189 execution proof hash is rejected before reload authority exists`() {
        val (root, preparation) = prepare(11903L, "site-c.example.com")
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff)
            val phase1185 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1184ExecutionResultSha256 = "d".repeat(64),
                        phase1169ExecutionResultSha256 = "e".repeat(64),
                        readOnlyPreflight = report,
                        mutationTransactionId = "phase11_90_tx_bad_hash",
                    )
            val phase1186 =
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        readOnlyPreflight = report,
                    )
            val phase1188 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                        phase1187ExecutionResultSha256 = "f".repeat(64),
                        phase1187AdmissionSha256 = "1".repeat(64),
                        phase1172ExecutionResultSha256 = "2".repeat(64),
                        phase11_59ExecutionProofSha256 = "3".repeat(64),
                        readOnlyPreflight = report,
                    )
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1188AuthorityPreparation = phase1188,
                    phase1189ExecutionResultSha256 = "not-a-sha",
                    phase1189AdmissionSha256 = "4".repeat(64),
                    phase1174ExecutionResultSha256 = "5".repeat(64),
                    phase11_60ExecutionProofSha256 = "6".repeat(64),
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
            configPath =
                requireNotNull(requireNotNull(handoff.servingPolicySelection).publicationPlan)
                    .configPath,
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
        val selection =
            SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation,
                evidence,
            )
        val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
            contractVersion = 1,
            status =
                SiteProductionDeploymentPostCoordinatorServingHandoffStatus
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
            handoffSha256 =
                SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                    .handoffSha256ForTest(base),
        )
    }

    private fun prepare(
        seed: Long = 1190L,
        domain: String = "site.example.com",
    ): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_90-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
                domain = domain,
                servicePort = 58490,
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
