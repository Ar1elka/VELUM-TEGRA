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

class SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundaryTest {
    @Test
    fun `ready phase1188 produces exact phase1174 activation admission without later authority`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff)
            val phase1185 =
                SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                    .prepareValidated(
                        handoff = handoff,
                        phase1184ExecutionResultSha256 = "1".repeat(64),
                        phase1169ExecutionResultSha256 = "2".repeat(64),
                        readOnlyPreflight = report,
                        mutationTransactionId = "phase11_89_tx_ready",
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
                        phase1187ExecutionResultSha256 = "3".repeat(64),
                        phase1187AdmissionSha256 = "4".repeat(64),
                        phase1172ExecutionResultSha256 = "5".repeat(64),
                        phase11_59ExecutionProofSha256 = "6".repeat(64),
                        readOnlyPreflight = report,
                    )

            val admission =
                SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                    .admit(phase1188)

            assertEquals(
                SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
                admission.status,
            )
            assertEquals(phase1188.authorityPreparationResultSha256, admission.phase1188AuthorityPreparationResultSha256)
            assertEquals(phase1188.phase1172ExecutionResultSha256, admission.phase1172ExecutionResultSha256)
            assertEquals(phase1188.activationExecutionPlanSha256, admission.activationExecutionPlanSha256)
            assertEquals(
                phase1188.phase1173AuthorityPreparation.authorityPreparationResultSha256,
                admission.phase1174Admission.policyBoundConfigActivationAuthorityPreparationResultSha256,
            )
            assertTrue(admission.realVpsExecutionEligible)
            assertTrue(admission.requiresFreshCredentialResolution)
            assertTrue(admission.requiresLiveRemoteHostKeyVerification)
            assertTrue(admission.exactConfigActivationAuthorized)
            assertFalse(admission.webServerReloadAuthorized)
            assertFalse(admission.coordinatorReinvocationAuthorized)
            assertFalse(admission.staticPublicationReplayAuthorized)
            assertFalse(admission.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                .validateAdmission(admission)
        } finally {
            deleteTree(root)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `tampered phase1188 proof is rejected before activation admission exists`() {
        val (root, preparation) = prepare(11892L, "tampered.example.com")
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
                        mutationTransactionId = "phase11_89_tx_tampered",
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
                        phase1187ExecutionResultSha256 = "9".repeat(64),
                        phase1187AdmissionSha256 = "a".repeat(64),
                        phase1172ExecutionResultSha256 = "b".repeat(64),
                        phase11_59ExecutionProofSha256 = "c".repeat(64),
                        readOnlyPreflight = report,
                    )
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                .admit(phase1188.copy(authorityPreparationResultSha256 = "d".repeat(64)))
        } finally {
            deleteTree(root)
        }
    }

    private fun preflight(handoff: SiteProductionDeploymentPostCoordinatorServingHandoff) =
        SiteWebServingReadOnlyPreflightBoundary.evaluate(
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

    private fun readyHandoff(preparation: SiteDeployerLocalPreparationResult):
        SiteProductionDeploymentPostCoordinatorServingHandoff {
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
            phase1180AdmissionSha256 = "e".repeat(64),
            phase1180ExecutionResultSha256 = "f".repeat(64),
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
            handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.handoffSha256ForTest(base),
        )
    }

    private fun prepare(seed: Long = 11891L, domain: String = "phase1189.example.com"):
        Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_89-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
                domain = domain,
                servicePort = 58489,
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
