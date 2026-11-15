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

class SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundaryTest {
    @Test
    fun `validated phase1190 authority admits exactly one phase1176 reload without authority expansion`() {
        val (root, preparation) = prepare()
        try {
            val phase1190 = readyPhase1190(preparation)
            val admission =
                SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
                    .admit(phase1190)

            assertEquals(
                SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
                admission.status,
            )
            assertEquals(
                phase1190.authorityPreparationResultSha256,
                admission.phase1190AuthorityPreparationResultSha256,
            )
            assertEquals(
                phase1190.phase1175AuthorityPreparationResultSha256,
                admission.phase1175AuthorityPreparationResultSha256,
            )
            assertEquals(
                phase1190.phase1175AuthorityPreparation.authorityPreparationResultSha256,
                admission.phase1176Admission.policyBoundNginxReloadAuthorityPreparationResultSha256,
            )
            assertEquals(
                phase1190.nginxReloadExecutionPlan.reloadPlanSha256,
                admission.phase1176Admission.nginxReloadExecutionPlanSha256,
            )
            assertTrue(admission.requiresFreshCredentialResolution)
            assertTrue(admission.requiresLiveRemoteHostKeyVerification)
            assertTrue(admission.realVpsExecutionEligible)
            assertTrue(admission.nginxReloadAuthorized)
            assertFalse(admission.configMutationAuthorized)
            assertFalse(admission.coordinatorReinvocationAuthorized)
            assertFalse(admission.staticPublicationReplayAuthorized)
            assertFalse(admission.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
                .validateAdmission(admission)
        } finally {
            deleteTree(root)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `tampered phase1190 authority is rejected before reload admission exists`() {
        val (root, preparation) = prepare(11911L, "tampered.example.com")
        try {
            val phase1190 = readyPhase1190(preparation)
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
                .admit(phase1190.copy(nginxReloadExecutionAuthorized = false))
        } finally {
            deleteTree(root)
        }
    }

    private fun readyPhase1190(
        preparation: SiteDeployerLocalPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult {
        val handoff = readyHandoff(preparation)
        val report = preflight(handoff)
        val phase1185 =
            SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1184ExecutionResultSha256 = "8".repeat(64),
                    phase1169ExecutionResultSha256 = "9".repeat(64),
                    readOnlyPreflight = report,
                    mutationTransactionId = "phase11_91_tx_ready",
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
        return SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
            .prepareValidated(
                handoff = handoff,
                phase1188AuthorityPreparation = phase1188,
                phase1189ExecutionResultSha256 = "e".repeat(64),
                phase1189AdmissionSha256 = "f".repeat(64),
                phase1174ExecutionResultSha256 = "1".repeat(64),
                phase11_60ExecutionProofSha256 = "2".repeat(64),
            )
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
        val selection =
            SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(preparation, evidence)
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

    private fun prepare(
        seed: Long = 1191L,
        domain: String = "site.example.com",
    ): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_91-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
                domain = domain,
                servicePort = 58491,
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
