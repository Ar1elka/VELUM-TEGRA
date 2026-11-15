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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundaryTest {
    @Test
    fun `ready phase1186 maps exactly to fresh phase1172 execution admission`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = true)
            val phase1185 = SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1184ExecutionResultSha256 = "8".repeat(64),
                    phase1169ExecutionResultSha256 = "9".repeat(64),
                    readOnlyPreflight = report,
                    mutationTransactionId = "phase11_87_tx_ready",
                )
            val phase1186 = SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1185Preparation = phase1185,
                    readOnlyPreflight = report,
                )
            val admission = SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                .admit(phase1186)

            assertEquals(
                SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
                admission.status,
            )
            assertEquals(phase1186.authorityPreparationResultSha256, admission.phase1186AuthorityPreparationResultSha256)
            assertEquals(phase1186.phase1183HandoffSha256, admission.phase1183HandoffSha256)
            assertEquals(phase1186.phase1185PreparationResultSha256, admission.phase1185PreparationResultSha256)
            assertEquals(phase1186.phase1171AuthorityPreparation.authorityPreparationResultSha256, admission.phase1171AuthorityPreparationResultSha256)
            assertEquals(
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                admission.phase1172Admission.status,
            )
            assertTrue(admission.requiresFreshCredentialResolution)
            assertTrue(admission.requiresLiveRemoteHostKeyVerification)
            assertTrue(admission.realVpsExecutionEligible)
            assertNotNull(admission.mutationPreparationSha256)
            assertNotNull(admission.stagingSyntaxExecutionPlanSha256)
            assertFalse(admission.exactConfigActivationAuthorized)
            assertFalse(admission.webServerReloadAuthorized)
            assertFalse(admission.coordinatorReinvocationAuthorized)
            assertFalse(admission.staticPublicationReplayAuthorized)
            assertFalse(admission.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary.validateAdmission(admission)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked phase1186 cannot create live staging syntax execution authority`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = false)
            val phase1185 = SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1184ExecutionResultSha256 = "a".repeat(64),
                    phase1169ExecutionResultSha256 = "b".repeat(64),
                    readOnlyPreflight = report,
                    mutationTransactionId = "phase11_87_tx_blocked",
                )
            val phase1186 = SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1185Preparation = phase1185,
                    readOnlyPreflight = report,
                )
            val admission = SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                .admit(phase1186)

            assertEquals(
                SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                    .BLOCKED_BY_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION,
                admission.status,
            )
            assertEquals(
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                    .BLOCKED_BY_POLICY_BOUND_STAGING_SYNTAX_AUTHORITY_PREPARATION,
                admission.phase1172Admission.status,
            )
            assertFalse(admission.requiresFreshCredentialResolution)
            assertFalse(admission.requiresLiveRemoteHostKeyVerification)
            assertFalse(admission.realVpsExecutionEligible)
            assertNull(admission.mutationPreparationSha256)
            assertNull(admission.stagingSyntaxExecutionPlanSha256)
            assertFalse(admission.exactConfigActivationAuthorized)
            assertFalse(admission.webServerReloadAuthorized)
            assertFalse(admission.coordinatorReinvocationAuthorized)
            assertFalse(admission.staticPublicationReplayAuthorized)
            assertFalse(admission.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `tampered phase1186 result is rejected before admission is usable`() {
        val (root, preparation) = prepare()
        try {
            val handoff = readyHandoff(preparation)
            val report = preflight(handoff, nginxPresent = true)
            val phase1185 = SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1184ExecutionResultSha256 = "c".repeat(64),
                    phase1169ExecutionResultSha256 = "d".repeat(64),
                    readOnlyPreflight = report,
                    mutationTransactionId = "phase11_87_tx_tamper",
                )
            val phase1186 = SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                .prepareValidated(
                    handoff = handoff,
                    phase1185Preparation = phase1185,
                    readOnlyPreflight = report,
                )
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary.admit(
                phase1186.copy(phase1183HandoffSha256 = "e".repeat(64)),
            )
        } finally {
            deleteTree(root)
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
            handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                .handoffSha256ForTest(base),
        )
    }

    private fun prepare(): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_87-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1187L),
                domain = "site.example.com",
                servicePort = 58487,
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
