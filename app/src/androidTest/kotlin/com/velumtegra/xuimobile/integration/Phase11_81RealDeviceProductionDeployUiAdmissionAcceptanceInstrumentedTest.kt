package com.velumtegra.xuimobile.integration

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerProductionExecutionPort
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewScreen
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewViewModel
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidUiExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiAdmission
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiExecutionAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiExecutionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiExecutionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_81RealDeviceProductionDeployUiAdmissionAcceptanceInstrumentedTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun exactProductionAdmissionRequiresThreeConfirmationsAndInvokesPortAtMostOnce() {
        val baselineViewModel = SiteDeployerReviewViewModel()
        val baselineReview = requireNotNull(baselineViewModel.uiState.value.review)
        val baseAdmission = SiteProductionDeploymentUiAdmission(
            contractVersion = SiteProductionDeploymentAndroidUiExecutionBoundary.CONTRACT_VERSION,
            status = SiteProductionDeploymentUiAdmissionStatus.READY_FOR_EXPLICIT_OPERATOR_APPROVAL,
            reviewSha256 = baselineReview.reviewSha256,
            serviceDomain = baselineReview.serviceBinding.domain,
            servicePort = baselineReview.serviceBinding.port,
            sourceTreeSha256 = baselineReview.preview.treeSha256,
            deploymentPlanSha256 = "a".repeat(64),
            localPreparationSha256 = "b".repeat(64),
            remoteHostIdentity = "192.0.2.169",
            targetRoot = "/srv/www/phase11_81_ui_acceptance",
            phase1180AdmissionSha256 = "c".repeat(64),
            phase1180InvocationAuthorizationSha256 = "d".repeat(64),
            phase1180CoordinatorInvocationId = "phase11_81_ui_acceptance_0001",
            preparedAtEpochMillis = 0L,
            phase1180PermitExpiresAtEpochMillis = Long.MAX_VALUE,
            requiresExactTargetConfirmation = true,
            requiresRealServerMutationConfirmation = true,
            requiresSingleAttemptNoRetryConfirmation = true,
            deployActionVisible = true,
            deployActionEnabled = false,
            authorizesCoordinatorInvocation = false,
            automaticRetryAuthorized = false,
            operatorApprovalChallengeSha256 = "e".repeat(64),
            admissionSha256 = "",
        )
        val admission = baseAdmission.copy(
            admissionSha256 = SiteProductionDeploymentAndroidUiExecutionBoundary
                .admissionSha256ForTest(baseAdmission),
        )
        val port = RecordingProductionPort(admission)
        val viewModel = SiteDeployerReviewViewModel(port)

        compose.setContent {
            MaterialTheme {
                SiteDeployerReviewScreen(
                    viewModel = viewModel,
                    onBack = { },
                )
            }
        }

        val deploy = compose.onNodeWithTag("site_deployer_production_deploy")
        deploy.performScrollTo().assertIsNotEnabled()
        assertFalse(viewModel.uiState.value.writeActionsEnabled)
        assertFalse(viewModel.uiState.value.realServerMutationEnabled)

        compose.onNodeWithTag("site_deployer_confirm_exact_target").performScrollTo().performClick()
        deploy.assertIsNotEnabled()
        compose.onNodeWithTag("site_deployer_confirm_real_mutation").performScrollTo().performClick()
        deploy.assertIsNotEnabled()
        compose.onNodeWithTag("site_deployer_confirm_no_retry").performScrollTo().performClick()
        deploy.assertIsEnabled()
        assertTrue(viewModel.uiState.value.writeActionsEnabled)
        assertTrue(viewModel.uiState.value.realServerMutationEnabled)

        deploy.performClick()
        compose.waitUntil(timeoutMillis = 5_000L) {
            port.invocationCount == 1 && viewModel.uiState.value.productionExecutionReceipt != null
        }
        assertEquals(1, port.invocationCount)
        assertTrue(viewModel.uiState.value.productionAttemptConsumed)
        assertFalse(viewModel.uiState.value.productionExecutionInProgress)
        compose.onNodeWithTag("site_deployer_production_result").performScrollTo()
        deploy.assertIsNotEnabled()

        // Editing any reviewed input invalidates the exact admission and cannot replay the old port call.
        compose.onNodeWithTag("site_deployer_site_name")
            .performScrollTo()
            .performTextReplacement("changed-after-production-approval")
        compose.waitForIdle()
        assertNull(viewModel.uiState.value.productionAdmission)
        assertFalse(viewModel.uiState.value.writeActionsEnabled)
        assertFalse(viewModel.uiState.value.realServerMutationEnabled)
        assertEquals(1, port.invocationCount)
        compose.onNodeWithTag("site_deployer_production_unavailable").performScrollTo()
    }

    private class RecordingProductionPort(
        private val admission: SiteProductionDeploymentUiAdmission,
    ) : SiteDeployerProductionExecutionPort {
        var invocationCount: Int = 0
            private set

        override fun currentAdmission(review: com.velumtegra.xuimobile.core.site.SiteDeployerReviewState): SiteProductionDeploymentUiAdmission? =
            admission.takeIf { it.reviewSha256 == review.reviewSha256 }

        override suspend fun executeOnce(
            authorization: SiteProductionDeploymentUiExecutionAuthorization,
        ): SiteProductionDeploymentUiExecutionReceipt {
            invocationCount += 1
            check(invocationCount == 1) { "UI attempted a second coordinator invocation" }
            SiteProductionDeploymentAndroidUiExecutionBoundary.validateForExecution(
                authorization = authorization,
                admission = admission,
                invokedAtEpochMillis = authorization.approvedAtEpochMillis + 1L,
            )
            return SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                authorization = authorization,
                status = SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
                phase1180ExecutionResultSha256 = "f".repeat(64),
                completedAtEpochMillis = authorization.approvedAtEpochMillis + 2L,
            )
        }
    }
}
