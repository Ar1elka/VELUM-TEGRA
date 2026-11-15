package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class SiteProductionDeploymentAndroidUiExecutionBoundaryTest {
    @Test
    fun `exact phase1180 admission becomes explicit single attempt UI authorization and stale review fails closed`() {
        val outputRoot = Files.createTempDirectory("phase11_81_ui_boundary")
        try {
            val seed = DesignSeed(1181)
            val domain = "phase1181.example.com"
            val port = 8443
            val host = "203.0.113.81"
            val target = "/srv/www/phase1181"
            val review = SiteDeployerReviewBoundary.prepare(
                SiteDeployerReviewRequest(
                    rootSeed = seed,
                    siteName = "Phase 11.81",
                    tagline = "explicit production UI",
                    domain = domain,
                    servicePort = port,
                    remoteHostIdentity = host,
                    targetRoot = target,
                    owner = "www_data",
                    group = "www_data",
                    trustedServerKeySha256 = "a".repeat(64),
                ),
            )
            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = seed,
                    siteName = "Phase 11.81",
                    tagline = "explicit production UI",
                    domain = domain,
                    servicePort = port,
                    remoteHostIdentity = host,
                    targetRoot = target,
                    owner = "www_data",
                    group = "www_data",
                ),
                outputRoot,
            )
            val phase1180Base = SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission(
                contractVersion = SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.CONTRACT_VERSION,
                status = SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmissionStatus
                    .READY_FOR_ONE_EXISTING_COORDINATOR_INVOCATION,
                invocationAuthorizationSha256 = "1".repeat(64),
                executionAuthorizationSha256 = "2".repeat(64),
                coordinatorRequestSha256 = "3".repeat(64),
                runtimeIdentitySha256 = "4".repeat(64),
                permitSha256 = "5".repeat(64),
                candidateTransportAuthorizationSha256 = "6".repeat(64),
                capabilityProfileSha256 = "7".repeat(64),
                localPreparationSha256 = preparation.preparationSha256,
                deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
                sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                remoteHostIdentity = host,
                targetRoot = target,
                coordinatorInvocationId = "phase11_81_coordinator_0001",
                evaluatedAtEpochMillis = 1_000L,
                permitExpiresAtEpochMillis = 30_000L,
                requiresDurableCoordinatorInvocationFence = true,
                delegatesToExistingCoordinator = true,
                delegatesTransportToAcceptedPhase1155Transaction = true,
                addsNewRemoteMutationPrimitive = false,
                automaticRetryAuthorized = false,
                arbitraryCommandAuthorized = false,
                exposesDeployUiAction = false,
                admissionSha256 = "",
            )
            val phase1180 = phase1180Base.copy(
                admissionSha256 = SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
                    .admissionSha256ForTest(phase1180Base),
            )

            val admission = SiteProductionDeploymentAndroidUiExecutionBoundary.prepare(
                review = review,
                preparation = preparation,
                coordinatorAdmission = phase1180,
                preparedAtEpochMillis = 2_000L,
            )
            assertEquals(review.reviewSha256, admission.reviewSha256)
            assertEquals(domain, admission.serviceDomain)
            assertEquals(port, admission.servicePort)
            assertEquals(host, admission.remoteHostIdentity)
            assertEquals(target, admission.targetRoot)
            assertEquals(preparation.remoteDeployPlan.sourceTreeSha256, admission.sourceTreeSha256)
            assertTrue(admission.deployActionVisible)
            assertFalse(admission.deployActionEnabled)
            assertFalse(admission.authorizesCoordinatorInvocation)
            assertFalse(admission.automaticRetryAuthorized)

            val wrongHostReview = review.copy(
                remoteTarget = review.remoteTarget.copy(remoteHostIdentity = "fixture.phase1181.local"),
            )
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.prepare(
                    review = wrongHostReview,
                    preparation = preparation,
                    coordinatorAdmission = phase1180,
                    preparedAtEpochMillis = 2_000L,
                )
            }.isFailure)
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.validateForReview(admission, wrongHostReview)
            }.isFailure)

            val wrongTargetReview = review.copy(
                remoteTarget = review.remoteTarget.copy(targetRoot = "/srv/www/other"),
            )
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.prepare(
                    review = wrongTargetReview,
                    preparation = preparation,
                    coordinatorAdmission = phase1180,
                    preparedAtEpochMillis = 2_000L,
                )
            }.isFailure)

            val wrongTargetPolicyReview = review.copy(
                remoteTarget = review.remoteTarget.copy(
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ),
            )
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.prepare(
                    review = wrongTargetPolicyReview,
                    preparation = preparation,
                    coordinatorAdmission = phase1180,
                    preparedAtEpochMillis = 2_000L,
                )
            }.isFailure)

            val wrongCertificateIntentReview = review.copy(
                certificate = review.certificate.copy(requested = true, domain = domain),
            )
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.prepare(
                    review = wrongCertificateIntentReview,
                    preparation = preparation,
                    coordinatorAdmission = phase1180,
                    preparedAtEpochMillis = 2_000L,
                )
            }.isFailure)

            val authorization = SiteProductionDeploymentAndroidUiExecutionBoundary.authorize(
                admission = admission,
                approval = SiteProductionDeploymentUiApproval(
                    operatorApprovalChallengeSha256 = admission.operatorApprovalChallengeSha256,
                    exactTargetConfirmed = true,
                    realServerMutationConfirmed = true,
                    singleAttemptNoRetryConfirmed = true,
                ),
                approvedAtEpochMillis = 3_000L,
            )
            assertTrue(authorization.authorizesSingleCoordinatorInvocation)
            assertTrue(authorization.requiresPhase1180DurableReplayFence)
            assertFalse(authorization.automaticRetryAuthorized)
            SiteProductionDeploymentAndroidUiExecutionBoundary.validateForExecution(
                authorization = authorization,
                admission = admission,
                invokedAtEpochMillis = 4_000L,
            )

            val receipt = SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                authorization = authorization,
                status = SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
                phase1180ExecutionResultSha256 = "f".repeat(64),
                completedAtEpochMillis = 5_000L,
            )
            assertEquals(1, receipt.existingCoordinatorInvocationCount)
            assertTrue(receipt.acceptedPhase1155TransactionDelegated)
            assertFalse(receipt.completeHttpServingPathVerified)
            assertEquals(null, receipt.phase1192ExecutionResultSha256)
            assertFalse(receipt.completeHttpsTlsServingPathVerified)
            assertEquals(null, receipt.phase1198HttpsServingReceiptSha256)
            assertEquals(null, receipt.phase1197ExecutionResultSha256)
            assertFalse(receipt.automaticRetryPerformed)

            // Caddy publication is only "verified" with an externally fetched URL; a files-only
            // commit must carry the concrete failure and can never claim reachability.
            val caddyOk = SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                authorization = authorization,
                status = SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED,
                phase1180ExecutionResultSha256 = "f".repeat(64),
                completedAtEpochMillis = 5_000L,
                servingOutcome = com.velumtegra.xuimobile.core.site.SiteServingOutcome(
                    com.velumtegra.xuimobile.core.site.SiteServingBackend.CADDY,
                    "https://site.example.test/",
                    "https://site.example.test/",
                    true, true, false, null, null,
                ),
            )
            assertEquals("https://site.example.test/", caddyOk.servingOutcome?.verifiedUrl)
            val notReachable = com.velumtegra.xuimobile.core.site.SiteServingOutcome(
                com.velumtegra.xuimobile.core.site.SiteServingBackend.CADDY,
                "https://site.example.test/",
                null,
                true, false, false,
                com.velumtegra.xuimobile.core.site.SiteServingFailureCategory.FIREWALL,
                "closed",
            )
            val filesOnly = SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                authorization = authorization,
                status = SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED,
                phase1180ExecutionResultSha256 = "f".repeat(64),
                completedAtEpochMillis = 5_000L,
                servingOutcome = notReachable,
            )
            assertFalse(filesOnly.servingOutcome!!.externallyReachable)
            var rejected = false
            try {
                SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                    authorization = authorization,
                    status = SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED,
                    phase1180ExecutionResultSha256 = "f".repeat(64),
                    completedAtEpochMillis = 5_000L,
                    servingOutcome = notReachable,
                )
            } catch (_: IllegalArgumentException) {
                rejected = true
            }
            assertTrue(rejected)

            val completeServingReceipt = SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                authorization = authorization,
                status = SiteProductionDeploymentUiExecutionStatus
                    .COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED,
                phase1180ExecutionResultSha256 = "f".repeat(64),
                completedAtEpochMillis = 5_001L,
                phase1192ExecutionResultSha256 = "e".repeat(64),
                completeHttpServingPathVerified = true,
            )
            assertTrue(completeServingReceipt.completeHttpServingPathVerified)
            assertEquals("e".repeat(64), completeServingReceipt.phase1192ExecutionResultSha256)
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                    authorization = authorization,
                    status = SiteProductionDeploymentUiExecutionStatus
                        .COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED,
                    phase1180ExecutionResultSha256 = "f".repeat(64),
                    completedAtEpochMillis = 5_002L,
                )
            }.isFailure)

            val completeHttpsServingReceipt = SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                authorization = authorization,
                status = SiteProductionDeploymentUiExecutionStatus
                    .COORDINATOR_COMMITTED_AND_HTTPS_TLS_SERVING_PATH_VERIFIED,
                phase1180ExecutionResultSha256 = "f".repeat(64),
                completedAtEpochMillis = 5_002L,
                phase1198HttpsServingReceiptSha256 = "d".repeat(64),
                phase1197ExecutionResultSha256 = "c".repeat(64),
                completeHttpsTlsServingPathVerified = true,
            )
            assertTrue(completeHttpsServingReceipt.completeHttpsTlsServingPathVerified)
            assertFalse(completeHttpsServingReceipt.completeHttpServingPathVerified)
            assertEquals("d".repeat(64), completeHttpsServingReceipt.phase1198HttpsServingReceiptSha256)
            assertEquals("c".repeat(64), completeHttpsServingReceipt.phase1197ExecutionResultSha256)
            assertTrue(runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
                    authorization = authorization,
                    status = SiteProductionDeploymentUiExecutionStatus
                        .COORDINATOR_COMMITTED_AND_HTTPS_TLS_SERVING_PATH_VERIFIED,
                    phase1180ExecutionResultSha256 = "f".repeat(64),
                    completedAtEpochMillis = 5_003L,
                )
            }.isFailure)

            val changedReview = review.copy(serviceBinding = review.serviceBinding.copy(port = 9443))
            val staleRejected = runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.validateForReview(admission, changedReview)
            }.isFailure
            assertTrue(staleRejected)

            val incompleteApprovalRejected = runCatching {
                SiteProductionDeploymentAndroidUiExecutionBoundary.authorize(
                    admission = admission,
                    approval = SiteProductionDeploymentUiApproval(
                        operatorApprovalChallengeSha256 = admission.operatorApprovalChallengeSha256,
                        exactTargetConfirmed = true,
                        realServerMutationConfirmed = true,
                        singleAttemptNoRetryConfirmed = false,
                    ),
                    approvedAtEpochMillis = 3_000L,
                )
            }.isFailure
            assertTrue(incompleteApprovalRejected)
        } finally {
            outputRoot.toFile().deleteRecursively()
        }
    }
}
