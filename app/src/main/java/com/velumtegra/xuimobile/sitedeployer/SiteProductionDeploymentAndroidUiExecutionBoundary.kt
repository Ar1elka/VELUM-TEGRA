package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteServingOutcome
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewState
import java.security.MessageDigest

/**
 * Phase 11.81 exposes the already accepted Phase 11.80 coordinator path to Android UI only through
 * an explicit, hash-bound operator confirmation. It adds no transport, SSH/SFTP, command, retry or
 * credential capability. The Phase 11.80 durable replay fence remains the authoritative one-shot
 * counteraction if process/UI state is lost after execution begins.
 */
internal object SiteProductionDeploymentAndroidUiExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepare(
        review: SiteDeployerReviewState,
        preparation: SiteDeployerLocalPreparationResult,
        coordinatorAdmission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        preparedAtEpochMillis: Long,
    ): SiteProductionDeploymentUiAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
            .validateAdmission(coordinatorAdmission)
        require(preparedAtEpochMillis >= coordinatorAdmission.evaluatedAtEpochMillis) {
            "UI admission cannot predate Phase 11.80 admission"
        }
        require(preparedAtEpochMillis <= coordinatorAdmission.permitExpiresAtEpochMillis) {
            "Phase 11.80 permit expired before UI admission"
        }
        require(review.preview.treeSha256 == preparation.previewExport.preview.treeSha256) {
            "UI review source tree differs from exact local preparation"
        }
        require(review.exportManifest.planSha256 == preparation.previewExport.export.manifest.planSha256) {
            "UI review export plan differs from exact local preparation"
        }
        require(review.serviceBinding.domain == preparation.serviceBinding.domain) {
            "UI review domain differs from exact local preparation"
        }
        require(review.serviceBinding.port == preparation.serviceBinding.port) {
            "UI review service port differs from exact local preparation"
        }
        require(review.remoteTarget.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity) {
            "UI review remote host differs from exact local preparation"
        }
        require(review.remoteTarget.targetRoot == preparation.remoteDeployPlan.publish.targetRoot) {
            "UI review target root differs from exact local preparation"
        }
        require(review.remoteTarget.existingTargetPolicy == preparation.remoteDeployPlan.publish.existingTargetPolicy) {
            "UI review existing-target policy differs from exact local preparation"
        }
        val certificateReuseRequested = preparation.remoteDeployPlan.certificate.mode ==
            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN
        require(review.certificate.requested == certificateReuseRequested) {
            "UI review certificate-reuse intent differs from exact local preparation"
        }
        if (certificateReuseRequested) {
            require(review.certificate.domain == preparation.serviceBinding.domain) {
                "UI review certificate domain differs from exact local preparation"
            }
        }
        require(coordinatorAdmission.localPreparationSha256 == preparation.preparationSha256) {
            "Phase 11.80 admission is bound to a different local preparation"
        }
        require(coordinatorAdmission.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256) {
            "Phase 11.80 admission is bound to a different deployment plan"
        }
        require(coordinatorAdmission.sourceTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256) {
            "Phase 11.80 admission is bound to a different source tree"
        }
        require(coordinatorAdmission.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Phase 11.80 admission remote host differs from local preparation"
        }
        require(coordinatorAdmission.targetRoot == preparation.remoteDeployPlan.publish.targetRoot) {
            "Phase 11.80 admission target root differs from local preparation"
        }

        val challenge = operatorApprovalChallengeSha256(
            reviewSha256 = review.reviewSha256,
            serviceDomain = preparation.serviceBinding.domain,
            servicePort = preparation.serviceBinding.port,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
            localPreparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = coordinatorAdmission.remoteHostIdentity,
            targetRoot = coordinatorAdmission.targetRoot,
            phase1180AdmissionSha256 = coordinatorAdmission.admissionSha256,
            phase1180InvocationAuthorizationSha256 = coordinatorAdmission.invocationAuthorizationSha256,
            phase1180CoordinatorInvocationId = coordinatorAdmission.coordinatorInvocationId,
            preparedAtEpochMillis = preparedAtEpochMillis,
            phase1180PermitExpiresAtEpochMillis = coordinatorAdmission.permitExpiresAtEpochMillis,
        )
        val base = SiteProductionDeploymentUiAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentUiAdmissionStatus.READY_FOR_EXPLICIT_OPERATOR_APPROVAL,
            reviewSha256 = review.reviewSha256,
            serviceDomain = preparation.serviceBinding.domain,
            servicePort = preparation.serviceBinding.port,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
            localPreparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = coordinatorAdmission.remoteHostIdentity,
            targetRoot = coordinatorAdmission.targetRoot,
            phase1180AdmissionSha256 = coordinatorAdmission.admissionSha256,
            phase1180InvocationAuthorizationSha256 = coordinatorAdmission.invocationAuthorizationSha256,
            phase1180CoordinatorInvocationId = coordinatorAdmission.coordinatorInvocationId,
            preparedAtEpochMillis = preparedAtEpochMillis,
            phase1180PermitExpiresAtEpochMillis = coordinatorAdmission.permitExpiresAtEpochMillis,
            requiresExactTargetConfirmation = true,
            requiresRealServerMutationConfirmation = true,
            requiresSingleAttemptNoRetryConfirmation = true,
            deployActionVisible = true,
            deployActionEnabled = false,
            authorizesCoordinatorInvocation = false,
            automaticRetryAuthorized = false,
            operatorApprovalChallengeSha256 = challenge,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    fun authorize(
        admission: SiteProductionDeploymentUiAdmission,
        approval: SiteProductionDeploymentUiApproval,
        approvedAtEpochMillis: Long,
    ): SiteProductionDeploymentUiExecutionAuthorization {
        validateAdmission(admission)
        require(approvedAtEpochMillis >= admission.preparedAtEpochMillis) {
            "UI approval cannot predate UI admission"
        }
        require(approvedAtEpochMillis <= admission.phase1180PermitExpiresAtEpochMillis) {
            "Phase 11.80 permit expired before UI approval"
        }
        require(approval.operatorApprovalChallengeSha256 == admission.operatorApprovalChallengeSha256) {
            "UI approval challenge is stale or bound to different inputs"
        }
        require(approval.exactTargetConfirmed) { "Exact production target must be explicitly confirmed" }
        require(approval.realServerMutationConfirmed) { "Real-server mutation must be explicitly confirmed" }
        require(approval.singleAttemptNoRetryConfirmed) {
            "Single-attempt/no-automatic-retry semantics must be explicitly confirmed"
        }

        val base = SiteProductionDeploymentUiExecutionAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentUiExecutionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_PHASE11_80_INVOCATION,
            uiAdmissionSha256 = admission.admissionSha256,
            phase1180AdmissionSha256 = admission.phase1180AdmissionSha256,
            reviewSha256 = admission.reviewSha256,
            serviceDomain = admission.serviceDomain,
            servicePort = admission.servicePort,
            sourceTreeSha256 = admission.sourceTreeSha256,
            deploymentPlanSha256 = admission.deploymentPlanSha256,
            remoteHostIdentity = admission.remoteHostIdentity,
            targetRoot = admission.targetRoot,
            phase1180CoordinatorInvocationId = admission.phase1180CoordinatorInvocationId,
            approvedAtEpochMillis = approvedAtEpochMillis,
            phase1180PermitExpiresAtEpochMillis = admission.phase1180PermitExpiresAtEpochMillis,
            authorizesSingleCoordinatorInvocation = true,
            requiresPhase1180DurableReplayFence = true,
            automaticRetryAuthorized = false,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateForReview(
        admission: SiteProductionDeploymentUiAdmission,
        review: SiteDeployerReviewState,
    ) {
        validateAdmission(admission)
        require(admission.reviewSha256 == review.reviewSha256) { "Production UI admission review changed" }
        require(admission.serviceDomain == review.serviceBinding.domain) { "Production UI admission domain changed" }
        require(admission.servicePort == review.serviceBinding.port) { "Production UI admission port changed" }
        require(admission.sourceTreeSha256 == review.preview.treeSha256) { "Production UI admission source tree changed" }
        require(admission.remoteHostIdentity == review.remoteTarget.remoteHostIdentity) {
            "Production UI admission remote host changed"
        }
        require(admission.targetRoot == review.remoteTarget.targetRoot) {
            "Production UI admission target root changed"
        }
    }

    fun validateForExecution(
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
        admission: SiteProductionDeploymentUiAdmission,
        invokedAtEpochMillis: Long,
    ) {
        validateAdmission(admission)
        validateAuthorization(authorization)
        require(authorization.uiAdmissionSha256 == admission.admissionSha256) { "UI authorization admission changed" }
        require(authorization.phase1180AdmissionSha256 == admission.phase1180AdmissionSha256) {
            "Phase 11.80 admission changed after UI approval"
        }
        require(authorization.reviewSha256 == admission.reviewSha256)
        require(authorization.serviceDomain == admission.serviceDomain)
        require(authorization.servicePort == admission.servicePort)
        require(authorization.sourceTreeSha256 == admission.sourceTreeSha256)
        require(authorization.deploymentPlanSha256 == admission.deploymentPlanSha256)
        require(authorization.remoteHostIdentity == admission.remoteHostIdentity)
        require(authorization.targetRoot == admission.targetRoot)
        require(authorization.phase1180CoordinatorInvocationId == admission.phase1180CoordinatorInvocationId)
        require(invokedAtEpochMillis >= authorization.approvedAtEpochMillis) {
            "Production UI execution cannot predate explicit approval"
        }
        require(invokedAtEpochMillis <= authorization.phase1180PermitExpiresAtEpochMillis) {
            "Phase 11.80 permit expired before production UI execution"
        }
    }

    fun complete(
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
        status: SiteProductionDeploymentUiExecutionStatus,
        phase1180ExecutionResultSha256: String,
        completedAtEpochMillis: Long,
        phase1192ExecutionResultSha256: String? = null,
        completeHttpServingPathVerified: Boolean = false,
        phase1198HttpsServingReceiptSha256: String? = null,
        phase1197ExecutionResultSha256: String? = null,
        completeHttpsTlsServingPathVerified: Boolean = false,
        servingOutcome: SiteServingOutcome? = null,
    ): SiteProductionDeploymentUiExecutionReceipt {
        validateAuthorization(authorization)
        require(sha256.matches(phase1180ExecutionResultSha256)) { "Phase 11.80 execution result SHA-256 is invalid" }
        require(completedAtEpochMillis >= authorization.approvedAtEpochMillis) {
            "Production UI completion cannot predate approval"
        }
        when (status) {
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED -> {
                require(completeHttpServingPathVerified)
                require(phase1192ExecutionResultSha256 != null && sha256.matches(phase1192ExecutionResultSha256)) {
                    "Verified complete HTTP serving path requires exact Phase 11.92 execution SHA-256"
                }
                require(!completeHttpsTlsServingPathVerified)
                require(phase1198HttpsServingReceiptSha256 == null)
                require(phase1197ExecutionResultSha256 == null)
            }
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_HTTPS_TLS_SERVING_PATH_VERIFIED -> {
                require(!completeHttpServingPathVerified)
                require(phase1192ExecutionResultSha256 == null)
                require(completeHttpsTlsServingPathVerified)
                require(phase1198HttpsServingReceiptSha256 != null && sha256.matches(phase1198HttpsServingReceiptSha256)) {
                    "Verified HTTPS/TLS serving path requires exact Phase 11.98 receipt SHA-256"
                }
                require(phase1197ExecutionResultSha256 != null && sha256.matches(phase1197ExecutionResultSha256)) {
                    "Verified HTTPS/TLS serving path requires exact Phase 11.97 execution SHA-256"
                }
            }
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_ROLLED_BACK_CLEAN,
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED,
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED -> {
                require(!completeHttpServingPathVerified)
                require(phase1192ExecutionResultSha256 == null)
                require(!completeHttpsTlsServingPathVerified)
                require(phase1198HttpsServingReceiptSha256 == null)
                require(phase1197ExecutionResultSha256 == null)
            }
        }
        val base = SiteProductionDeploymentUiExecutionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = status,
            uiAuthorizationSha256 = authorization.authorizationSha256,
            phase1180AdmissionSha256 = authorization.phase1180AdmissionSha256,
            phase1180ExecutionResultSha256 = phase1180ExecutionResultSha256,
            existingCoordinatorInvocationCount = 1,
            acceptedPhase1155TransactionDelegated = true,
            automaticRetryPerformed = false,
            completedAtEpochMillis = completedAtEpochMillis,
            receiptSha256 = "",
            phase1192ExecutionResultSha256 = phase1192ExecutionResultSha256,
            completeHttpServingPathVerified = completeHttpServingPathVerified,
            phase1198HttpsServingReceiptSha256 = phase1198HttpsServingReceiptSha256,
            phase1197ExecutionResultSha256 = phase1197ExecutionResultSha256,
            completeHttpsTlsServingPathVerified = completeHttpsTlsServingPathVerified,
            servingOutcome = servingOutcome,
        )
        return base.copy(receiptSha256 = receiptSha256(base)).also {
            validateReceipt(it, authorization)
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentUiAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentUiAdmissionStatus.READY_FOR_EXPLICIT_OPERATOR_APPROVAL)
        listOf(
            admission.reviewSha256,
            admission.sourceTreeSha256,
            admission.deploymentPlanSha256,
            admission.localPreparationSha256,
            admission.phase1180AdmissionSha256,
            admission.phase1180InvocationAuthorizationSha256,
            admission.operatorApprovalChallengeSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(admission.serviceDomain.isNotBlank())
        require(admission.servicePort in 1..65535)
        require(admission.remoteHostIdentity.isNotBlank())
        require(admission.targetRoot.startsWith("/"))
        require(admission.phase1180CoordinatorInvocationId.isNotBlank())
        require(admission.preparedAtEpochMillis >= 0L)
        require(admission.preparedAtEpochMillis <= admission.phase1180PermitExpiresAtEpochMillis)
        require(admission.requiresExactTargetConfirmation)
        require(admission.requiresRealServerMutationConfirmation)
        require(admission.requiresSingleAttemptNoRetryConfirmation)
        require(admission.deployActionVisible)
        require(!admission.deployActionEnabled)
        require(!admission.authorizesCoordinatorInvocation)
        require(!admission.automaticRetryAuthorized)
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = "")))
    }

    fun validateAuthorization(authorization: SiteProductionDeploymentUiExecutionAuthorization) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(authorization.status == SiteProductionDeploymentUiExecutionAuthorizationStatus
            .AUTHORIZED_FOR_SINGLE_PHASE11_80_INVOCATION)
        listOf(
            authorization.uiAdmissionSha256,
            authorization.phase1180AdmissionSha256,
            authorization.reviewSha256,
            authorization.sourceTreeSha256,
            authorization.deploymentPlanSha256,
            authorization.authorizationSha256,
        ).forEach { require(sha256.matches(it)) }
        require(authorization.serviceDomain.isNotBlank())
        require(authorization.servicePort in 1..65535)
        require(authorization.remoteHostIdentity.isNotBlank())
        require(authorization.targetRoot.startsWith("/"))
        require(authorization.phase1180CoordinatorInvocationId.isNotBlank())
        require(authorization.approvedAtEpochMillis >= 0L)
        require(authorization.approvedAtEpochMillis <= authorization.phase1180PermitExpiresAtEpochMillis)
        require(authorization.authorizesSingleCoordinatorInvocation)
        require(authorization.requiresPhase1180DurableReplayFence)
        require(!authorization.automaticRetryAuthorized)
        require(authorization.authorizationSha256 == authorizationSha256(authorization.copy(authorizationSha256 = "")))
    }

    fun validateReceipt(
        receipt: SiteProductionDeploymentUiExecutionReceipt,
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
    ) {
        validateAuthorization(authorization)
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(receipt.uiAuthorizationSha256 == authorization.authorizationSha256)
        require(receipt.phase1180AdmissionSha256 == authorization.phase1180AdmissionSha256)
        require(sha256.matches(receipt.phase1180ExecutionResultSha256))
        require(receipt.existingCoordinatorInvocationCount == 1)
        require(receipt.acceptedPhase1155TransactionDelegated)
        when (receipt.status) {
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED -> {
                require(receipt.completeHttpServingPathVerified)
                require(receipt.phase1192ExecutionResultSha256 != null &&
                    sha256.matches(receipt.phase1192ExecutionResultSha256))
                require(!receipt.completeHttpsTlsServingPathVerified)
                require(receipt.phase1198HttpsServingReceiptSha256 == null)
                require(receipt.phase1197ExecutionResultSha256 == null)
            }
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_HTTPS_TLS_SERVING_PATH_VERIFIED -> {
                require(!receipt.completeHttpServingPathVerified)
                require(receipt.phase1192ExecutionResultSha256 == null)
                require(receipt.completeHttpsTlsServingPathVerified)
                require(receipt.phase1198HttpsServingReceiptSha256 != null &&
                    sha256.matches(receipt.phase1198HttpsServingReceiptSha256))
                require(receipt.phase1197ExecutionResultSha256 != null &&
                    sha256.matches(receipt.phase1197ExecutionResultSha256))
            }
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_ROLLED_BACK_CLEAN,
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED,
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED -> {
                require(!receipt.completeHttpServingPathVerified)
                require(receipt.phase1192ExecutionResultSha256 == null)
                require(!receipt.completeHttpsTlsServingPathVerified)
                require(receipt.phase1198HttpsServingReceiptSha256 == null)
                require(receipt.phase1197ExecutionResultSha256 == null)
            }
        }
        val outcome = receipt.servingOutcome
        when (receipt.status) {
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED -> {
                require(outcome != null && outcome.externallyReachable && outcome.verifiedUrl != null) {
                    "Caddy publication requires an externally verified URL"
                }
            }
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED -> {
                require(outcome != null && !outcome.externallyReachable && outcome.failureCategory != null) {
                    "Unverified publication requires the concrete serving failure"
                }
            }
            SiteProductionDeploymentUiExecutionStatus.COORDINATOR_ROLLED_BACK_CLEAN -> require(outcome == null)
            else -> require(outcome == null || outcome.externallyReachable) {
                "A verified serving status cannot carry an unreachable outcome"
            }
        }
        require(!receipt.automaticRetryPerformed)
        require(receipt.completedAtEpochMillis >= authorization.approvedAtEpochMillis)
        require(sha256.matches(receipt.receiptSha256))
        require(receipt.receiptSha256 == receiptSha256(receipt.copy(receiptSha256 = "")))
    }

    internal fun admissionSha256ForTest(admissionWithoutSha: SiteProductionDeploymentUiAdmission): String =
        admissionSha256(admissionWithoutSha.copy(admissionSha256 = ""))

    private fun operatorApprovalChallengeSha256(
        reviewSha256: String,
        serviceDomain: String,
        servicePort: Int,
        sourceTreeSha256: String,
        deploymentPlanSha256: String,
        localPreparationSha256: String,
        remoteHostIdentity: String,
        targetRoot: String,
        phase1180AdmissionSha256: String,
        phase1180InvocationAuthorizationSha256: String,
        phase1180CoordinatorInvocationId: String,
        preparedAtEpochMillis: Long,
        phase1180PermitExpiresAtEpochMillis: Long,
    ): String = digest(
        buildString {
            append("purpose=phase11.81-production-ui-operator-approval\n")
            append("reviewSha256=").append(reviewSha256).append('\n')
            append("serviceDomain=").append(serviceDomain).append('\n')
            append("servicePort=").append(servicePort).append('\n')
            append("sourceTreeSha256=").append(sourceTreeSha256).append('\n')
            append("deploymentPlanSha256=").append(deploymentPlanSha256).append('\n')
            append("localPreparationSha256=").append(localPreparationSha256).append('\n')
            append("remoteHostIdentity=").append(remoteHostIdentity).append('\n')
            append("targetRoot=").append(targetRoot).append('\n')
            append("phase1180AdmissionSha256=").append(phase1180AdmissionSha256).append('\n')
            append("phase1180InvocationAuthorizationSha256=").append(phase1180InvocationAuthorizationSha256).append('\n')
            append("phase1180CoordinatorInvocationId=").append(phase1180CoordinatorInvocationId).append('\n')
            append("preparedAtEpochMillis=").append(preparedAtEpochMillis).append('\n')
            append("phase1180PermitExpiresAtEpochMillis=").append(phase1180PermitExpiresAtEpochMillis).append('\n')
        },
    )

    private fun admissionSha256(value: SiteProductionDeploymentUiAdmission): String = digest(
        buildString {
            append("contractVersion=").append(value.contractVersion).append('\n')
            append("status=").append(value.status.name).append('\n')
            append("reviewSha256=").append(value.reviewSha256).append('\n')
            append("serviceDomain=").append(value.serviceDomain).append('\n')
            append("servicePort=").append(value.servicePort).append('\n')
            append("sourceTreeSha256=").append(value.sourceTreeSha256).append('\n')
            append("deploymentPlanSha256=").append(value.deploymentPlanSha256).append('\n')
            append("localPreparationSha256=").append(value.localPreparationSha256).append('\n')
            append("remoteHostIdentity=").append(value.remoteHostIdentity).append('\n')
            append("targetRoot=").append(value.targetRoot).append('\n')
            append("phase1180AdmissionSha256=").append(value.phase1180AdmissionSha256).append('\n')
            append("phase1180InvocationAuthorizationSha256=").append(value.phase1180InvocationAuthorizationSha256).append('\n')
            append("phase1180CoordinatorInvocationId=").append(value.phase1180CoordinatorInvocationId).append('\n')
            append("preparedAtEpochMillis=").append(value.preparedAtEpochMillis).append('\n')
            append("phase1180PermitExpiresAtEpochMillis=").append(value.phase1180PermitExpiresAtEpochMillis).append('\n')
            append("requiresExactTargetConfirmation=").append(value.requiresExactTargetConfirmation).append('\n')
            append("requiresRealServerMutationConfirmation=").append(value.requiresRealServerMutationConfirmation).append('\n')
            append("requiresSingleAttemptNoRetryConfirmation=").append(value.requiresSingleAttemptNoRetryConfirmation).append('\n')
            append("deployActionVisible=").append(value.deployActionVisible).append('\n')
            append("deployActionEnabled=").append(value.deployActionEnabled).append('\n')
            append("authorizesCoordinatorInvocation=").append(value.authorizesCoordinatorInvocation).append('\n')
            append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
            append("operatorApprovalChallengeSha256=").append(value.operatorApprovalChallengeSha256).append('\n')
        },
    )

    private fun authorizationSha256(value: SiteProductionDeploymentUiExecutionAuthorization): String = digest(
        buildString {
            append("contractVersion=").append(value.contractVersion).append('\n')
            append("status=").append(value.status.name).append('\n')
            append("uiAdmissionSha256=").append(value.uiAdmissionSha256).append('\n')
            append("phase1180AdmissionSha256=").append(value.phase1180AdmissionSha256).append('\n')
            append("reviewSha256=").append(value.reviewSha256).append('\n')
            append("serviceDomain=").append(value.serviceDomain).append('\n')
            append("servicePort=").append(value.servicePort).append('\n')
            append("sourceTreeSha256=").append(value.sourceTreeSha256).append('\n')
            append("deploymentPlanSha256=").append(value.deploymentPlanSha256).append('\n')
            append("remoteHostIdentity=").append(value.remoteHostIdentity).append('\n')
            append("targetRoot=").append(value.targetRoot).append('\n')
            append("phase1180CoordinatorInvocationId=").append(value.phase1180CoordinatorInvocationId).append('\n')
            append("approvedAtEpochMillis=").append(value.approvedAtEpochMillis).append('\n')
            append("phase1180PermitExpiresAtEpochMillis=").append(value.phase1180PermitExpiresAtEpochMillis).append('\n')
            append("authorizesSingleCoordinatorInvocation=").append(value.authorizesSingleCoordinatorInvocation).append('\n')
            append("requiresPhase1180DurableReplayFence=").append(value.requiresPhase1180DurableReplayFence).append('\n')
            append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
        },
    )

    private fun receiptSha256(value: SiteProductionDeploymentUiExecutionReceipt): String = digest(
        buildString {
            append("contractVersion=").append(value.contractVersion).append('\n')
            append("status=").append(value.status.name).append('\n')
            append("uiAuthorizationSha256=").append(value.uiAuthorizationSha256).append('\n')
            append("phase1180AdmissionSha256=").append(value.phase1180AdmissionSha256).append('\n')
            append("phase1180ExecutionResultSha256=").append(value.phase1180ExecutionResultSha256).append('\n')
            append("existingCoordinatorInvocationCount=").append(value.existingCoordinatorInvocationCount).append('\n')
            append("acceptedPhase1155TransactionDelegated=").append(value.acceptedPhase1155TransactionDelegated).append('\n')
            append("automaticRetryPerformed=").append(value.automaticRetryPerformed).append('\n')
            append("completedAtEpochMillis=").append(value.completedAtEpochMillis).append('\n')
            append("phase1192ExecutionResultSha256=").append(value.phase1192ExecutionResultSha256 ?: "").append('\n')
            append("completeHttpServingPathVerified=").append(value.completeHttpServingPathVerified).append('\n')
            append("phase1198HttpsServingReceiptSha256=")
                .append(value.phase1198HttpsServingReceiptSha256 ?: "").append('\n')
            append("phase1197ExecutionResultSha256=")
                .append(value.phase1197ExecutionResultSha256 ?: "").append('\n')
            append("completeHttpsTlsServingPathVerified=")
                .append(value.completeHttpsTlsServingPathVerified).append('\n')
            value.servingOutcome?.let { outcome ->
                append("servingBackend=").append(outcome.backend?.name ?: "").append('\n')
                append("servingPlannedUrl=").append(outcome.plannedUrl).append('\n')
                append("servingVerifiedUrl=").append(outcome.verifiedUrl ?: "").append('\n')
                append("servingOnServer=").append(outcome.servedOnServer).append('\n')
                append("servingExternallyReachable=").append(outcome.externallyReachable).append('\n')
                append("servingConfigRolledBack=").append(outcome.configRolledBack).append('\n')
                append("servingFailureCategory=").append(outcome.failureCategory?.name ?: "").append('\n')
                append("servingFailureMessage=").append(outcome.failureMessage ?: "").append('\n')
            }
        },
    )

    private fun digest(canonical: String): String = MessageDigest.getInstance("SHA-256")
        .digest(canonical.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
