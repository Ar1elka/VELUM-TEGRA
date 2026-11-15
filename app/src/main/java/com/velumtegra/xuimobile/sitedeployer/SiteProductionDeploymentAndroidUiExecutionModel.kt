package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeployerReviewState
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy

enum class SiteProductionDeploymentUiAdmissionStatus {
    READY_FOR_EXPLICIT_OPERATOR_APPROVAL,
}

data class SiteProductionDeploymentUiAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentUiAdmissionStatus,
    val reviewSha256: String,
    val serviceDomain: String,
    val servicePort: Int,
    val sourceTreeSha256: String,
    val deploymentPlanSha256: String,
    val localPreparationSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val phase1180AdmissionSha256: String,
    val phase1180InvocationAuthorizationSha256: String,
    val phase1180CoordinatorInvocationId: String,
    val preparedAtEpochMillis: Long,
    val phase1180PermitExpiresAtEpochMillis: Long,
    val requiresExactTargetConfirmation: Boolean,
    val requiresRealServerMutationConfirmation: Boolean,
    val requiresSingleAttemptNoRetryConfirmation: Boolean,
    val deployActionVisible: Boolean,
    val deployActionEnabled: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val automaticRetryAuthorized: Boolean,
    val operatorApprovalChallengeSha256: String,
    val admissionSha256: String,
)

data class SiteProductionDeploymentUiApproval(
    val operatorApprovalChallengeSha256: String,
    val exactTargetConfirmed: Boolean,
    val realServerMutationConfirmed: Boolean,
    val singleAttemptNoRetryConfirmed: Boolean,
)

enum class SiteProductionDeploymentUiExecutionAuthorizationStatus {
    AUTHORIZED_FOR_SINGLE_PHASE11_80_INVOCATION,
}

data class SiteProductionDeploymentUiExecutionAuthorization(
    val contractVersion: Int,
    val status: SiteProductionDeploymentUiExecutionAuthorizationStatus,
    val uiAdmissionSha256: String,
    val phase1180AdmissionSha256: String,
    val reviewSha256: String,
    val serviceDomain: String,
    val servicePort: Int,
    val sourceTreeSha256: String,
    val deploymentPlanSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val phase1180CoordinatorInvocationId: String,
    val approvedAtEpochMillis: Long,
    val phase1180PermitExpiresAtEpochMillis: Long,
    val authorizesSingleCoordinatorInvocation: Boolean,
    val requiresPhase1180DurableReplayFence: Boolean,
    val automaticRetryAuthorized: Boolean,
    val authorizationSha256: String,
)

enum class SiteProductionDeploymentUiExecutionStatus {
    COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
    COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED,
    COORDINATOR_COMMITTED_AND_HTTPS_TLS_SERVING_PATH_VERIFIED,
    COORDINATOR_ROLLED_BACK_CLEAN,

    /** Files committed and Caddy serves the exact site, verified from the device. */
    COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED,

    /** Files committed, but the site is not (yet) reachable; see servingOutcome for the reason. */
    COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED,
}

data class SiteProductionDeploymentUiExecutionReceipt(
    val contractVersion: Int,
    val status: SiteProductionDeploymentUiExecutionStatus,
    val uiAuthorizationSha256: String,
    val phase1180AdmissionSha256: String,
    val phase1180ExecutionResultSha256: String,
    val existingCoordinatorInvocationCount: Int,
    val acceptedPhase1155TransactionDelegated: Boolean,
    val automaticRetryPerformed: Boolean,
    val completedAtEpochMillis: Long,
    val receiptSha256: String,
    val phase1192ExecutionResultSha256: String? = null,
    val completeHttpServingPathVerified: Boolean = false,
    val phase1198HttpsServingReceiptSha256: String? = null,
    val phase1197ExecutionResultSha256: String? = null,
    val completeHttpsTlsServingPathVerified: Boolean = false,
    /** Honest serving result shown to the operator (verified URL or the concrete failure). */
    val servingOutcome: com.velumtegra.xuimobile.core.site.SiteServingOutcome? = null,
)

/**
 * Read-only projection of the exact production target currently installed in the process-local
 * Phase 11.82 execution context. It is presentation input only and carries no mutation authority.
 */
data class SiteProductionDeploymentUiTargetBinding(
    val remoteHostIdentity: String,
    val targetRoot: String,
    val owner: String,
    val group: String,
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy,
    val certificateReuseRequested: Boolean,
    val trustedServerKeySha256: String,
)

/**
 * Phase 11.81 UI seam. The default app implementation is deliberately disabled; Phase 11.82 may
 * install the independently accepted production execution composition without changing this UI
 * admission contract. A concrete port must preserve the Phase 11.80 durable replay fence and may
 * execute at most one coordinator invocation for one UI authorization.
 */
interface SiteDeployerProductionExecutionPort {
    /**
     * Optional read-only exact target projection used to build the operator review against the same
     * host/path/trust inputs as the installed production context. Implementations that do not expose
     * a production context preserve the accepted review-only fixture behavior by returning null.
     */
    fun currentTargetBinding(): SiteProductionDeploymentUiTargetBinding? = null

    fun currentAdmission(review: SiteDeployerReviewState): SiteProductionDeploymentUiAdmission?

    suspend fun executeOnce(
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
    ): SiteProductionDeploymentUiExecutionReceipt
}

internal object DisabledSiteDeployerProductionExecutionPort : SiteDeployerProductionExecutionPort {
    override fun currentAdmission(review: SiteDeployerReviewState): SiteProductionDeploymentUiAdmission? = null

    override suspend fun executeOnce(
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
    ): SiteProductionDeploymentUiExecutionReceipt = error(
        "Production Site Deployer execution port is not installed",
    )
}
