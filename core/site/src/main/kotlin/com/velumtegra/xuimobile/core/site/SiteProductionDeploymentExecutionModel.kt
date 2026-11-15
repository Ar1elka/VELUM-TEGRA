package com.velumtegra.xuimobile.core.site

enum class SiteProductionDeploymentExecutionStatus {
    BLOCKED,
    AWAITING_EXECUTION_APPROVAL,
    AUTHORIZED_FOR_COORDINATOR_HANDOFF,
}

data class SiteProductionDeploymentExecutionRequest(
    val readyRecord: SiteProductionDeploymentReadyRecord,
    val readinessRequest: SiteProductionDeploymentReadinessRequest,
    val coordinatorRequest: SiteDeploymentCoordinatorRequest,
    val transportCapabilities: SiteRemoteTransportCapabilities,
    val executionAttemptId: String,
    val evaluatedAtEpochMillis: Long,
)

data class SiteProductionDeploymentExecutionBlocker(
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentExecutionDraft(
    val contractVersion: Int,
    val status: SiteProductionDeploymentExecutionStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCoordinatorHandoff: Boolean,
    val requiresRuntimeMutationEnablement: Boolean,
    val executionAttemptId: String,
    val readyRecordSha256: String,
    val readinessSha256: String,
    val deploymentPlanSha256: String,
    val preflightSha256: String,
    val exportPlanSha256: String,
    val sourceTreeSha256: String,
    val coordinatorRequestSha256: String,
    val capabilityProfileSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val evaluatedAtEpochMillis: Long,
    val evidenceExpiresAtEpochMillis: Long,
    val blockers: List<SiteProductionDeploymentExecutionBlocker>,
    val executionApprovalChallengeSha256: String,
    val executionDraftSha256: String,
)

data class SiteProductionDeploymentExecutionApproval(
    val executionApprovalChallengeSha256: String,
    val confirmed: Boolean,
)

data class SiteProductionDeploymentExecutionAuthorization(
    val contractVersion: Int,
    val status: SiteProductionDeploymentExecutionStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCoordinatorHandoff: Boolean,
    val requiresRuntimeMutationEnablement: Boolean,
    val executionAttemptId: String,
    val readyRecordSha256: String,
    val readinessSha256: String,
    val deploymentPlanSha256: String,
    val preflightSha256: String,
    val exportPlanSha256: String,
    val sourceTreeSha256: String,
    val coordinatorRequestSha256: String,
    val capabilityProfileSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val evaluatedAtEpochMillis: Long,
    val evidenceExpiresAtEpochMillis: Long,
    val executionApprovalChallengeSha256: String,
    val executionAuthorizationSha256: String,
)
