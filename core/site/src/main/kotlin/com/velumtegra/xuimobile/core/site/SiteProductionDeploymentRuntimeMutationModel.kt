package com.velumtegra.xuimobile.core.site

enum class SiteProductionDeploymentRuntimeMutationStatus {
    BLOCKED,
    AWAITING_RUNTIME_MUTATION_APPROVAL,
    RUNTIME_MUTATION_PERMIT_ISSUED,
    AUTHORIZED_FOR_SINGLE_COORDINATOR_INVOCATION,
}

data class SiteProductionDeploymentRuntimeIdentity(
    val runtimeSessionId: String,
    val remoteHostIdentity: String,
    val transportImplementationId: String,
    val capabilityProfileSha256: String,
)

data class SiteProductionDeploymentRuntimeMutationRequest(
    val executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
    val executionRequest: SiteProductionDeploymentExecutionRequest,
    val runtimeIdentity: SiteProductionDeploymentRuntimeIdentity,
    val coordinatorInvocationId: String,
    val evaluatedAtEpochMillis: Long,
    val requestedPermitLifetimeMillis: Long,
)

data class SiteProductionDeploymentRuntimeMutationBlocker(
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentRuntimeMutationDraft(
    val contractVersion: Int,
    val status: SiteProductionDeploymentRuntimeMutationStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val requiresAtomicOneShotConsumption: Boolean,
    val executionAttemptId: String,
    val coordinatorInvocationId: String,
    val executionAuthorizationSha256: String,
    val readyRecordSha256: String,
    val coordinatorRequestSha256: String,
    val capabilityProfileSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val runtimeIdentitySha256: String,
    val evaluatedAtEpochMillis: Long,
    val readinessEvidenceExpiresAtEpochMillis: Long,
    val permitExpiresAtEpochMillis: Long,
    val blockers: List<SiteProductionDeploymentRuntimeMutationBlocker>,
    val runtimeMutationApprovalChallengeSha256: String,
    val runtimeMutationDraftSha256: String,
)

data class SiteProductionDeploymentRuntimeMutationApproval(
    val runtimeMutationApprovalChallengeSha256: String,
    val confirmed: Boolean,
)

data class SiteProductionDeploymentRuntimeMutationPermit(
    val contractVersion: Int,
    val status: SiteProductionDeploymentRuntimeMutationStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val requiresAtomicOneShotConsumption: Boolean,
    val executionAttemptId: String,
    val coordinatorInvocationId: String,
    val executionAuthorizationSha256: String,
    val readyRecordSha256: String,
    val coordinatorRequestSha256: String,
    val capabilityProfileSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val runtimeIdentitySha256: String,
    val evaluatedAtEpochMillis: Long,
    val readinessEvidenceExpiresAtEpochMillis: Long,
    val permitExpiresAtEpochMillis: Long,
    val runtimeMutationApprovalChallengeSha256: String,
    val permitSha256: String,
)

fun interface SiteProductionDeploymentRuntimeMutationConsumptionPort {
    /**
     * Atomically records first consumption of [permitSha256]. Returning false means the permit
     * was already consumed or the replay fence cannot safely prove first use.
     */
    fun consumeOnce(permitSha256: String): Boolean
}

data class SiteProductionDeploymentCoordinatorInvocationAuthorization(
    val contractVersion: Int,
    val status: SiteProductionDeploymentRuntimeMutationStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val singleUseConsumed: Boolean,
    val executionAttemptId: String,
    val coordinatorInvocationId: String,
    val executionAuthorizationSha256: String,
    val coordinatorRequestSha256: String,
    val runtimeIdentitySha256: String,
    val permitSha256: String,
    val consumedAtEpochMillis: Long,
    val permitExpiresAtEpochMillis: Long,
    val invocationAuthorizationSha256: String,
)
