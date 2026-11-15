package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorResult

enum class SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmissionStatus {
    READY_FOR_ONE_EXISTING_COORDINATOR_INVOCATION,
}

data class SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmissionStatus,
    val invocationAuthorizationSha256: String,
    val executionAuthorizationSha256: String,
    val coordinatorRequestSha256: String,
    val runtimeIdentitySha256: String,
    val permitSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val capabilityProfileSha256: String,
    val localPreparationSha256: String,
    val deploymentPlanSha256: String,
    val sourceTreeSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val coordinatorInvocationId: String,
    val evaluatedAtEpochMillis: Long,
    val permitExpiresAtEpochMillis: Long,
    val requiresDurableCoordinatorInvocationFence: Boolean,
    val delegatesToExistingCoordinator: Boolean,
    val delegatesTransportToAcceptedPhase1155Transaction: Boolean,
    val addsNewRemoteMutationPrimitive: Boolean,
    val automaticRetryAuthorized: Boolean,
    val arbitraryCommandAuthorized: Boolean,
    val exposesDeployUiAction: Boolean,
    val admissionSha256: String,
)

enum class SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus {
    COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
    COORDINATOR_ROLLED_BACK_CLEAN,
}

data class SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus,
    val admissionSha256: String,
    val invocationAuthorizationSha256: String,
    val executionAuthorizationSha256: String,
    val coordinatorRequestSha256: String,
    val localPreparationSha256: String,
    val deploymentPlanSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val staticFileTransactionResult: SiteProductionDeploymentRealVpsStaticFileTransactionResult,
    val coordinatorResult: SiteDeploymentCoordinatorResult,
    val coordinatorInvocationFenceConsumed: Boolean,
    val coordinatorInvoked: Boolean,
    val existingCoordinatorInvocationCount: Int,
    val acceptedPhase1155TransactionDelegated: Boolean,
    val newRemoteMutationPrimitiveAdded: Boolean,
    val automaticRetryPerformed: Boolean,
    val arbitraryCommandInputAccepted: Boolean,
    val exposesDeployUiAction: Boolean,
    val executedAtEpochMillis: Long,
    val executionResultSha256: String,
)
