package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

enum class SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus {
    READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
    BLOCKED_BY_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION,
}

data class SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus,
    val phase1186AuthorityPreparationResultSha256: String,
    val phase1183HandoffSha256: String,
    val phase1184ExecutionResultSha256: String,
    val phase1185PreparationResultSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169ExecutionResultSha256: String,
    val phase1170PreparationResultSha256: String,
    val phase1171AuthorityPreparationResultSha256: String,
    val phase1172Admission: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String?,
    val stagingSyntaxExecutionPlanSha256: String?,
    val requiresFreshCredentialResolution: Boolean,
    val requiresLiveRemoteHostKeyVerification: Boolean,
    val realVpsExecutionEligible: Boolean,
    val exactConfigActivationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val coordinatorReinvocationAuthorized: Boolean,
    val staticPublicationReplayAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val admissionSha256: String,
)

enum class SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus {
    EXECUTED_AND_CLEANED_WITHOUT_CONFIG_ACTIVATION_OR_COORDINATOR_REPLAY,
}

data class SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus,
    val phase1187AdmissionSha256: String,
    val phase1186AuthorityPreparationResultSha256: String,
    val phase1183HandoffSha256: String,
    val phase1184ExecutionResultSha256: String,
    val phase1185PreparationResultSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169ExecutionResultSha256: String,
    val phase1170PreparationResultSha256: String,
    val phase1171AuthorityPreparationResultSha256: String,
    val phase1172ExecutionResult: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
    val freshCredentialResolutionProofSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String,
    val stagingSyntaxExecutionPlanSha256: String,
    val exactPostCoordinatorChainBindingVerified: Boolean,
    val durableBaselineCheckpointRecorded: Boolean,
    val credentialLeaseMaterialConsumed: Boolean,
    val productionNetworkTouched: Boolean,
    val liveHostKeyPinVerified: Boolean,
    val operationOwnedStagingWritePerformed: Boolean,
    val operationOwnedValidationWritePerformed: Boolean,
    val nginxSyntaxValidationPassed: Boolean,
    val operationOwnedCleanupVerified: Boolean,
    val exactConfigActivationPerformed: Boolean,
    val webServerReloadPerformed: Boolean,
    val coordinatorReinvoked: Boolean,
    val staticPublicationReplayPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
    val executionResultSha256: String,
)
