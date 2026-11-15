package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

enum class SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus {
    READY_FOR_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
}

data class SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus,
    val phase1187ExecutionResultSha256: String,
    val phase1187AdmissionSha256: String,
    val phase1186AuthorityPreparationResultSha256: String,
    val phase1185PreparationResultSha256: String,
    val phase1184ExecutionResultSha256: String,
    val phase1183HandoffSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169ExecutionResultSha256: String,
    val phase1170PreparationResultSha256: String,
    val phase1171AuthorityPreparationResultSha256: String,
    val phase1172ExecutionResultSha256: String,
    val phase1173AuthorityPreparation:
        SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String,
    val stagingSyntaxExecutionPlanSha256: String,
    val phase11_59ExecutionProofSha256: String,
    val activationExecutionPlanSha256: String,
    val successfulPostCoordinatorStagingSyntaxExecutionProofValidated: Boolean,
    val activationExecutionPlanCreated: Boolean,
    val productionNetworkTouchedByAuthorityPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val stagingConfigWriteAuthorized: Boolean,
    val exactConfigActivationAuthorized: Boolean,
    val nginxSyntaxValidationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val coordinatorReinvocationAuthorized: Boolean,
    val staticPublicationReplayAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val authorityPreparationResultSha256: String,
)
