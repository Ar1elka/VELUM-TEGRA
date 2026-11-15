package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus

enum class SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus {
    READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
    BLOCKED_BY_POST_COORDINATOR_CONFIG_MUTATION_PREPARATION,
}

data class SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus,
    val phase1183HandoffSha256: String,
    val phase1184AdmissionSha256: String,
    val phase1184ExecutionResultSha256: String,
    val phase1185PreparationResultSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169ExecutionResultSha256: String,
    val phase1170PreparationResultSha256: String,
    val phase1171AuthorityPreparation: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val preflightStatus: SiteWebServingReadOnlyPreflightStatus,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String?,
    val stagingSyntaxExecutionPlanSha256: String?,
    val stagingSyntaxExecutionPlanCreated: Boolean,
    val productionNetworkTouchedByAuthorityPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val coordinatorReinvoked: Boolean,
    val staticPublicationReplayPerformed: Boolean,
    val stagingConfigWriteAuthorized: Boolean,
    val validationConfigWriteAuthorized: Boolean,
    val isolatedNginxSyntaxValidationAuthorized: Boolean,
    val exactConfigActivationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val authorityPreparationResultSha256: String,
)
