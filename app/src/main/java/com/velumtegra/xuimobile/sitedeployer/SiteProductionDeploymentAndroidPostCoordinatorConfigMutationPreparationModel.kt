package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus

enum class SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus {
    READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION,
    BLOCKED_BY_POST_COORDINATOR_READ_ONLY_PREFLIGHT,
}

data class SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationStatus,
    val phase1183HandoffSha256: String,
    val phase1184AdmissionSha256: String,
    val phase1184ExecutionResultSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169ExecutionResultSha256: String,
    val phase1170Preparation: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val preflightStatus: SiteWebServingReadOnlyPreflightStatus,
    val mutationTransactionId: String,
    val mutationPreparationCreated: Boolean,
    val productionNetworkTouchedByPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val coordinatorReinvoked: Boolean,
    val staticPublicationReplayPerformed: Boolean,
    val webServingMutationAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val preparationResultSha256: String,
)
