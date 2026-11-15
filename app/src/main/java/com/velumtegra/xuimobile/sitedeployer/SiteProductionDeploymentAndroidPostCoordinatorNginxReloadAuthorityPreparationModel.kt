package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

enum class SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus {
    READY_FOR_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
}

data class SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus,
    val phase1189ExecutionResultSha256: String,
    val phase1189AdmissionSha256: String,
    val phase1188AuthorityPreparationResultSha256: String,
    val phase1187ExecutionResultSha256: String,
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
    val phase1173AuthorityPreparationResultSha256: String,
    val phase1174ExecutionResultSha256: String,
    val phase1175AuthorityPreparation:
        SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
    val phase1175AuthorityPreparationResultSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String,
    val stagingSyntaxExecutionPlanSha256: String,
    val phase11_59ExecutionProofSha256: String,
    val activationExecutionPlanSha256: String,
    val phase11_60ExecutionProofSha256: String,
    val nginxReloadExecutionPlan: SiteWebServingNginxReloadExecutionPlan,
    val successfulPostCoordinatorConfigActivationExecutionProofValidated: Boolean,
    val nginxReloadExecutionPlanCreated: Boolean,
    val productionNetworkTouchedByAuthorityPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val exactConfigActivationPerformedByAuthorityPreparation: Boolean,
    val nginxReloadExecutionAuthorized: Boolean,
    val nginxReloadPerformed: Boolean,
    val coordinatorReinvocationAuthorized: Boolean,
    val staticPublicationReplayAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val authorityPreparationResultSha256: String,
)
