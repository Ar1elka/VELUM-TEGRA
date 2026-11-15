package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

enum class SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus {
    READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
}

data class SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus,
    val policyBoundConfigActivationExecutionResultSha256: String,
    val policyBoundConfigActivationAuthorityPreparationResultSha256: String,
    val policyBoundStagingSyntaxExecutionResultSha256: String,
    val policyBoundStagingSyntaxAuthorityPreparationResultSha256: String,
    val servingPolicySelectionSha256: String,
    val policyBoundPreflightExecutionResultSha256: String,
    val policyBoundConfigMutationPreparationResultSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val readOnlyPreflightSha256: String,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String,
    val stagingSyntaxExecutionPlanSha256: String,
    val phase11_59ExecutionProofSha256: String,
    val activationExecutionPlanSha256: String,
    val phase11_60ExecutionProofSha256: String,
    val nginxReloadExecutionPlan: SiteWebServingNginxReloadExecutionPlan,
    val exactProductionChainBindingVerified: Boolean,
    val successfulConfigActivationExecutionProofValidated: Boolean,
    val nginxReloadExecutionPlanCreated: Boolean,
    val productionNetworkTouchedByAuthorityPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val exactConfigActivationPerformedByAuthorityPreparation: Boolean,
    val nginxReloadExecutionAuthorized: Boolean,
    val nginxReloadPerformed: Boolean,
    val configMutationAuthorized: Boolean,
    val certificateMutationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val authorityPreparationResultSha256: String,
)
