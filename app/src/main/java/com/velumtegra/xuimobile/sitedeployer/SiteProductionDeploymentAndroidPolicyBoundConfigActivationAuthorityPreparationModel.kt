package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

enum class SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus {
    READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
}

data class SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus,
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
    val activationExecutionPlan: SiteWebServingConfigActivationExecutionPlan,
    val exactProductionChainBindingVerified: Boolean,
    val successfulStagingSyntaxExecutionProofValidated: Boolean,
    val activationExecutionPlanCreated: Boolean,
    val productionNetworkTouchedByAuthorityPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val stagingConfigWriteAuthorized: Boolean,
    val exactConfigActivationAuthorized: Boolean,
    val nginxSyntaxValidationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
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
