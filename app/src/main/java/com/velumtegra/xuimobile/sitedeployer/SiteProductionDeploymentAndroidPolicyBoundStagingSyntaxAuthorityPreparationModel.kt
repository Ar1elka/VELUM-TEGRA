package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus

enum class SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus {
    READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
    BLOCKED_BY_POLICY_BOUND_CONFIG_MUTATION_PREPARATION,
}

data class SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus,
    val servingPolicySelectionSha256: String,
    val policyBoundPreflightExecutionResultSha256: String,
    val policyBoundConfigMutationPreparationResultSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val readOnlyPreflightSha256: String,
    val readOnlyPreflightStatus: SiteWebServingReadOnlyPreflightStatus,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String?,
    val stagingSyntaxExecutionPlan: SiteWebServingConfigStagingSyntaxExecutionPlan?,
    val exactPolicyPreparationBindingVerified: Boolean,
    val stagingSyntaxExecutionPlanCreated: Boolean,
    val productionNetworkTouchedByAuthorityPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val stagingConfigWriteAuthorized: Boolean,
    val validationConfigWriteAuthorized: Boolean,
    val isolatedNginxSyntaxValidationAuthorized: Boolean,
    val exactConfigActivationAuthorized: Boolean,
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
