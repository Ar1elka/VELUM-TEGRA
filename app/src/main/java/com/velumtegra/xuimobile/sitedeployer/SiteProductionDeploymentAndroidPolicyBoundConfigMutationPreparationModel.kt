package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparation
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus

enum class SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus {
    READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY,
    BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT,
}

data class SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus,
    val servingPolicySelectionSha256: String,
    val policyBoundPreflightAdmissionSha256: String,
    val policyBoundPreflightExecutionResultSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val readOnlyPreflightSha256: String,
    val readOnlyPreflightStatus: SiteWebServingReadOnlyPreflightStatus,
    val mutationTransactionId: String,
    val mutationPreparation: SiteWebServingConfigMutationPreparation?,
    val exactPolicyPreflightBindingVerified: Boolean,
    val mutationPreparationCreated: Boolean,
    val productionNetworkTouchedByPreparation: Boolean,
    val remoteMutationPerformed: Boolean,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val certificateMutationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val preparationResultSha256: String,
)
