package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus

enum class SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus {
    READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
    BLOCKED_BY_EXPLICIT_SERVING_POLICY,
}

data class SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus,
    val servingPolicySelectionSha256: String,
    val preparationSha256: String,
    val staticTargetTreeSha256: String,
    val selectedProtocol: SiteWebServingProtocol?,
    val publicationPlanSha256: String?,
    val remoteHostIdentity: String?,
    val readOnlyPreflightExecutionEligible: Boolean,
    val freshCredentialResolutionRequired: Boolean,
    val liveHostKeyVerificationRequired: Boolean,
    val productionNetworkTouchedByAdmission: Boolean,
    val remoteMutationAuthorized: Boolean,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val admissionSha256: String,
)

data class SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult(
    val contractVersion: Int,
    val servingPolicySelectionSha256: String,
    val admissionSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val preflightStatus: SiteWebServingReadOnlyPreflightStatus,
    val preflightExecutionProof:
        SiteProductionDeploymentRealVpsWebServingReadOnlyPreflightExecutionProof,
    val exactPolicyPlanBindingVerified: Boolean,
    val freshCredentialProofRequired: Boolean,
    val liveHostKeyVerified: Boolean,
    val remoteMutationPerformed: Boolean,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val privateKeyContentReadPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val executionResultSha256: String,
)
