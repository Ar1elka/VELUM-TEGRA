package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

enum class SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus {
    READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
    BLOCKED_BY_POLICY_BOUND_STAGING_SYNTAX_AUTHORITY_PREPARATION,
}

data class SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus,
    val policyBoundStagingSyntaxAuthorityPreparationResultSha256: String,
    val servingPolicySelectionSha256: String,
    val policyBoundPreflightExecutionResultSha256: String,
    val policyBoundConfigMutationPreparationResultSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val readOnlyPreflightSha256: String,
    val mutationTransactionId: String,
    val mutationPreparationSha256: String?,
    val stagingSyntaxExecutionPlanSha256: String?,
    val requiresFreshCredentialResolution: Boolean,
    val requiresLiveRemoteHostKeyVerification: Boolean,
    val realVpsExecutionEligible: Boolean,
    val exactConfigActivationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val certificateMutationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val admissionSha256: String,
)

enum class SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionStatus {
    EXECUTED_AND_CLEANED_WITHOUT_EXACT_CONFIG_ACTIVATION_OR_RELOAD,
}

data class SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionStatus,
    val admissionSha256: String,
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
    val phase11_59ExecutionProof:
        SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionProof,
    val freshCredentialResolutionProofSha256: String,
    val exactProductionChainBindingVerified: Boolean,
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
    val certificateMutationPerformed: Boolean,
    val dnsMutationPerformed: Boolean,
    val firewallMutationPerformed: Boolean,
    val packageInstallPerformed: Boolean,
    val privateKeyContentReadPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val executionResultSha256: String,
)
