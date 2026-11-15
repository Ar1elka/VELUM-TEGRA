package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus

enum class SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus {
    READY_FOR_FRESH_POLICY_BOUND_READ_ONLY_PREFLIGHT,
}

data class SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus,
    val phase1183HandoffSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169Admission: SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val remoteHostIdentity: String,
    val requiresFreshCredentialResolution: Boolean,
    val requiresLiveHostKeyVerification: Boolean,
    val authorizesCoordinatorReinvocation: Boolean,
    val authorizesStaticPublicationReplay: Boolean,
    val authorizesWebServingMutation: Boolean,
    val automaticRetryAuthorized: Boolean,
    val admissionSha256: String,
)

data class SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult(
    val contractVersion: Int,
    val phase1184AdmissionSha256: String,
    val phase1183HandoffSha256: String,
    val phase1180ExecutionResultSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1169AdmissionSha256: String,
    val phase1169ExecutionResult: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
    val freshCredentialResolutionProofSha256: String,
    val publicationPlanSha256: String,
    val selectedProtocol: SiteWebServingProtocol,
    val preflightStatus: SiteWebServingReadOnlyPreflightStatus,
    val productionNetworkTouched: Boolean,
    val remoteMutationPerformed: Boolean,
    val coordinatorReinvoked: Boolean,
    val staticPublicationReplayPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
    val executionResultSha256: String,
)
