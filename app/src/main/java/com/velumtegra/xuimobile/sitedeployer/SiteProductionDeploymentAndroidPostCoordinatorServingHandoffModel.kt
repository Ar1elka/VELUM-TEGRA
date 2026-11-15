package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence

enum class SiteProductionDeploymentPostCoordinatorServingHandoffStatus {
    READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
    BLOCKED_COORDINATOR_ROLLED_BACK_CLEAN,
    BLOCKED_CERTIFICATE_REUSE_REQUIRES_VALIDATED_COMPOSITION,
    BLOCKED_BY_EXPLICIT_SERVING_POLICY,
}

data class SiteProductionDeploymentPostCoordinatorServingHandoff(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorServingHandoffStatus,
    val phase1180AdmissionSha256: String,
    val phase1180ExecutionResultSha256: String,
    val localPreparationSha256: String,
    val sourceTreeSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val staticPublicationEvidence: SiteStaticPublicationEvidence?,
    val servingPolicySelection: SiteProductionDeploymentServingPolicySelectionResult?,
    val servingPolicySelectionSha256: String?,
    val requiresFreshPolicyBoundWebServingPreflight: Boolean,
    val authorizesWebServingNetworkExecution: Boolean,
    val authorizesWebServingMutation: Boolean,
    val authorizesCoordinatorReinvocation: Boolean,
    val automaticRetryAuthorized: Boolean,
    val handoffSha256: String,
)
