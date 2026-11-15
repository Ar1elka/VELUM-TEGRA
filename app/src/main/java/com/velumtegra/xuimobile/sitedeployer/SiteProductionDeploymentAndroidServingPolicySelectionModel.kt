package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy

enum class SiteProductionDeploymentServingPolicySelectionStatus {
    HTTP_PUBLICATION_PLAN_READY_EXPLICIT_NO_CERTIFICATE_REUSE,
    HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
    BLOCKED_REUSE_REQUESTED_NO_CONFIGURED_CERTIFICATE,
    BLOCKED_REUSE_REQUESTED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
    BLOCKED_REUSE_REQUESTED_REQUIRES_REVIEW_OR_RECONCILIATION,
}

data class SiteProductionDeploymentServingPolicySelectionResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentServingPolicySelectionStatus,
    val preparationSha256: String,
    val staticTargetTreeSha256: String,
    val requestedCertificateReuseMode: SiteCertificateReuseMode,
    val requestedDomain: String?,
    val strategy: SiteWebServingStrategy,
    val selectedProtocol: SiteWebServingProtocol?,
    val certificateCompositionSha256: String?,
    val publicationPlan: SiteWebServingPublicationPlan?,
    val publicationPlanSelected: Boolean,
    val explicitUserIntentPreserved: Boolean,
    val silentProtocolDowngradePerformed: Boolean,
    val productionNetworkTouchedBySelection: Boolean,
    val remoteMutationPerformed: Boolean,
    val certificateMutationAuthorized: Boolean,
    val tlsConfigurationAuthorized: Boolean,
    val nginxMutationAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val privateKeyContentReadAuthorized: Boolean,
    val automaticRetryAuthorized: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val selectionSha256: String,
)
