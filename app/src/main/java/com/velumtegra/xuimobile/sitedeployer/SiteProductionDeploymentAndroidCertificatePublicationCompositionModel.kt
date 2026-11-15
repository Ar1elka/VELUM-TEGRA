package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteExactDomainCertificateReuseBindingReport
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy

enum class SiteProductionDeploymentCertificatePublicationCompositionStatus {
    HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE,
    BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
    BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
    BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
}

data class SiteProductionDeploymentCertificatePublicationCompositionResult(
    val contractVersion: Int,
    val status: SiteProductionDeploymentCertificatePublicationCompositionStatus,
    val preparationSha256: String,
    val staticTargetTreeSha256: String,
    val realVpsExecutionProofSha256: String,
    val eligibilityReportSha256: String,
    val bindingReport: SiteExactDomainCertificateReuseBindingReport,
    val strategy: SiteWebServingStrategy,
    val publicationPlan: SiteWebServingPublicationPlan?,
    val realVpsExecutionProofValidated: Boolean,
    val publicationPlanSelected: Boolean,
    val productionNetworkTouchedByComposition: Boolean,
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
    val compositionSha256: String,
)
