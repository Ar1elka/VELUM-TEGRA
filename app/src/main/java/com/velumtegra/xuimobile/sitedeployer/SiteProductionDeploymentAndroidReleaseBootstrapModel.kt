package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingReadinessMode

/**
 * Product-level release flow selected before the production readiness request is frozen.
 *
 * FIRST_PUBLICATION_POST_COORDINATOR is the reviewed release-complete flow. The legacy
 * preconfigured mode remains selectable for compatibility, but it is deliberately not admitted by
 * the first-publication bootstrap publication gate.
 */
internal enum class SiteProductionDeploymentReleaseFlow {
    PRECONFIGURED_ENDPOINT,
    FIRST_PUBLICATION_POST_COORDINATOR,
}

internal data class SiteProductionDeploymentReleaseBootstrapEvidence(
    val releaseFlow: SiteProductionDeploymentReleaseFlow,
    val serverAccessId: String,
    val serverId: String,
    val remoteHostIdentity: String,
    val sshPort: Int,
    val sshUsername: String,
    val serverAccessPinnedHostKeySha256: String,
    val expectedServerKeySha256: String,
    val remoteObservationHostIdentity: String,
    val remoteObservationServerKeySha256: String,
    val serviceObservationHostIdentity: String,
    val serviceObservationServerKeySha256: String,
    val serviceDomain: String,
    val servicePort: Int,
    val serviceBindingReadinessMode: SiteProductionServiceBindingReadinessMode,
    val serviceBindingObservedConfigured: Boolean,
    val readyRecordServiceBindingReadinessMode: SiteProductionServiceBindingReadinessMode,
    val readyRecordOperatorApproved: Boolean,
    val readyRecordApprovalSha256: String,
    val preparationSha256: String,
    val deploymentPlanSha256: String,
    val sourceTreeSha256: String,
    val coordinatorAdmissionSha256: String,
    val targetRoot: String,
    val certificateReuseMode: SiteCertificateReuseMode,
    val postCoordinatorCredentialProviderPresent: Boolean,
    val uiPreparedAtEpochMillis: Long,
    val permitExpiresAtEpochMillis: Long,
)

internal enum class SiteProductionDeploymentReleaseBootstrapStatus {
    READY_TO_PUBLISH_REVIEWED_FIRST_PUBLICATION_CONTEXT,

    /**
     * Replacement of the operator's existing site in the same folder while the exact VELUM nginx
     * config for this folder/domain/port is already serving it. Only static files are swapped
     * (rename-only, with automatic rollback); nginx is not touched.
     */
    READY_TO_PUBLISH_REVIEWED_REPLACEMENT_CONTEXT,
}

/**
 * Local release-bootstrap admission only. It does not resolve credentials, touch the network,
 * authorize a coordinator invocation, mutate a VPS, or execute serving operations.
 */
internal data class SiteProductionDeploymentReleaseBootstrapAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentReleaseBootstrapStatus,
    val releaseFlow: SiteProductionDeploymentReleaseFlow,
    val selectedReadinessMode: SiteProductionServiceBindingReadinessMode,
    val serverAccessId: String,
    val remoteHostIdentity: String,
    val serviceDomain: String,
    val servicePort: Int,
    val targetRoot: String,
    val preparationSha256: String,
    val deploymentPlanSha256: String,
    val sourceTreeSha256: String,
    val coordinatorAdmissionSha256: String,
    val readyRecordApprovalSha256: String,
    val certificateReuseMode: SiteCertificateReuseMode,
    val completePostCoordinatorServingCapabilityRequired: Boolean,
    val requiresFinalHttpsTlsVerification: Boolean,
    val productionNetworkTouched: Boolean,
    val credentialMaterialRead: Boolean,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val automaticRetryAuthorized: Boolean,
    val arbitraryCommandAuthorized: Boolean,
    val silentProtocolDowngradePerformed: Boolean,
    val bootstrapAdmissionSha256: String,
)
