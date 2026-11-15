package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentTransportAcquisitionAuthorizationStatus {
    BLOCKED,
    AWAITING_TRANSPORT_ACQUISITION_APPROVAL,
    AUTHORIZED_FOR_SINGLE_TRANSPORT_ACQUISITION_HANDOFF,
}

data class SiteProductionDeploymentTransportAcquisitionAuthorizationRequest(
    val readinessRequest: SiteProductionDeploymentTransportAcquisitionReadinessRequest,
    val readinessDescriptor: SiteProductionDeploymentTransportAcquisitionReadinessDescriptor,
    val authorizationAttemptId: String,
    val evaluatedAtEpochMillis: Long,
    val requestedAuthorizationLifetimeMillis: Long,
)

data class SiteProductionDeploymentTransportAcquisitionAuthorizationBlocker(
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentTransportAcquisitionAuthorizationDraft(
    val contractVersion: Int,
    val status: SiteProductionDeploymentTransportAcquisitionAuthorizationStatus,
    val authorizationOnly: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val authorizesSingleTransportAcquisitionHandoff: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresExplicitApproval: Boolean,
    val requiresDurableOneShotConsumptionBeforeAcquisition: Boolean,
    val authorizationAttemptId: String,
    val readinessSha256: String,
    val compositionDescriptorSha256: String,
    val serverIdentitySha256: String,
    val runtimeSessionId: String,
    val remoteHostIdentity: String,
    val executionAttemptId: String,
    val coordinatorInvocationId: String,
    val runtimeMutationPermitSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val boundedSftpImplementationId: String,
    val boundedSftpCapabilityProfileSha256: String,
    val evaluatedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val blockers: List<SiteProductionDeploymentTransportAcquisitionAuthorizationBlocker>,
    val approvalChallengeSha256: String,
    val draftSha256: String,
)

data class SiteProductionDeploymentTransportAcquisitionApproval(
    val approvalChallengeSha256: String,
    val confirmed: Boolean,
)

data class SiteProductionDeploymentTransportAcquisitionAuthorization(
    val contractVersion: Int,
    val status: SiteProductionDeploymentTransportAcquisitionAuthorizationStatus,
    val authorizationOnly: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val authorizesSingleTransportAcquisitionHandoff: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresDurableOneShotConsumptionBeforeAcquisition: Boolean,
    val authorizationAttemptId: String,
    val readinessSha256: String,
    val compositionDescriptorSha256: String,
    val serverIdentitySha256: String,
    val runtimeSessionId: String,
    val remoteHostIdentity: String,
    val executionAttemptId: String,
    val coordinatorInvocationId: String,
    val runtimeMutationPermitSha256: String,
    val candidateTransportAuthorizationSha256: String,
    val boundedSftpImplementationId: String,
    val boundedSftpCapabilityProfileSha256: String,
    val evaluatedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val approvalChallengeSha256: String,
    val authorizationSha256: String,
)
