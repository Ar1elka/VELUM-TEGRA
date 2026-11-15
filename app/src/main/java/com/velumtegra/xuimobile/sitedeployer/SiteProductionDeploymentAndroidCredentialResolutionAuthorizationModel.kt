package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentCredentialResolutionAuthorizationStatus {
    BLOCKED,
    AWAITING_CREDENTIAL_RESOLUTION_APPROVAL,
    AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
}

data class SiteProductionDeploymentCredentialResolutionAuthorizationRequest(
    val admission: SiteProductionDeploymentTransportAcquisitionExecutionAdmission,
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val authorizationAttemptId: String,
    val evaluatedAtEpochMillis: Long,
    val requestedAuthorizationLifetimeMillis: Long,
)

data class SiteProductionDeploymentCredentialResolutionAuthorizationBlocker(
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentCredentialResolutionAuthorizationDraft(
    val contractVersion: Int,
    val status: SiteProductionDeploymentCredentialResolutionAuthorizationStatus,
    val authorizationOnly: Boolean,
    val secretStoreReadPerformed: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSingleCredentialResolutionHandoff: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresExplicitApproval: Boolean,
    val requiresDurableOneShotConsumptionBeforeCredentialResolution: Boolean,
    val requiresSeparateSshSessionAcquisitionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val admissionSha256: String,
    val consumptionReceiptSha256: String,
    val serverIdentitySha256: String,
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val authorizationAttemptId: String,
    val evaluatedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val blockers: List<SiteProductionDeploymentCredentialResolutionAuthorizationBlocker>,
    val approvalChallengeSha256: String,
    val draftSha256: String,
)

data class SiteProductionDeploymentCredentialResolutionApproval(
    val approvalChallengeSha256: String,
    val confirmed: Boolean,
)

data class SiteProductionDeploymentCredentialResolutionAuthorization(
    val contractVersion: Int,
    val status: SiteProductionDeploymentCredentialResolutionAuthorizationStatus,
    val authorizationOnly: Boolean,
    val secretStoreReadPerformed: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSingleCredentialResolutionHandoff: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresDurableOneShotConsumptionBeforeCredentialResolution: Boolean,
    val requiresSeparateSshSessionAcquisitionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val admissionSha256: String,
    val consumptionReceiptSha256: String,
    val serverIdentitySha256: String,
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val authorizationAttemptId: String,
    val evaluatedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val approvalChallengeSha256: String,
    val authorizationSha256: String,
)
