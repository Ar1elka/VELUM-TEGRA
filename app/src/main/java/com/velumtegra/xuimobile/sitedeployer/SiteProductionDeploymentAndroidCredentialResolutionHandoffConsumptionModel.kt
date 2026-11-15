package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentCredentialResolutionHandoffConsumptionStatus {
    DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
}

data class SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt(
    val contractVersion: Int,
    val status: SiteProductionDeploymentCredentialResolutionHandoffConsumptionStatus,
    val singleUseConsumed: Boolean,
    val credentialReferenceBound: Boolean,
    val secretStoreReadPerformed: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresSeparateCredentialResolutionExecutionBoundary: Boolean,
    val requiresSeparateSshSessionAcquisitionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val authorizationAttemptId: String,
    val authorizationSha256: String,
    val admissionSha256: String,
    val consumptionReceiptSha256: String,
    val serverIdentitySha256: String,
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val consumedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val credentialResolutionConsumptionReceiptSha256: String,
)
