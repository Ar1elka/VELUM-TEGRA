package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionStatus {
    DURABLY_CONSUMED_AWAITING_SEPARATE_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
}

data class SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt(
    val contractVersion: Int,
    val status: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionStatus,
    val singleUseConsumed: Boolean,
    val credentialLeaseMaterialRead: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresSeparateSshSessionAcquisitionExecutionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val authorizationAttemptId: String,
    val authorizationSha256: String,
    val resolutionProofSha256: String,
    val credentialResolutionConsumptionReceiptSha256: String,
    val serverIdentitySha256: String,
    val compositionDescriptorSha256: String,
    val serverAccessBindingSha256: String,
    val serverAccessId: String,
    val runtimeSessionId: String,
    val remoteHostIdentity: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val sshConnectionFactoryImplementation: String,
    val exactSessionRegistryImplementation: String,
    val consumedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val sshSessionAcquisitionConsumptionReceiptSha256: String,
)
