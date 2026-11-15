package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentTransportAcquisitionHandoffConsumptionStatus {
    DURABLY_CONSUMED_AWAITING_SEPARATE_ACQUISITION_BOUNDARY,
}

data class SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt(
    val contractVersion: Int,
    val status: SiteProductionDeploymentTransportAcquisitionHandoffConsumptionStatus,
    val singleUseConsumed: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesTransportAcquisitionExecution: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresSeparateAcquisitionExecutionBoundary: Boolean,
    val authorizationAttemptId: String,
    val authorizationSha256: String,
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
    val consumedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val consumptionReceiptSha256: String,
)
