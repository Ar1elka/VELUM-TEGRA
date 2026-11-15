package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus {
    BLOCKED,
    ADMITTED_FOR_SEPARATE_TRANSPORT_ACQUISITION_EXECUTION_BOUNDARY,
}

data class SiteProductionDeploymentTransportAcquisitionExecutionAdmissionBlocker(
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentTransportAcquisitionExecutionAdmission(
    val contractVersion: Int,
    val status: SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus,
    val admissionOnly: Boolean,
    val durableHandoffConsumed: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesTransportAcquisitionExecution: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresSeparateCredentialResolutionBoundary: Boolean,
    val requiresSeparateSshSessionAcquisitionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val consumptionReceiptSha256: String,
    val authorizationSha256: String,
    val readinessSha256: String,
    val compositionDescriptorSha256: String,
    val serverIdentitySha256: String,
    val runtimeSessionId: String,
    val remoteHostIdentity: String,
    val serverAccessId: String,
    val pinnedHostKeySha256: String,
    val runtimeCoordinatorImplementation: String,
    val sshConnectionFactoryImplementation: String,
    val exactSessionRegistryImplementation: String,
    val deploymentRuntimeImplementation: String,
    val sftpPrimitiveFactoryImplementation: String,
    val boundedSftpImplementationId: String,
    val boundedSftpCapabilityProfileSha256: String,
    val evaluatedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val blockers: List<SiteProductionDeploymentTransportAcquisitionExecutionAdmissionBlocker>,
    val admissionSha256: String,
)
