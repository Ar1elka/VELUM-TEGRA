package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionAuthorization
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationPermit
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationRequest

enum class SiteProductionDeploymentTransportAcquisitionReadinessStatus {
    BLOCKED,
    READY_FOR_SEPARATE_TRANSPORT_ACQUISITION,
}

data class SiteProductionDeploymentTransportAcquisitionReadinessRequest(
    val composition: SiteProductionDeploymentAndroidCompositionDescriptor,
    val executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
    val executionRequest: SiteProductionDeploymentExecutionRequest,
    val runtimeMutationPermit: SiteProductionDeploymentRuntimeMutationPermit,
    val runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
    val evaluatedAtEpochMillis: Long,
)

data class SiteProductionDeploymentTransportAcquisitionReadinessBlocker(
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentTransportAcquisitionReadinessDescriptor(
    val contractVersion: Int,
    val status: SiteProductionDeploymentTransportAcquisitionReadinessStatus,
    val readinessOnly: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val resolvesCredentials: Boolean,
    val acquiresSshSession: Boolean,
    val opensSftpChannel: Boolean,
    val invokesCoordinator: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresSeparateTransportAcquisitionAuthorization: Boolean,
    val requiresDurableReplayConsumptionBeforeCoordinatorInvocation: Boolean,
    val compositionDescriptorSha256: String,
    val serverIdentitySha256: String,
    val runtimeSessionId: String,
    val remoteHostIdentity: String,
    val executionAttemptId: String,
    val coordinatorInvocationId: String,
    val readyRecordSha256: String,
    val executionAuthorizationSha256: String,
    val runtimeMutationPermitSha256: String,
    val runtimeIdentitySha256: String,
    val candidateTransportAuthorizationSha256: String,
    val boundedSftpImplementationId: String,
    val boundedSftpCapabilityProfileSha256: String,
    val boundedSftpFactoryClassName: String,
    val evaluatedAtEpochMillis: Long,
    val executionEvidenceExpiresAtEpochMillis: Long,
    val runtimeMutationPermitExpiresAtEpochMillis: Long,
    val blockers: List<SiteProductionDeploymentTransportAcquisitionReadinessBlocker>,
    val readinessSha256: String,
)
