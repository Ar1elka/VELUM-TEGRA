package com.velumtegra.xuimobile.sitedeployer

enum class SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus {
    RESOLVED_TO_EPHEMERAL_LEASE,
    SECRET_NOT_FOUND,
    SECRET_UNAVAILABLE,
    SECRET_CORRUPT,
    SECRET_STORAGE_FAILURE,
}

data class SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof(
    val contractVersion: Int,
    val status: SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus,
    val durableHandoffConsumed: Boolean,
    val executionReceiptConsumed: Boolean,
    val secretStoreReadPerformed: Boolean,
    val credentialLeaseMaterialRead: Boolean,
    val credentialMaterialPersisted: Boolean,
    val productionNetworkTouched: Boolean,
    val hostKeyPinVerifiedAgainstRemote: Boolean,
    val authorizesNetworkAccess: Boolean,
    val authorizesCredentialResolution: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesReadOnlyPreflightExecution: Boolean,
    val authorizesMutation: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresLiveRemoteHostKeyVerification: Boolean,
    val requiresSeparateSshSessionAcquisitionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val requiresSeparateReadOnlyExecutionBoundary: Boolean,
    val requiresSeparateMutationBoundary: Boolean,
    val credentialResolutionConsumptionReceiptSha256: String,
    val authorizationSha256: String,
    val handoffConsumptionReceiptSha256: String,
    val sourceAuthorizationSha256: String,
    val admissionSha256: String,
    val serverAccessBindingSha256: String,
    val requestSha256: String,
    val capabilityProfileSha256: String,
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val resolvedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val resolutionProofSha256: String,
)

sealed interface SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult {
    val proof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof

    data class Resolved(
        override val proof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        val lease: SiteProductionDeploymentEphemeralCredentialLease,
    ) : SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult

    data class Blocked(
        override val proof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
    ) : SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
}
