package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityReport

enum class SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionStatus {
    REAL_VPS_EXISTING_3X_UI_CERTIFICATE_REUSE_ELIGIBILITY_OBSERVED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
}

data class SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionProof(
    val contractVersion: Int,
    val status: SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionStatus,
    val eligibilityPlanSha256: String,
    val eligibilityReport: SiteExisting3xUiCertificateReuseEligibilityReport,
    val freshCredentialResolutionProofSha256: String,
    val freshCredentialResolutionConsumptionReceiptSha256: String,
    val serverAccessBindingSha256: String,
    val serverAccessId: String,
    val remoteHostIdentity: String,
    val remotePort: Int,
    val username: String,
    val pinnedHostKeySha256: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val sessionId: String,
    val operationOwnerId: String,
    val remoteCommandCount: Int,
    val credentialLeaseMaterialConsumed: Boolean,
    val productionNetworkTouched: Boolean,
    val hostKeyPinVerifiedAgainstRemote: Boolean,
    val exactSessionRegistryUsed: Boolean,
    val mutationOperationPerformed: Boolean,
    val arbitraryCommandAccepted: Boolean,
    val privateKeyContentReadPerformed: Boolean,
    val certificateMutationPerformed: Boolean,
    val tlsConfigurationPerformed: Boolean,
    val dnsMutationPerformed: Boolean,
    val firewallMutationPerformed: Boolean,
    val packageInstallPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
    val sessionClosed: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
    val credentialResolvedAtEpochMillis: Long,
    val executedAtEpochMillis: Long,
    val freshCredentialAuthorizationExpiresAtEpochMillis: Long,
    val certificateEvaluatedAtEpochMillis: Long,
    val executionProofSha256: String,
)
