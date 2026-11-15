package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport

enum class SiteProductionDeploymentRealVpsWebServingReadOnlyPreflightExecutionStatus {
    REAL_VPS_WEB_SERVING_READ_ONLY_PREFLIGHT_OBSERVED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
}

data class SiteProductionDeploymentRealVpsWebServingReadOnlyPreflightExecutionProof(
    val contractVersion: Int,
    val status: SiteProductionDeploymentRealVpsWebServingReadOnlyPreflightExecutionStatus,
    val publicationPlanSha256: String,
    val preflightReport: SiteWebServingReadOnlyPreflightReport,
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
    val configMutationPerformed: Boolean,
    val webServerReloadPerformed: Boolean,
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
    val executionProofSha256: String,
)
