package com.velumtegra.xuimobile.core.site

data class SiteProductionServiceBindingIntent(
    val domain: String,
    val port: Int,
)

data class SiteProductionServiceBindingObservation(
    val remoteHostIdentity: String,
    val serverKeySha256: String,
    val domain: String,
    val port: Int,
    val configured: Boolean,
    val observedAtEpochMillis: Long,
)

data class SiteProductionObservationFreshnessPolicy(
    val evaluatedAtEpochMillis: Long,
    val maxAgeMillis: Long,
)

enum class SiteProductionServiceBindingReadinessMode {
    REQUIRE_ALREADY_CONFIGURED,
    REQUIRE_POST_COORDINATOR_ACTIVATION,
}

enum class SiteProductionServiceBindingCheckCode {
    SERVER_HOST_IDENTITY,
    SERVER_KEY_FINGERPRINT,
    DOMAIN,
    PORT,
    CONFIGURED,
}

data class SiteProductionServiceBindingCheck(
    val code: SiteProductionServiceBindingCheckCode,
    val passed: Boolean,
    val detail: String,
)

enum class SiteProductionDeploymentReadinessStatus {
    BLOCKED,
    AWAITING_OPERATOR_APPROVAL,
    READY_FOR_EXPLICIT_EXECUTION,
}

data class SiteProductionDeploymentReadinessRequest(
    val exportPlan: SiteExportPlan,
    val localReceipt: SiteLocalExportReceipt,
    val remoteRequest: SiteRemoteDeployRequest,
    val trust: SiteRemotePreflightTrust,
    val remoteObservation: SiteRemotePreflightObservation,
    val remoteObservationObservedAtEpochMillis: Long,
    val serviceBindingIntent: SiteProductionServiceBindingIntent,
    val serviceBindingObservation: SiteProductionServiceBindingObservation,
    val freshnessPolicy: SiteProductionObservationFreshnessPolicy,
    val serviceBindingReadinessMode: SiteProductionServiceBindingReadinessMode =
        SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
)

data class SiteProductionReadinessBlocker(
    val scope: String,
    val code: String,
    val detail: String,
)

data class SiteProductionDeploymentReadinessDraft(
    val contractVersion: Int,
    val status: SiteProductionDeploymentReadinessStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val requiresSeparateExecutionAuthorization: Boolean,
    val exportManifest: SiteExportManifest,
    val deploymentPlan: SiteRemoteDeployPlan,
    val preflight: SiteRemotePreflightReport,
    val remoteObservationObservedAtEpochMillis: Long,
    val serviceBindingIntent: SiteProductionServiceBindingIntent,
    val serviceBindingReadinessMode: SiteProductionServiceBindingReadinessMode,
    val serviceBindingObservationSha256: String,
    val serviceBindingObservedAtEpochMillis: Long,
    val freshnessPolicy: SiteProductionObservationFreshnessPolicy,
    val serviceBindingChecks: List<SiteProductionServiceBindingCheck>,
    val blockers: List<SiteProductionReadinessBlocker>,
    val operatorApprovalChallengeSha256: String,
    val readinessSha256: String,
)

data class SiteProductionOperatorApproval(
    val operatorApprovalChallengeSha256: String,
    val confirmed: Boolean,
)

data class SiteProductionDeploymentReadyRecord(
    val contractVersion: Int,
    val status: SiteProductionDeploymentReadinessStatus,
    val realServerMutationEnabled: Boolean,
    val authorizesTransport: Boolean,
    val requiresSeparateExecutionAuthorization: Boolean,
    val operatorApproved: Boolean,
    val operatorApprovalChallengeSha256: String,
    val readinessSha256: String,
    val deploymentPlanSha256: String,
    val preflightSha256: String,
    val exportPlanSha256: String,
    val sourceTreeSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val stagingRoot: String,
    val backupRoot: String?,
    val serviceBindingDomain: String,
    val serviceBindingPort: Int,
    val serviceBindingReadinessMode: SiteProductionServiceBindingReadinessMode,
    val serviceBindingObservationSha256: String,
    val remoteObservationObservedAtEpochMillis: Long,
    val serviceBindingObservedAtEpochMillis: Long,
    val evaluatedAtEpochMillis: Long,
    val maxObservationAgeMillis: Long,
    val approvalRecordSha256: String,
)
