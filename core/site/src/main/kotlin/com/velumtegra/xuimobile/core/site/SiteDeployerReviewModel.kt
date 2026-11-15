package com.velumtegra.xuimobile.core.site

data class SiteDeployerReviewRequest(
    val rootSeed: DesignSeed,
    val siteName: String? = null,
    val tagline: String? = null,
    val themeFamily: ThemeFamily? = null,
    val backgroundFamily: BackgroundFamily? = null,
    val typographyProfile: TypographyProfile? = null,
    val componentStyle: ComponentStyle? = null,
    val domain: String,
    val servicePort: Int,
    val exportFormat: SiteExportFormat = SiteExportFormat.ZIP,
    val requestedOutputBaseName: String? = null,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val owner: String,
    val group: String,
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
    val reuseExisting3xUiCertificate: Boolean = false,
    val trustedServerKeySha256: String,
    val observation: SiteRemotePreflightObservation? = null,
)

enum class SiteDeployerExecutionMode {
    DRY_RUN_ONLY,
}

enum class SiteDeployerPreflightState {
    NOT_OBSERVED,
    READY,
    BLOCKED,
}

enum class SiteDeployerReadiness {
    UNKNOWN,
    READY,
    BLOCKED,
    NOT_REQUESTED,
}

data class SiteDeployerDesignReview(
    val siteName: String,
    val tagline: String?,
    val themeFamily: ThemeFamily,
    val backgroundFamily: BackgroundFamily,
    val typographyProfile: TypographyProfile,
    val componentStyle: ComponentStyle,
    val brandInitials: String,
    val brandShape: BrandShape,
    val accentHex: String,
    val backgroundHex: String,
)

data class SiteDeployerServiceBindingReview(
    val domain: String,
    val port: Int,
    val appliedByCurrentDeployContract: Boolean,
)

data class SiteDeployerRemoteTargetReview(
    val remoteHostIdentity: String,
    val targetRoot: String,
    val stagingRoot: String,
    val backupRoot: String?,
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy,
    val readiness: SiteDeployerReadiness,
)

data class SiteDeployerCertificateReview(
    val requested: Boolean,
    val domain: String?,
    val readiness: SiteDeployerReadiness,
    val privateKeyHandling: SitePrivateKeyHandling,
)

data class SiteDeployerDryRunPreflightReview(
    val state: SiteDeployerPreflightState,
    val requiredAvailableBytes: Long,
    val checks: List<SiteRemotePreflightCheck>,
    val authorizesTransport: Boolean,
)

data class SiteDeployerPreflightBlocker(
    val code: SiteRemotePreflightCheckCode,
    val detail: String,
)

data class SiteDeployerReviewState(
    val executionMode: SiteDeployerExecutionMode,
    val realServerMutationEnabled: Boolean,
    val fixtureDeploymentOnly: Boolean,
    val design: SiteDeployerDesignReview,
    val serviceBinding: SiteDeployerServiceBindingReview,
    val preview: SitePreviewPlan,
    val exportManifest: SiteExportManifest,
    val remoteTarget: SiteDeployerRemoteTargetReview,
    val certificate: SiteDeployerCertificateReview,
    val preflight: SiteDeployerDryRunPreflightReview,
    val preflightBlockers: List<SiteDeployerPreflightBlocker>,
    val reviewSha256: String,
)
