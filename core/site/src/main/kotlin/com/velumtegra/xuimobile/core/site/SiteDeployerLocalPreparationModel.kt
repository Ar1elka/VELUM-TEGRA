package com.velumtegra.xuimobile.core.site

import java.nio.file.Path

data class SiteDeployerLocalPreparationRequest(
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
)

data class SiteDeployerLocalServiceBinding(
    val domain: String,
    val port: Int,
    val appliedByCurrentDeployContract: Boolean,
)

data class SiteDeployerLocalPreparationResult(
    val design: SiteDesign,
    val bundle: SiteBundle,
    val previewExport: SitePreviewExportPlan,
    val localExportReceipt: SiteLocalExportReceipt,
    val remoteDeployPlan: SiteRemoteDeployPlan,
    val serviceBinding: SiteDeployerLocalServiceBinding,
    val preparationSha256: String,
    val productionNetworkTouched: Boolean,
    val remoteMutationPerformed: Boolean,
    val coordinatorInvoked: Boolean,
    val transportAuthorized: Boolean,
) {
    val localArtifactPath: Path
        get() = localExportReceipt.outputPath
}
