package com.velumtegra.xuimobile.core.site

enum class SiteRemoteExistingTargetPolicy {
    REQUIRE_ABSENT,
    BACKUP_AND_REPLACE,
}

enum class SiteCertificateReuseMode {
    NONE,
    REUSE_EXISTING_3X_UI_IF_PROVEN,
}

enum class SitePrivateKeyHandling {
    REMAIN_ON_SERVER,
}

data class SiteCertificateReuseRequest(
    val mode: SiteCertificateReuseMode = SiteCertificateReuseMode.NONE,
    val requestedDomain: String? = null,
)

data class SiteRemoteDeployRequest(
    val remoteHostIdentity: String,
    val targetRoot: String,
    val owner: String,
    val group: String,
    val directoryMode: String = "0755",
    val fileMode: String = "0644",
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
    val certificateReuse: SiteCertificateReuseRequest = SiteCertificateReuseRequest(),
)

data class SiteRemoteDeployEntry(
    val path: String,
    val mediaType: String,
    val byteSize: Int,
    val sha256: String,
)

data class SiteCertificateReuseRequirement(
    val mode: SiteCertificateReuseMode,
    val requiredDomain: String?,
    val sameServerRequired: Boolean,
    val privateKeyHandling: SitePrivateKeyHandling,
)

data class SiteRemotePublishContract(
    val targetRoot: String,
    val stagingRoot: String,
    val backupRoot: String?,
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy,
    val owner: String,
    val group: String,
    val directoryMode: String,
    val fileMode: String,
    val requireStagingAbsent: Boolean,
    val requireBackupAbsent: Boolean,
    val verifyBeforePublish: Boolean,
    val verifyAfterPublish: Boolean,
    val rollbackOnFailure: Boolean,
)

data class SiteRemoteDeployPlan(
    val contractVersion: Int,
    val remoteHostIdentity: String,
    val sourceOutputName: String,
    val sourceFormat: SiteExportFormat,
    val sourceTreeSha256: String,
    val sourcePlanSha256: String,
    val sourceArtifactSha256: String?,
    val fileCount: Int,
    val totalBytes: Long,
    val entries: List<SiteRemoteDeployEntry>,
    val publish: SiteRemotePublishContract,
    val certificate: SiteCertificateReuseRequirement,
    val deploymentPlanSha256: String,
)
