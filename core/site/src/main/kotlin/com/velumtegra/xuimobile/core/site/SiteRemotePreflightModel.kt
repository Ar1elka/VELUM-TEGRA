package com.velumtegra.xuimobile.core.site

enum class SiteRemoteObservedPathType {
    ABSENT,
    DIRECTORY,
    FILE,
    SYMLINK,
    OTHER,
}

data class SiteRemoteObservedPath(
    val path: String,
    val type: SiteRemoteObservedPathType,
    val byteSize: Long = 0,
)

data class SiteRemoteServerObservation(
    val remoteHostIdentity: String,
    val serverKeySha256: String,
)

data class SiteRemoteOwnershipObservation(
    val ownerExists: Boolean,
    val groupExists: Boolean,
    val ownershipChangeApplicable: Boolean,
    val modeChangeApplicable: Boolean,
)

data class SiteRemoteCertificateObservation(
    val serverKeySha256: String,
    val dnsNames: List<String>,
    val certificateSha256: String,
    val usableNow: Boolean,
    val privateKeyPresentOnServer: Boolean,
)

data class SiteRemotePreflightObservation(
    val server: SiteRemoteServerObservation,
    val target: SiteRemoteObservedPath,
    val staging: SiteRemoteObservedPath,
    val backup: SiteRemoteObservedPath?,
    val availableBytes: Long,
    val ownership: SiteRemoteOwnershipObservation,
    val certificate: SiteRemoteCertificateObservation? = null,
)

data class SiteRemotePreflightTrust(
    val expectedServerKeySha256: String,
)

enum class SiteRemotePreflightCheckCode {
    SERVER_HOST_IDENTITY,
    SERVER_KEY_FINGERPRINT,
    TARGET_STATE,
    STAGING_STATE,
    BACKUP_STATE,
    AVAILABLE_CAPACITY,
    OWNER_ACCOUNT,
    GROUP_ACCOUNT,
    OWNERSHIP_APPLICABLE,
    MODE_APPLICABLE,
    CERTIFICATE_PRESENT,
    CERTIFICATE_SERVER_IDENTITY,
    CERTIFICATE_DOMAIN,
    CERTIFICATE_USABLE_NOW,
    CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT,
}

data class SiteRemotePreflightCheck(
    val code: SiteRemotePreflightCheckCode,
    val passed: Boolean,
    val detail: String,
)

enum class SiteRemotePreflightStatus {
    READY,
    BLOCKED,
}

data class SiteRemotePreflightReport(
    val contractVersion: Int,
    val deploymentPlanSha256: String,
    val observationSha256: String,
    val requiredAvailableBytes: Long,
    val checks: List<SiteRemotePreflightCheck>,
    val status: SiteRemotePreflightStatus,
    val preflightSha256: String,
)
