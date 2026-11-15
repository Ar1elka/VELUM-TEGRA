package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class UpdateServerArchitecture { AMD64, ARM64 }

/** Closed, reviewed release inventory; neither a latest-version guess nor caller-supplied URLs. */
enum class ReviewedXuiUpdatePackage(val architecture: UpdateServerArchitecture, val sha256: String, val assetName: String) {
    V3_10_2_AMD64(UpdateServerArchitecture.AMD64,
        "bfda7921984e7a72555c38d4e861c7a8b67b3686b658608937de99682f1452d0", "x-ui-linux-amd64.tar.gz"),
    V3_10_2_ARM64(UpdateServerArchitecture.ARM64,
        "a867c65ce52ad49f6504dd4c9c395337dc92ba57ae478da4f1b7ddb624014ed5", "x-ui-linux-arm64.tar.gz");

    val version: String get() = "3.10.2"
    val releasePage: String get() = "https://github.com/MHSanaei/3x-ui/releases/tag/v3.10.2"
    val downloadUrl: String get() = "https://github.com/MHSanaei/3x-ui/releases/download/v3.10.2/$assetName"
}

data class UpdatePackageRequest(val report: UpdatePreflightSnapshot, val release: ReviewedXuiUpdatePackage)

/** Process-local evidence about cached bytes only. This is NEVER remote mutation authority. */
data class UpdatePackageReceipt(
    val scope: ManagementScope,
    val preflightObservedAt: Instant,
    val release: ReviewedXuiUpdatePackage,
    val sha256: String,
    val sizeBytes: Long,
    val verifiedAt: Instant,
    val cacheToken: String,
) {
    init {
        require(sha256 == release.sha256)
        require(sizeBytes in 1..MAX_BYTES)
        require(!verifiedAt.isBefore(preflightObservedAt))
        require(Regex("[0-9a-f]{32}").matches(cacheToken))
    }
    companion object {
        const val MAX_BYTES: Long = 192L * 1024 * 1024
    }
}

enum class UpdateRecoveryRequirement {
    CONSISTENT_DATABASE_COPY,
    PREVIOUS_BINARY_AND_RUNTIME,
    SERVICE_CONFIGURATION_AND_PERMISSIONS,
    PRIVATE_SETTINGS_AND_CERTIFICATES,
    VERIFIED_RESTORE_AND_READBACK,
}
