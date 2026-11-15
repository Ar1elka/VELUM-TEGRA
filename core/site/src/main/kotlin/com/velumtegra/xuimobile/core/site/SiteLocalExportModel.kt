package com.velumtegra.xuimobile.core.site

import java.nio.file.Path

data class SiteLocalExportReceipt(
    val format: SiteExportFormat,
    val outputName: String,
    val outputPath: Path,
    val fileCount: Int,
    val totalBytes: Long,
    val sourceTreeSha256: String,
    val planSha256: String,
    val artifactSha256: String?,
    val verified: Boolean,
)

internal enum class SiteLocalExportStage {
    TEMP_WRITTEN,
    TEMP_VERIFIED,
}
