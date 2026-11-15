package com.velumtegra.xuimobile.core.site

enum class SiteExportFormat {
    DIRECTORY,
    ZIP,
}

data class SitePreviewExportRequest(
    val format: SiteExportFormat = SiteExportFormat.ZIP,
    val requestedBaseName: String? = null,
)

data class SitePreviewFile(
    val path: String,
    val mediaType: String,
    val byteSize: Int,
    val sha256: String,
    val isEntryPoint: Boolean,
)

data class SitePreviewPlan(
    val entryPath: String,
    val siteName: String,
    val fileCount: Int,
    val totalBytes: Long,
    val treeSha256: String,
    val files: List<SitePreviewFile>,
)

data class SiteExportEntry(
    val path: String,
    val mediaType: String,
    val content: String,
    val byteSize: Int,
    val sha256: String,
)

data class SiteExportManifest(
    val boundaryVersion: Int,
    val format: SiteExportFormat,
    val outputBaseName: String,
    val outputName: String,
    val sourceTreeSha256: String,
    val fileCount: Int,
    val totalBytes: Long,
    val planSha256: String,
)

data class SiteExportPlan(
    val entries: List<SiteExportEntry>,
    val manifest: SiteExportManifest,
)

data class SitePreviewExportPlan(
    val preview: SitePreviewPlan,
    val export: SiteExportPlan,
)
