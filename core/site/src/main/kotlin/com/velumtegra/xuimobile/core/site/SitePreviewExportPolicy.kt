package com.velumtegra.xuimobile.core.site

import java.text.Normalizer
import java.util.Locale

object SitePreviewExportPolicy {
    const val MAX_OUTPUT_BASE_NAME_LENGTH: Int = 64
    private const val MAX_REQUESTED_NAME_LENGTH: Int = 96
    private val safeBaseName = Regex("^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

    fun resolveOutputBaseName(
        requestedBaseName: String?,
        siteName: String,
        treeSha256: String,
    ): String {
        if (requestedBaseName != null) {
            validateRawRequestedName(requestedBaseName)
            val normalized = slugify(requestedBaseName)
            require(normalized.isNotEmpty()) {
                "Requested export name must contain at least one ASCII letter or digit after normalization"
            }
            return normalized
        }

        val derived = slugify(siteName)
        return if (derived.isNotEmpty()) {
            derived
        } else {
            "site-${treeSha256.take(12)}"
        }
    }

    fun outputName(baseName: String, format: SiteExportFormat): String {
        validateOutputBaseName(baseName)
        return when (format) {
            SiteExportFormat.DIRECTORY -> baseName
            SiteExportFormat.ZIP -> "$baseName.zip"
        }
    }

    fun validate(plan: SitePreviewExportPlan) {
        val preview = plan.preview
        val export = plan.export
        val manifest = export.manifest

        require(preview.entryPath == "index.html") { "Preview entry path must be index.html" }
        require(preview.files.isNotEmpty()) { "Preview plan must contain files" }
        require(preview.files.count(SitePreviewFile::isEntryPoint) == 1) {
            "Preview plan must contain exactly one entry point"
        }
        require(preview.files.single(SitePreviewFile::isEntryPoint).path == preview.entryPath) {
            "Preview entry point marker/path mismatch"
        }
        require(preview.files.map(SitePreviewFile::path) == preview.files.map(SitePreviewFile::path).sorted()) {
            "Preview files must be sorted by path"
        }
        require(export.entries.map(SiteExportEntry::path) == export.entries.map(SiteExportEntry::path).sorted()) {
            "Export entries must be sorted by path"
        }
        require(preview.files.size == export.entries.size) { "Preview/export file count mismatch" }
        require(preview.fileCount == export.entries.size) { "Preview file count metadata mismatch" }
        require(manifest.fileCount == export.entries.size) { "Export manifest file count mismatch" }
        require(preview.totalBytes == manifest.totalBytes) { "Preview/export total byte count mismatch" }
        require(preview.treeSha256 == manifest.sourceTreeSha256) { "Preview/export source tree mismatch" }
        require(manifest.boundaryVersion == SitePreviewExportBoundary.BOUNDARY_VERSION) {
            "Unsupported preview/export boundary version"
        }
        validateOutputBaseName(manifest.outputBaseName)
        require(manifest.outputName == outputName(manifest.outputBaseName, manifest.format)) {
            "Export output name does not match format/base name"
        }

        val documents = export.entries.map { entry ->
            SiteBuildPolicy.validatePath(entry.path)
            val bytes = entry.content.encodeToByteArray()
            require(entry.byteSize == bytes.size) { "Export entry byte size mismatch: ${entry.path}" }
            require(entry.sha256 == SiteBundleDigest.sha256(bytes)) { "Export entry SHA-256 mismatch: ${entry.path}" }
            SiteDocument(entry.path, entry.mediaType, entry.content)
        }
        val totalBytes = export.entries.sumOf { it.byteSize.toLong() }
        require(totalBytes == manifest.totalBytes) { "Export manifest total bytes mismatch" }
        require(totalBytes == preview.totalBytes) { "Preview total bytes mismatch" }

        val expectedPreviewFiles = export.entries.map { entry ->
            SitePreviewFile(
                path = entry.path,
                mediaType = entry.mediaType,
                byteSize = entry.byteSize,
                sha256 = entry.sha256,
                isEntryPoint = entry.path == preview.entryPath,
            )
        }
        require(preview.files == expectedPreviewFiles) { "Preview file metadata does not match export entries" }
        require(SiteBundleDigest.treeSha256(documents) == manifest.sourceTreeSha256) {
            "Export entries do not match source tree SHA-256"
        }
        require(manifest.planSha256 == SitePreviewExportDigest.planSha256(export.entries, manifest.copy(planSha256 = ""))) {
            "Export plan SHA-256 mismatch"
        }
    }

    private fun validateRawRequestedName(value: String) {
        require(value.isNotBlank()) { "Requested export name must not be blank" }
        require(value.length <= MAX_REQUESTED_NAME_LENGTH) { "Requested export name is too long" }
        require(value.none(Char::isISOControl)) { "Requested export name contains control characters" }
        require('/' !in value && '\\' !in value) { "Path separators are forbidden in requested export name" }
        require(".." !in value) { "Parent-path syntax is forbidden in requested export name" }
        require('.' !in value) { "File extensions/dot segments are forbidden in requested export name" }
    }

    private fun validateOutputBaseName(baseName: String) {
        require(baseName.length in 1..MAX_OUTPUT_BASE_NAME_LENGTH) { "Export base name length is invalid" }
        require(safeBaseName.matches(baseName)) { "Export base name is not canonical/safe" }
    }

    private fun slugify(input: String): String {
        val ascii = Normalizer.normalize(input.trim(), Normalizer.Form.NFKD)
            .lowercase(Locale.ROOT)
            .filterNot { ch -> Character.getType(ch) == Character.NON_SPACING_MARK.toInt() }
        return ascii
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .take(MAX_OUTPUT_BASE_NAME_LENGTH)
            .trim('-')
    }
}

internal object SitePreviewExportDigest {
    fun planSha256(entries: List<SiteExportEntry>, manifestWithoutPlanSha: SiteExportManifest): String {
        val canonical = buildString {
            append("boundaryVersion=").append(manifestWithoutPlanSha.boundaryVersion).append('\n')
            append("format=").append(manifestWithoutPlanSha.format.name).append('\n')
            append("outputBaseName=").append(manifestWithoutPlanSha.outputBaseName).append('\n')
            append("outputName=").append(manifestWithoutPlanSha.outputName).append('\n')
            append("sourceTreeSha256=").append(manifestWithoutPlanSha.sourceTreeSha256).append('\n')
            append("fileCount=").append(manifestWithoutPlanSha.fileCount).append('\n')
            append("totalBytes=").append(manifestWithoutPlanSha.totalBytes).append('\n')
            entries.forEach { entry ->
                append(entry.path).append('\u0000')
                append(entry.mediaType).append('\u0000')
                append(entry.byteSize).append('\u0000')
                append(entry.sha256).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}
