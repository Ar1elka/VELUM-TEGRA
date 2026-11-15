package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

object SiteLocalExportPolicy {
    const val ADAPTER_VERSION: Int = 1

    fun validatePlan(plan: SiteExportPlan) {
        val manifest = plan.manifest
        require(manifest.boundaryVersion == SitePreviewExportBoundary.BOUNDARY_VERSION) {
            "Unsupported export boundary version"
        }
        require(plan.entries.isNotEmpty()) { "Export plan must contain at least one entry" }
        require(plan.entries.size <= SiteBuildPolicy.MAX_DOCUMENTS) { "Export plan contains too many entries" }
        require(plan.entries.map(SiteExportEntry::path) == plan.entries.map(SiteExportEntry::path).sorted()) {
            "Export entries must be sorted by path"
        }
        require(plan.entries.map(SiteExportEntry::path).distinct().size == plan.entries.size) {
            "Export plan contains duplicate paths"
        }
        require(manifest.fileCount == plan.entries.size) { "Export manifest file count mismatch" }
        require(manifest.outputName == SitePreviewExportPolicy.outputName(manifest.outputBaseName, manifest.format)) {
            "Export output name does not match its safe base name/format"
        }

        var totalBytes = 0L
        val documents = plan.entries.map { entry ->
            SiteBuildPolicy.validatePath(entry.path)
            val bytes = entry.content.encodeToByteArray()
            require(bytes.size <= SiteBuildPolicy.MAX_DOCUMENT_BYTES) {
                "Export entry exceeds per-document limit: ${entry.path}"
            }
            require(entry.byteSize == bytes.size) { "Export entry byte size mismatch: ${entry.path}" }
            require(entry.sha256 == SiteBundleDigest.sha256(bytes)) { "Export entry SHA-256 mismatch: ${entry.path}" }
            totalBytes += bytes.size
            SiteDocument(entry.path, entry.mediaType, entry.content)
        }
        require(totalBytes <= SiteBuildPolicy.MAX_TOTAL_BYTES) { "Export plan exceeds total size limit" }
        require(manifest.totalBytes == totalBytes) { "Export manifest total bytes mismatch" }
        require(manifest.sourceTreeSha256 == SiteBundleDigest.treeSha256(documents)) {
            "Export source tree SHA-256 mismatch"
        }
        require(
            manifest.planSha256 == SitePreviewExportDigest.planSha256(
                plan.entries,
                manifest.copy(planSha256 = ""),
            ),
        ) { "Export plan SHA-256 mismatch" }
    }

    internal fun resolveRoot(outputRoot: Path): Path {
        require(Files.exists(outputRoot, LinkOption.NOFOLLOW_LINKS)) { "Export root does not exist" }
        require(!Files.isSymbolicLink(outputRoot)) { "Export root must not be a symbolic link" }
        require(Files.isDirectory(outputRoot, LinkOption.NOFOLLOW_LINKS)) { "Export root must be a directory" }
        return outputRoot.toRealPath(LinkOption.NOFOLLOW_LINKS)
    }

    internal fun resolveTarget(root: Path, plan: SiteExportPlan): Path {
        val target = root.resolve(plan.manifest.outputName).normalize()
        require(target.parent == root) { "Export target escaped the selected root" }
        require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) { "Export target already exists" }
        return target
    }

    internal fun resolveEntry(root: Path, relativePath: String): Path {
        SiteBuildPolicy.validatePath(relativePath)
        val target = root.resolve(relativePath).normalize()
        require(target.startsWith(root)) { "Export entry escaped temporary root: $relativePath" }
        return target
    }
}
