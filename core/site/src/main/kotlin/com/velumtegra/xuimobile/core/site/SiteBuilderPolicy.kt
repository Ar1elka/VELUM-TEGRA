package com.velumtegra.xuimobile.core.site

import java.security.MessageDigest

object SiteBuildPolicy {
    const val MAX_DOCUMENTS: Int = 64
    const val MAX_DOCUMENT_BYTES: Int = 512 * 1024
    const val MAX_TOTAL_BYTES: Long = 4L * 1024L * 1024L

    private val allowedPath = Regex("^[A-Za-z0-9._/-]+$")
    private val allowedExtensions = setOf("html", "css", "js", "svg", "txt")

    fun validateDesign(design: SiteDesign) {
        require(design.generatorVersion > 0) { "Design generator version must be positive" }
        require(SiteInputPolicy.normalizeName(design.identity.name) == design.identity.name) {
            "Site design name must already be normalized"
        }
        design.identity.tagline?.let { tagline ->
            require(SiteInputPolicy.normalizeTagline(tagline) == tagline) {
                "Site design tagline must already be normalized"
            }
        }
        require(design.background.density in 1..4) { "Background density is outside supported range" }
        require(design.background.angleDegrees in 0..359) { "Background angle is outside supported range" }
        require(design.background.primaryAnchorXPercent in 0..100) { "Primary background X anchor is invalid" }
        require(design.background.primaryAnchorYPercent in 0..100) { "Primary background Y anchor is invalid" }
        require(design.background.secondaryAnchorXPercent in 0..100) { "Secondary background X anchor is invalid" }
        require(design.background.secondaryAnchorYPercent in 0..100) { "Secondary background Y anchor is invalid" }
        require(SiteContrastPolicy.passesNormalText(design.palette.textPrimary, design.palette.backgroundPrimary)) {
            "Design primary text contrast is below policy"
        }
        require(SiteContrastPolicy.passesNormalText(design.palette.textPrimary, design.palette.surface)) {
            "Design surface text contrast is below policy"
        }
        require(
            SiteContrastPolicy.contrastRatio(design.palette.accentPrimary, design.palette.backgroundPrimary) >=
                SiteContrastPolicy.UI_ACCENT_MIN_RATIO,
        ) { "Design accent contrast is below policy" }
        validateBrandSvg(design.brand.svg)
    }

    private fun validateBrandSvg(svg: String) {
        val lower = svg.lowercase()
        require(svg.startsWith("<svg")) { "Brand asset must be an SVG document" }
        require("<!doctype" !in lower && "<!entity" !in lower) { "DTD/entity declarations are forbidden in brand SVG" }
        require("<script" !in lower) { "Scripts are forbidden in brand SVG" }
        require("<image" !in lower) { "Image embedding is forbidden in brand SVG" }
        require("<foreignobject" !in lower) { "foreignObject is forbidden in brand SVG" }
        require("href=" !in lower && "xlink:href" !in lower) { "External references are forbidden in brand SVG" }
    }

    fun validate(bundle: SiteBundle) {
        require(bundle.documents.isNotEmpty()) { "Site bundle must contain at least one document" }
        require(bundle.documents.size <= MAX_DOCUMENTS) { "Site bundle contains too many documents" }
        require(bundle.documents.map(SiteDocument::path) == bundle.documents.map(SiteDocument::path).sorted()) {
            "Site bundle documents must be sorted by path"
        }
        require(bundle.preview.siteName == bundle.manifest.siteName) { "Preview/manifest site name mismatch" }
        require(bundle.manifest.builderVersion > 0) { "Manifest builder version must be positive" }
        require(bundle.manifest.designGeneratorVersion > 0) { "Manifest design generator version must be positive" }

        val seen = HashSet<String>(bundle.documents.size)
        var totalBytes = 0L
        bundle.documents.forEach { document ->
            validatePath(document.path)
            require(seen.add(document.path)) { "Duplicate site document path: ${document.path}" }
            require('\u0000' !in document.content) { "Site document contains NUL: ${document.path}" }
            require(document.byteSize <= MAX_DOCUMENT_BYTES) {
                "Site document exceeds size limit: ${document.path}"
            }
            totalBytes += document.byteSize
        }
        require(totalBytes <= MAX_TOTAL_BYTES) { "Site bundle exceeds total size limit" }
        require(bundle.preview.fileCount == bundle.documents.size) { "Preview file count mismatch" }
        require(bundle.preview.totalBytes == totalBytes) { "Preview total bytes mismatch" }
        require(bundle.preview.paths == bundle.documents.map(SiteDocument::path)) { "Preview path list mismatch" }
        require(bundle.manifest.fileCount == bundle.documents.size) { "Manifest file count mismatch" }
        require(bundle.manifest.totalBytes == totalBytes) { "Manifest total bytes mismatch" }
        require(bundle.manifest.treeSha256 == SiteBundleDigest.treeSha256(bundle.documents)) {
            "Manifest tree SHA-256 mismatch"
        }
    }

    internal fun validatePath(path: String) {
        require(path.isNotBlank()) { "Site document path must not be blank" }
        require(path.length <= 160) { "Site document path is too long" }
        require(path == path.trim()) { "Site document path must not contain surrounding whitespace" }
        require(!path.startsWith('/')) { "Absolute site document paths are forbidden" }
        require('\\' !in path) { "Backslashes are forbidden in site document paths" }
        require(allowedPath.matches(path)) { "Site document path contains unsupported characters: $path" }
        val segments = path.split('/')
        require(segments.none { it.isBlank() || it == "." || it == ".." }) {
            "Unsafe site document path: $path"
        }
        val extension = path.substringAfterLast('.', missingDelimiterValue = "").lowercase()
        require(extension in allowedExtensions) { "Unsupported site document extension: $path" }
    }
}

internal object SiteBundleDigest {
    fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    fun treeSha256(documents: List<SiteDocument>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        documents.forEach { document ->
            digest.update(document.path.encodeToByteArray())
            digest.update(0)
            digest.update(document.mediaType.encodeToByteArray())
            digest.update(0)
            digest.update(document.content.encodeToByteArray())
            digest.update(0)
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }
}
