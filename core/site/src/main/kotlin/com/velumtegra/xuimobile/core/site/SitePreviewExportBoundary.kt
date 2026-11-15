package com.velumtegra.xuimobile.core.site

object SitePreviewExportBoundary {
    const val BOUNDARY_VERSION: Int = 1

    fun prepare(
        bundle: SiteBundle,
        request: SitePreviewExportRequest = SitePreviewExportRequest(),
    ): SitePreviewExportPlan {
        SiteBuildPolicy.validate(bundle)
        require(bundle.documents.any { it.path == "index.html" }) {
            "Site bundle must contain index.html for local preview"
        }

        val entries = bundle.documents.map { document ->
            SiteExportEntry(
                path = document.path,
                mediaType = document.mediaType,
                content = document.content,
                byteSize = document.byteSize,
                sha256 = document.sha256,
            )
        }
        val previewFiles = entries.map { entry ->
            SitePreviewFile(
                path = entry.path,
                mediaType = entry.mediaType,
                byteSize = entry.byteSize,
                sha256 = entry.sha256,
                isEntryPoint = entry.path == "index.html",
            )
        }
        val baseName = SitePreviewExportPolicy.resolveOutputBaseName(
            requestedBaseName = request.requestedBaseName,
            siteName = bundle.manifest.siteName,
            treeSha256 = bundle.manifest.treeSha256,
        )
        val outputName = SitePreviewExportPolicy.outputName(baseName, request.format)
        val manifestBase = SiteExportManifest(
            boundaryVersion = BOUNDARY_VERSION,
            format = request.format,
            outputBaseName = baseName,
            outputName = outputName,
            sourceTreeSha256 = bundle.manifest.treeSha256,
            fileCount = entries.size,
            totalBytes = bundle.manifest.totalBytes,
            planSha256 = "",
        )
        val manifest = manifestBase.copy(
            planSha256 = SitePreviewExportDigest.planSha256(entries, manifestBase),
        )
        val result = SitePreviewExportPlan(
            preview = SitePreviewPlan(
                entryPath = "index.html",
                siteName = bundle.manifest.siteName,
                fileCount = entries.size,
                totalBytes = bundle.manifest.totalBytes,
                treeSha256 = bundle.manifest.treeSha256,
                files = previewFiles,
            ),
            export = SiteExportPlan(
                entries = entries,
                manifest = manifest,
            ),
        )
        SitePreviewExportPolicy.validate(result)
        return result
    }
}
