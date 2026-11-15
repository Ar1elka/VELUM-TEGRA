package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SitePreviewExportIntegrityTest {
    @Test
    fun `preview metadata mirrors exact export entries`() {
        val bundle = bundleFor(1001)
        val plan = SitePreviewExportBoundary.prepare(bundle)

        val previewProjection = plan.preview.files.map { file ->
            listOf(file.path, file.mediaType, file.byteSize.toString(), file.sha256)
        }
        val exportProjection = plan.export.entries.map { file ->
            listOf(file.path, file.mediaType, file.byteSize.toString(), file.sha256)
        }
        assertEquals(exportProjection, previewProjection)
    }

    @Test
    fun `tampered plan fingerprint is rejected`() {
        val plan = SitePreviewExportBoundary.prepare(bundleFor(1002))
        val tampered = plan.copy(
            export = plan.export.copy(
                manifest = plan.export.manifest.copy(planSha256 = "0".repeat(64)),
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SitePreviewExportPolicy.validate(tampered)
        }
    }

    private fun bundleFor(seed: Long): SiteBundle {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(seed))),
        )
        return SiteBuilder.build(SiteBuildRequest(design))
    }
}
