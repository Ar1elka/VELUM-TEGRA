package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SitePreviewExportPolicyTest {
    @Test
    fun `requested output name rejects path and extension syntax`() {
        val bundle = bundleFor("Safe Site", 123)
        listOf("../escape", "nested/name", "nested\\name", "site.zip").forEach { name ->
            assertThrows(IllegalArgumentException::class.java) {
                SitePreviewExportBoundary.prepare(
                    bundle,
                    SitePreviewExportRequest(requestedBaseName = name),
                )
            }
        }
    }

    @Test
    fun `non ascii site name gets deterministic hash fallback`() {
        val bundle = bundleFor("Астра", 456)
        val first = SitePreviewExportBoundary.prepare(bundle)
        val second = SitePreviewExportBoundary.prepare(bundle)

        assertTrue(first.export.manifest.outputBaseName.startsWith("site-"))
        assertTrue(first.export.manifest.outputBaseName.length == 17)
        assertTrue(first.export.manifest.outputBaseName == second.export.manifest.outputBaseName)
    }

    @Test
    fun `tampered export content is rejected before io`() {
        val bundle = bundleFor("Safe Site", 789)
        val prepared = SitePreviewExportBoundary.prepare(bundle)
        val first = prepared.export.entries.first()
        val tampered = prepared.copy(
            export = prepared.export.copy(
                entries = listOf(first.copy(content = first.content + "tampered")) + prepared.export.entries.drop(1),
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SitePreviewExportPolicy.validate(tampered)
        }
    }

    private fun bundleFor(name: String, seed: Long): SiteBundle {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(seed)),
                siteName = name,
            ),
        )
        return SiteBuilder.build(SiteBuildRequest(design))
    }
}
