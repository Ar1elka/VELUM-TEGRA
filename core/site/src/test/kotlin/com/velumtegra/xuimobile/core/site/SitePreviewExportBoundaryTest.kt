package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SitePreviewExportBoundaryTest {
    @Test
    fun `same bundle produces stable preview and export plan`() {
        val bundle = bundleFor("Vela Forge", 77)

        val first = SitePreviewExportBoundary.prepare(bundle)
        val second = SitePreviewExportBoundary.prepare(bundle)

        assertEquals(first, second)
        assertEquals("index.html", first.preview.entryPath)
        assertEquals(1, first.preview.files.count { it.isEntryPoint })
        assertEquals(bundle.manifest.treeSha256, first.export.manifest.sourceTreeSha256)
        assertEquals(bundle.documents.map { it.path }, first.export.entries.map { it.path })
        SitePreviewExportPolicy.validate(first)
    }

    @Test
    fun `directory and zip formats keep identical source entries`() {
        val bundle = bundleFor("Arc Node", 88)
        val directory = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        )
        val zip = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.ZIP),
        )

        assertEquals(directory.export.entries, zip.export.entries)
        assertEquals("arc-node", directory.export.manifest.outputName)
        assertEquals("arc-node.zip", zip.export.manifest.outputName)
        assertNotEquals(directory.export.manifest.planSha256, zip.export.manifest.planSha256)
    }

    @Test
    fun `explicit output name is normalized deterministically`() {
        val bundle = bundleFor("Vela Forge", 99)
        val plan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(requestedBaseName = "  Client Demo 01  "),
        )

        assertEquals("client-demo-01", plan.export.manifest.outputBaseName)
        assertEquals("client-demo-01.zip", plan.export.manifest.outputName)
        assertTrue(plan.export.manifest.planSha256.length == 64)
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
