package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteBuilderTest {
    @Test
    fun `same design produces byte-stable bundle and manifest`() {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(20260916)),
                siteName = "Vela Forge",
                tagline = "Deterministic static site",
            ),
        )

        val first = SiteBuilder.build(SiteBuildRequest(design))
        val second = SiteBuilder.build(SiteBuildRequest(design))

        assertEquals(first, second)
        assertEquals(first.manifest.treeSha256, second.manifest.treeSha256)
        assertEquals(first.documents.map { it.path }, first.documents.map { it.path }.sorted())
    }

    @Test
    fun `default bundle contains only local static assets`() {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(42))),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design))
        val allContent = bundle.documents.joinToString("\n") { it.content }

        assertTrue("index.html" in bundle.preview.paths)
        assertTrue("about.html" in bundle.preview.paths)
        assertTrue("news.html" in bundle.preview.paths)
        assertTrue("resources.html" in bundle.preview.paths)
        assertTrue("downloads.html" in bundle.preview.paths)
        assertTrue("contact.html" in bundle.preview.paths)
        assertTrue("css/site.css" in bundle.preview.paths)
        assertTrue("assets/brand.svg" in bundle.preview.paths)
        assertFalse("href=\"http" in allContent.lowercase())
        assertFalse("src=\"http" in allContent.lowercase())
        assertFalse("url(http" in allContent.lowercase())
        assertFalse("<script" in allContent.lowercase())
        SiteBuildPolicy.validate(bundle)
    }

    @Test
    fun `changing design changes bundle fingerprint`() {
        val first = SiteBuilder.build(
            SiteBuildRequest(
                SiteDesignGenerator.generate(
                    SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(11))),
                ),
            ),
        )
        val second = SiteBuilder.build(
            SiteBuildRequest(
                SiteDesignGenerator.generate(
                    SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(12))),
                ),
            ),
        )

        assertNotEquals(first.manifest.treeSha256, second.manifest.treeSha256)
    }
}
