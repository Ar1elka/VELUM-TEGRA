package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteBuilderEscapingTest {
    @Test
    fun `custom page text is normalized and html escaped`() {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(77)),
                siteName = "Safe Site",
            ),
        )
        val bundle = SiteBuilder.build(
            SiteBuildRequest(
                design = design,
                pages = listOf(
                    SitePageSpec(
                        kind = SitePageKind.HOME,
                        navLabel = "Home",
                        heading = "<Hello & goodbye>",
                        lead = "Use <b>plain</b> text & keep it safe.",
                        sections = listOf(
                            SiteContentSection("A < B", "Quoted \"text\" & more"),
                        ),
                    ),
                ),
            ),
        )
        val html = bundle.documents.single { it.path == "index.html" }.content

        assertTrue("&lt;Hello &amp; goodbye&gt;" in html)
        assertTrue("Use &lt;b&gt;plain&lt;/b&gt; text &amp; keep it safe." in html)
        assertFalse("<Hello & goodbye>" in html)
        assertFalse("<b>plain</b>" in html)
    }
}
