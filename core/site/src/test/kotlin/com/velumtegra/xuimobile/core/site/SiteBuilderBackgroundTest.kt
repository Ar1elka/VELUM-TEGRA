package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertTrue
import org.junit.Test

class SiteBuilderBackgroundTest {
    @Test
    fun `every background family renders a valid deterministic css bundle`() {
        BackgroundFamily.entries.forEachIndexed { index, family ->
            val design = SiteDesignGenerator.generate(
                SiteDesignRequest(
                    seeds = SiteDesignSeeds.fromRoot(DesignSeed(index.toLong() + 1000)),
                    backgroundFamily = family,
                ),
            )
            val bundle = SiteBuilder.build(SiteBuildRequest(design))
            val css = bundle.documents.single { it.path == "css/site.css" }.content

            assertTrue("background=${family.name}" in css)
            assertTrue("prefers-reduced-motion" in css)
            SiteBuildPolicy.validate(bundle)
        }
    }
}
