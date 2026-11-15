package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertThrows
import org.junit.Test

class SiteBuilderPolicyTest {
    @Test
    fun `unsafe relative paths are rejected`() {
        listOf("../index.html", "/index.html", "css\\site.css", "./index.html").forEach { path ->
            assertThrows(IllegalArgumentException::class.java) {
                SiteBuildPolicy.validatePath(path)
            }
        }
    }

    @Test
    fun `duplicate document paths are rejected`() {
        val documents = listOf(
            SiteDocument("index.html", "text/html", "a"),
            SiteDocument("index.html", "text/html", "b"),
        )
        val total = documents.sumOf { it.byteSize.toLong() }
        val bundle = SiteBundle(
            documents = documents,
            preview = SiteBuildPreview("Test", 2, total, documents.map { it.path }),
            manifest = SiteBuildManifest(
                builderVersion = 1,
                designGeneratorVersion = 1,
                siteName = "Test",
                fileCount = 2,
                totalBytes = total,
                treeSha256 = SiteBundleDigest.treeSha256(documents),
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteBuildPolicy.validate(bundle)
        }
    }

    @Test
    fun `tampered brand svg with external reference is rejected`() {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(55))),
        )
        val tampered = design.copy(
            brand = design.brand.copy(
                svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"https://example.invalid/a.png\"/></svg>",
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteBuilder.build(SiteBuildRequest(tampered))
        }
    }

}
