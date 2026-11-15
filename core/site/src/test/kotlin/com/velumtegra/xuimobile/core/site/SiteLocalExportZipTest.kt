package com.velumtegra.xuimobile.core.site

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.zip.ZipFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteLocalExportZipTest {
    @Test
    fun writesVerifiedZipContainingOnlyPlannedEntries() {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(2205L))))))
        val plan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("site-export-zip-")
        try {
            val receipt = SiteLocalExportAdapter.export(plan, root)
            assertTrue(receipt.verified)
            assertEquals(SiteExportFormat.ZIP, receipt.format)
            assertTrue(receipt.artifactSha256 != null)
            ZipFile(receipt.outputPath.toFile(), StandardCharsets.UTF_8).use { zip ->
                val actual = zip.entries().toList()
                assertEquals(plan.entries.map { it.path }, actual.map { it.name })
                actual.zip(plan.entries).forEach { (zipEntry, expected) ->
                    assertEquals(expected.content, zip.getInputStream(zipEntry).bufferedReader().use { it.readText() })
                }
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
