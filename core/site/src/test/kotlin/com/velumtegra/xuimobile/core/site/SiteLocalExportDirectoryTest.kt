package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteLocalExportDirectoryTest {
    @Test
    fun writesAndVerifiesExactDirectoryPlan() {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(1105L))))))
        val plan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY, requestedBaseName = "Local Preview"),
        ).export
        val root = Files.createTempDirectory("site-export-dir-")
        try {
            val receipt = SiteLocalExportAdapter.export(plan, root)
            assertTrue(receipt.verified)
            assertEquals(null, receipt.artifactSha256)
            assertEquals("local-preview", receipt.outputName)
            assertEquals(plan.manifest.sourceTreeSha256, receipt.sourceTreeSha256)
            assertEquals(plan.entries.map { it.path }, Files.walk(receipt.outputPath).use { stream ->
                stream.filter(Files::isRegularFile)
                    .map { receipt.outputPath.relativize(it).toString().replace('\\', '/') }
                    .sorted()
                    .toList()
            })
            plan.entries.forEach { entry ->
                assertEquals(entry.content, Files.readString(receipt.outputPath.resolve(entry.path)))
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
