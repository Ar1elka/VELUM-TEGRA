package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteLocalExportSafetyTest {
    @Test
    fun rejectsTamperedPlanBeforeCreatingOutput() {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(3305L))))))
        val plan = SitePreviewExportBoundary.prepare(bundle).export
        val tampered = plan.copy(entries = plan.entries.mapIndexed { index, entry ->
            if (index == 0) entry.copy(content = entry.content + "tamper") else entry
        })
        val root = Files.createTempDirectory("site-export-reject-")
        try {
            assertFails { SiteLocalExportAdapter.export(tampered, root) }
            assertTrue(Files.list(root).use { it.findAny().isEmpty })
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun refusesExistingTargetWithoutOverwritingIt() {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(4405L))))))
        val plan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("site-export-existing-")
        val existing = root.resolve(plan.manifest.outputName)
        Files.writeString(existing, "keep-me")
        try {
            assertFails { SiteLocalExportAdapter.export(plan, root) }
            assertTrue(Files.readString(existing) == "keep-me")
            assertFalse(Files.list(root).use { stream -> stream.anyMatch { it.fileName.toString().contains(".tmp-") } })
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun verificationFailureCleansTemporaryOutput() {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(5505L))))))
        val plan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY, requestedBaseName = "cleanup-check"),
        ).export
        val root = Files.createTempDirectory("site-export-cleanup-")
        try {
            assertFails {
                SiteLocalExportAdapter.exportInternal(plan, root) { stage, temp ->
                    if (stage == SiteLocalExportStage.TEMP_WRITTEN) {
                        Files.writeString(temp.resolve(plan.entries.first().path), "corrupted")
                    }
                }
            }
            assertFalse(Files.exists(root.resolve(plan.manifest.outputName)))
            assertFalse(Files.list(root).use { stream -> stream.anyMatch { it.fileName.toString().contains(".tmp-") } })
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun assertFails(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Expected operation to fail")
        } catch (_: IllegalArgumentException) {
            // expected
        } catch (_: IllegalStateException) {
            // expected
        }
    }
}
