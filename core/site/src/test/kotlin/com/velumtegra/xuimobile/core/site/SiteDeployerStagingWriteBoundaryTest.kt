package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDeployerStagingWriteBoundaryTest {
    @Test
    fun exactPreparationProducesOnlyStagingPathsAndStableHash() {
        val rootA = Files.createTempDirectory("site-stage-plan-a-")
        val rootB = Files.createTempDirectory("site-stage-plan-b-")
        try {
            val request = SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1152L),
                domain = "phase1152.example.com",
                servicePort = 8443,
                remoteHostIdentity = "192.0.2.169",
                targetRoot = "/tmp/velum-p1152-unit",
                owner = "root",
                group = "root",
            )
            val first = SiteDeployerLocalPreparationBoundary.prepare(request, rootA)
            val second = SiteDeployerLocalPreparationBoundary.prepare(request, rootB)
            val a = SiteDeployerStagingWriteBoundary.prepare(first)
            val b = SiteDeployerStagingWriteBoundary.prepare(second)
            assertEquals(a, b)
            assertEquals(first.preparationSha256, a.preparationSha256)
            assertEquals(first.remoteDeployPlan.publish.stagingRoot, a.stagingRoot)
            assertEquals(first.bundle.manifest.treeSha256, a.sourceTreeSha256)
            assertEquals(first.bundle.manifest.fileCount, a.fileCount)
            assertEquals(first.bundle.manifest.totalBytes, a.totalBytes)
            assertTrue(a.directories.all { it.remotePath == a.stagingRoot || it.remotePath.startsWith(a.stagingRoot + "/") })
            assertTrue(a.files.all { it.remotePath.startsWith(a.stagingRoot + "/") })
            assertTrue(a.files.none { it.remotePath == a.targetRoot || it.remotePath.startsWith(a.targetRoot + "/") })
            SiteDeployerStagingWriteBoundary.validate(a, first.bundle)
        } finally {
            listOf(rootA, rootB).forEach { root ->
                Files.walk(root).use { s -> s.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
            }
        }
    }
}
