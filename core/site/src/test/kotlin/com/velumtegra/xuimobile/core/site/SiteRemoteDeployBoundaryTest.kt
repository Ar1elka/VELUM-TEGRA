package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteDeployBoundaryTest {
    @Test
    fun `same verified source and request produce stable remote plan`() {
        withVerifiedExport(6116L, SiteExportFormat.DIRECTORY) { exportPlan, receipt ->
            val request = request(target = "/var/www/vela-site")
            val first = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, request)
            val second = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, request)

            assertEquals(first, second)
            assertEquals(exportPlan.manifest.sourceTreeSha256, first.sourceTreeSha256)
            assertEquals(exportPlan.entries.map { it.path }, first.entries.map { it.path })
            assertTrue(first.publish.stagingRoot.contains(exportPlan.manifest.sourceTreeSha256.take(12)))
            assertNull(first.publish.backupRoot)
            assertTrue(first.deploymentPlanSha256.matches(Regex("^[0-9a-f]{64}$")))
            SiteRemoteDeployPolicy.validatePlan(first)
        }
    }

    @Test
    fun `replace policy creates backup and rollback contract`() {
        withVerifiedExport(6117L, SiteExportFormat.ZIP) { exportPlan, receipt ->
            val plan = SiteRemoteDeployBoundary.prepare(
                exportPlan,
                receipt,
                request(
                    target = "/srv/www/client-site",
                    policy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ),
            )

            assertTrue(plan.publish.backupRoot?.contains(".velum-backup-") == true)
            assertTrue(plan.publish.requireBackupAbsent)
            assertTrue(plan.publish.rollbackOnFailure)
            assertTrue(plan.sourceArtifactSha256?.length == 64)
        }
    }

    private fun request(
        target: String,
        policy: SiteRemoteExistingTargetPolicy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
    ) = SiteRemoteDeployRequest(
        remoteHostIdentity = "vps-01.example.net",
        targetRoot = target,
        owner = "www-data",
        group = "www-data",
        existingTargetPolicy = policy,
    )

    private fun withVerifiedExport(
        seed: Long,
        format: SiteExportFormat,
        block: (SiteExportPlan, SiteLocalExportReceipt) -> Unit,
    ) {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))))),
        )
        val plan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = format, requestedBaseName = "remote-contract"),
        ).export
        val root = Files.createTempDirectory("remote-contract-")
        try {
            block(plan, SiteLocalExportAdapter.export(plan, root))
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
