package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertThrows
import org.junit.Test

class SiteRemoteDeploySafetyTest {
    @Test
    fun `rejects unsafe remote roots accounts and modes`() {
        val base = SiteRemoteDeployRequest(
            remoteHostIdentity = "vps-01.example.net",
            targetRoot = "/var/www/site",
            owner = "www-data",
            group = "www-data",
        )
        listOf("/", "relative/site", "/var/www/../site", "/var//www/site", "/var/www/site/").forEach { badRoot ->
            assertThrows(IllegalArgumentException::class.java) {
                SiteRemoteDeployPolicy.validateRequest(base.copy(targetRoot = badRoot))
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteDeployPolicy.validateRequest(base.copy(owner = "root;rm"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteDeployPolicy.validateRequest(base.copy(fileMode = "0777"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteDeployPolicy.validateRequest(base.copy(directoryMode = "0777"))
        }
    }

    @Test
    fun `rejects unverified or mismatched local receipt`() {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(6201L))))),
        )
        val exportPlan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("remote-contract-safety-")
        try {
            val receipt = SiteLocalExportAdapter.export(exportPlan, root)
            val request = SiteRemoteDeployRequest(
                remoteHostIdentity = "vps-01.example.net",
                targetRoot = "/var/www/site",
                owner = "www-data",
                group = "www-data",
            )
            assertThrows(IllegalArgumentException::class.java) {
                SiteRemoteDeployBoundary.prepare(exportPlan, receipt.copy(verified = false), request)
            }
            assertThrows(IllegalArgumentException::class.java) {
                SiteRemoteDeployBoundary.prepare(exportPlan, receipt.copy(sourceTreeSha256 = "0".repeat(64)), request)
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
