package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteDeployCertificateTest {
    @Test
    fun `3x-ui certificate reuse is only expressed as exact-domain same-server requirement`() {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(6301L))))),
        )
        val exportPlan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("remote-cert-")
        try {
            val receipt = SiteLocalExportAdapter.export(exportPlan, root)
            val plan = SiteRemoteDeployBoundary.prepare(
                exportPlan,
                receipt,
                SiteRemoteDeployRequest(
                    remoteHostIdentity = "vps-01.example.net",
                    targetRoot = "/var/www/site",
                    owner = "www-data",
                    group = "www-data",
                    certificateReuse = SiteCertificateReuseRequest(
                        mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                        requestedDomain = "WWW.Example.COM",
                    ),
                ),
            )

            assertEquals("www.example.com", plan.certificate.requiredDomain)
            assertTrue(plan.certificate.sameServerRequired)
            assertEquals(SitePrivateKeyHandling.REMAIN_ON_SERVER, plan.certificate.privateKeyHandling)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `certificate request rejects wildcard path-like and missing domain`() {
        val base = SiteRemoteDeployRequest(
            remoteHostIdentity = "vps-01.example.net",
            targetRoot = "/var/www/site",
            owner = "www-data",
            group = "www-data",
        )
        listOf("*.example.com", "example/com", "localhost").forEach { badDomain ->
            assertThrows(IllegalArgumentException::class.java) {
                SiteRemoteDeployPolicy.validateRequest(
                    base.copy(
                        certificateReuse = SiteCertificateReuseRequest(
                            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                            badDomain,
                        ),
                    ),
                )
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteDeployPolicy.validateRequest(
                base.copy(certificateReuse = SiteCertificateReuseRequest(SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN)),
            )
        }
    }
}
