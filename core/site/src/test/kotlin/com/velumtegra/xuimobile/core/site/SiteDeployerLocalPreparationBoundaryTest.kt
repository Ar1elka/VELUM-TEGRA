package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDeployerLocalPreparationBoundaryTest {
    @Test
    fun `same constructor request produces byte-stable verified package and exact remote plan`() {
        val firstRoot = Files.createTempDirectory("site-local-prep-a-")
        val secondRoot = Files.createTempDirectory("site-local-prep-b-")
        try {
            val request = baseRequest()
            val first = SiteDeployerLocalPreparationBoundary.prepare(request, firstRoot)
            val second = SiteDeployerLocalPreparationBoundary.prepare(request, secondRoot)

            assertEquals(first.design, second.design)
            assertEquals(first.bundle.manifest, second.bundle.manifest)
            assertEquals(first.previewExport.export.manifest, second.previewExport.export.manifest)
            assertEquals(first.localExportReceipt.artifactSha256, second.localExportReceipt.artifactSha256)
            assertEquals(first.remoteDeployPlan, second.remoteDeployPlan)
            assertEquals(first.preparationSha256, second.preparationSha256)
            assertTrue(first.localExportReceipt.verified)
            assertTrue(Files.exists(first.localArtifactPath))
            assertTrue(Files.exists(second.localArtifactPath))
            assertFalse(first.productionNetworkTouched)
            assertFalse(first.remoteMutationPerformed)
            assertFalse(first.coordinatorInvoked)
            assertFalse(first.transportAuthorized)
        } finally {
            deleteTree(firstRoot)
            deleteTree(secondRoot)
        }
    }

    @Test
    fun `new randomizer seed changes generated package while keeping bounded deployment contract`() {
        val firstRoot = Files.createTempDirectory("site-local-variant-a-")
        val secondRoot = Files.createTempDirectory("site-local-variant-b-")
        try {
            val first = SiteDeployerLocalPreparationBoundary.prepare(baseRequest(), firstRoot)
            val second = SiteDeployerLocalPreparationBoundary.prepare(
                baseRequest().copy(rootSeed = DesignSeed(1152L)),
                secondRoot,
            )

            assertNotEquals(first.preparationSha256, second.preparationSha256)
            assertNotEquals(first.previewExport.preview.treeSha256, second.previewExport.preview.treeSha256)
            assertEquals(first.remoteDeployPlan.publish.targetRoot, second.remoteDeployPlan.publish.targetRoot)
            assertNotEquals(first.remoteDeployPlan.publish.stagingRoot, second.remoteDeployPlan.publish.stagingRoot)
            assertFalse(second.transportAuthorized)
        } finally {
            deleteTree(firstRoot)
            deleteTree(secondRoot)
        }
    }

    @Test
    fun `domain port and existing 3x-ui certificate reuse are bound without moving private key or configuring listener`() {
        val root = Files.createTempDirectory("site-local-cert-")
        try {
            val result = SiteDeployerLocalPreparationBoundary.prepare(
                baseRequest().copy(
                    domain = "WWW.Example.COM",
                    servicePort = 8443,
                    reuseExisting3xUiCertificate = true,
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ),
                root,
            )

            assertEquals("www.example.com", result.serviceBinding.domain)
            assertEquals(8443, result.serviceBinding.port)
            assertFalse(result.serviceBinding.appliedByCurrentDeployContract)
            assertEquals(SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN, result.remoteDeployPlan.certificate.mode)
            assertEquals("www.example.com", result.remoteDeployPlan.certificate.requiredDomain)
            assertEquals(SitePrivateKeyHandling.REMAIN_ON_SERVER, result.remoteDeployPlan.certificate.privateKeyHandling)
            assertTrue(result.remoteDeployPlan.publish.backupRoot != null)
            assertTrue(result.remoteDeployPlan.publish.rollbackOnFailure)
        } finally {
            deleteTree(root)
        }
    }

    private fun baseRequest() = SiteDeployerLocalPreparationRequest(
        rootSeed = DesignSeed(1151L),
        domain = "site.example.com",
        servicePort = 443,
        remoteHostIdentity = "fixture.local",
        targetRoot = "/srv/www/site",
        owner = "www_data",
        group = "www_data",
    )

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
