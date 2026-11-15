package com.velumtegra.xuimobile.integration

import android.os.StrictMode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SitePrivateKeyHandling
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_51RealDeviceSiteDeployerLocalPreparationAcceptanceInstrumentedTest {
    @Test
    fun deterministicRandomizerBuildsVerifiedLocalArtifactAndExactDeploymentPlanWithoutNetworkOrRemoteMutation() {
        val priorPolicy = StrictMode.getThreadPolicy()
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder(priorPolicy)
                .detectNetwork()
                .penaltyDeath()
                .build(),
        )
        val cacheRoot = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir.toPath()
        val firstRoot = Files.createTempDirectory(cacheRoot, "phase11_51-a-")
        val secondRoot = Files.createTempDirectory(cacheRoot, "phase11_51-b-")
        val variantRoot = Files.createTempDirectory(cacheRoot, "phase11_51-c-")
        try {
            val request = SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1151L),
                domain = "Site.Example.COM",
                servicePort = 8443,
                remoteHostIdentity = "fixture.local",
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = true,
            )
            val first = SiteDeployerLocalPreparationBoundary.prepare(request, firstRoot)
            val second = SiteDeployerLocalPreparationBoundary.prepare(request, secondRoot)
            val variant = SiteDeployerLocalPreparationBoundary.prepare(
                request.copy(rootSeed = DesignSeed(1152L)),
                variantRoot,
            )

            assertTrue(first.localExportReceipt.verified)
            assertTrue(Files.isRegularFile(first.localArtifactPath))
            assertEquals(first.previewExport.preview.treeSha256, first.remoteDeployPlan.sourceTreeSha256)
            assertEquals(first.previewExport.export.manifest.planSha256, first.remoteDeployPlan.sourcePlanSha256)
            assertEquals(first.localExportReceipt.artifactSha256, first.remoteDeployPlan.sourceArtifactSha256)
            assertEquals(first.preparationSha256, second.preparationSha256)
            assertEquals(first.remoteDeployPlan, second.remoteDeployPlan)
            assertEquals(first.localExportReceipt.artifactSha256, second.localExportReceipt.artifactSha256)
            assertNotEquals(first.preparationSha256, variant.preparationSha256)
            assertNotEquals(first.previewExport.preview.treeSha256, variant.previewExport.preview.treeSha256)
            assertEquals("site.example.com", first.serviceBinding.domain)
            assertEquals(8443, first.serviceBinding.port)
            assertFalse(first.serviceBinding.appliedByCurrentDeployContract)
            assertEquals(SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN, first.remoteDeployPlan.certificate.mode)
            assertEquals("site.example.com", first.remoteDeployPlan.certificate.requiredDomain)
            assertEquals(SitePrivateKeyHandling.REMAIN_ON_SERVER, first.remoteDeployPlan.certificate.privateKeyHandling)
            assertFalse(first.productionNetworkTouched)
            assertFalse(first.remoteMutationPerformed)
            assertFalse(first.coordinatorInvoked)
            assertFalse(first.transportAuthorized)
        } finally {
            deleteTree(firstRoot)
            deleteTree(secondRoot)
            deleteTree(variantRoot)
            StrictMode.setThreadPolicy(priorPolicy)
        }
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
