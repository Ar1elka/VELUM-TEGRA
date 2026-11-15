package com.velumtegra.xuimobile.integration

import android.os.StrictMode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteServerCertificateFileReference
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_56RealDeviceSiteDeployerWebServingPublicationPlanAcceptanceInstrumentedTest {
    @Test
    fun exactCommittedStaticTargetProducesDeterministicHttpsNginxPlanWithoutNetworkOrMutationAuthority() {
        val priorPolicy = StrictMode.getThreadPolicy()
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder(priorPolicy)
                .detectNetwork()
                .penaltyDeath()
                .build(),
        )
        val cacheRoot = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir.toPath()
        val firstRoot = Files.createTempDirectory(cacheRoot, "phase11_56-a-")
        val secondRoot = Files.createTempDirectory(cacheRoot, "phase11_56-b-")
        try {
            val request = SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1156L),
                domain = "Site.Example.COM",
                servicePort = 8443,
                remoteHostIdentity = "server-1.example",
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = true,
            )
            val firstPreparation = SiteDeployerLocalPreparationBoundary.prepare(request, firstRoot)
            val secondPreparation = SiteDeployerLocalPreparationBoundary.prepare(request, secondRoot)
            val certificate = SiteServerCertificateFileReference(
                remoteHostIdentity = "server-1.example",
                certificateSha256 = "a".repeat(64),
                dnsNames = listOf("site.example.com"),
                certificatePath = "/etc/x-ui/cert/fullchain.pem",
                privateKeyPath = "/etc/x-ui/cert/private.key",
                usableNow = true,
                privateKeyPresentOnServer = true,
            )
            fun plan(preparation: com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult) =
                SiteWebServingPublicationPlanBoundary.prepare(
                    SiteWebServingPublicationPlanRequest(
                        preparation = preparation,
                        staticPublicationEvidence = SiteStaticPublicationEvidence(
                            preparationSha256 = preparation.preparationSha256,
                            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
                            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                            committedClean = true,
                            remoteResidualStateClean = true,
                        ),
                        strategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
                        certificateReference = certificate,
                    ),
                )

            val first = plan(firstPreparation)
            val second = plan(secondPreparation)
            assertEquals(first.publicationPlanSha256, second.publicationPlanSha256)
            assertEquals(first.desiredConfigSha256, second.desiredConfigSha256)
            assertEquals(first.configPath, second.configPath)
            assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, first.protocol)
            assertEquals("site.example.com", first.domain)
            assertEquals(8443, first.port)
            assertTrue(first.configPath.startsWith("/etc/nginx/conf.d/velum-tegra-"))
            assertTrue("listen 8443 ssl;" in first.desiredConfigUtf8)
            assertTrue("server_name site.example.com;" in first.desiredConfigUtf8)
            assertTrue("root /srv/www/site;" in first.desiredConfigUtf8)
            assertTrue("ssl_certificate /etc/x-ui/cert/fullchain.pem;" in first.desiredConfigUtf8)
            assertTrue("ssl_certificate_key /etc/x-ui/cert/private.key;" in first.desiredConfigUtf8)
            assertTrue(first.requiresReadOnlyServerPreflight)
            assertTrue(first.requiresLivePortConflictProof)
            assertTrue(first.requiresConfigSyntaxValidationBeforeActivation)
            assertTrue(first.requiresDurableRollbackCheckpoint)
            assertTrue(first.requiresPostServeVerification)
            assertFalse(first.configMutationAuthorized)
            assertFalse(first.webServerReloadAuthorized)
            assertFalse(first.dnsMutationAuthorized)
            assertFalse(first.firewallMutationAuthorized)
            assertFalse(first.packageInstallAuthorized)
            assertFalse(first.certificatePrivateKeyTransferRequired)
        } finally {
            deleteTree(firstRoot)
            deleteTree(secondRoot)
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
