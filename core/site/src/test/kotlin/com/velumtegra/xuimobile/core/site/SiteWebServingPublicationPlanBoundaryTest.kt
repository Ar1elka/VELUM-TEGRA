package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingPublicationPlanBoundaryTest {
    @Test
    fun exactCommittedTargetProducesDeterministicHttpsNginxPlanWithoutMutationAuthority() {
        val rootA = Files.createTempDirectory("phase11_56-a-")
        val rootB = Files.createTempDirectory("phase11_56-b-")
        try {
            val preparationA = preparation(rootA, reuseCertificate = true)
            val preparationB = preparation(rootB, reuseCertificate = true)
            val cert = certificateReference(preparationA.remoteDeployPlan.remoteHostIdentity)

            val first = SiteWebServingPublicationPlanBoundary.prepare(
                request(preparationA, cert),
            )
            val second = SiteWebServingPublicationPlanBoundary.prepare(
                request(preparationB, cert),
            )

            assertEquals(first.publicationPlanSha256, second.publicationPlanSha256)
            assertEquals(first.desiredConfigSha256, second.desiredConfigSha256)
            assertEquals(first.configPath, second.configPath)
            assertEquals(
                first.configPath,
                SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
                    remoteHostIdentity = first.remoteHostIdentity,
                    targetRoot = first.targetRoot,
                    domain = first.domain,
                    port = first.port,
                ),
            )
            assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, first.protocol)
            assertEquals("site.example.com", first.domain)
            assertEquals(8443, first.port)
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
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test
    fun noCertificateReuseProducesHttpPlanAndRejectsUnexpectedCertificateReference() {
        val root = Files.createTempDirectory("phase11_56-http-")
        try {
            val preparation = preparation(root, reuseCertificate = false)
            val plan = SiteWebServingPublicationPlanBoundary.prepare(request(preparation, null))
            assertEquals(SiteWebServingProtocol.HTTP, plan.protocol)
            assertTrue("listen 8443;" in plan.desiredConfigUtf8)
            assertFalse("ssl_certificate" in plan.desiredConfigUtf8)
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingPublicationPlanBoundary.prepare(
                    request(preparation, certificateReference(preparation.remoteDeployPlan.remoteHostIdentity)),
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun mismatchedOrRolledBackEvidenceFailsClosed() {
        val root = Files.createTempDirectory("phase11_56-evidence-")
        try {
            val preparation = preparation(root, reuseCertificate = true)
            val base = evidence(preparation)
            val cert = certificateReference(preparation.remoteDeployPlan.remoteHostIdentity)
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingPublicationPlanBoundary.prepare(
                    SiteWebServingPublicationPlanRequest(
                        preparation,
                        base.copy(committedClean = false),
                        SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
                        cert,
                    ),
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingPublicationPlanBoundary.prepare(
                    SiteWebServingPublicationPlanRequest(
                        preparation,
                        base.copy(finalTargetTreeSha256 = "0".repeat(64)),
                        SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
                        cert,
                    ),
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingPublicationPlanBoundary.prepare(
                    request(
                        preparation,
                        cert.copy(dnsNames = listOf("other.example.com")),
                    ),
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun exactBindingChangesProduceDifferentPublicationPlanIdentity() {
        val rootA = Files.createTempDirectory("phase11_56-bind-a-")
        val rootB = Files.createTempDirectory("phase11_56-bind-b-")
        try {
            val firstPrep = preparation(rootA, reuseCertificate = false)
            val secondPrep = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1156L),
                    domain = "site.example.com",
                    servicePort = 9443,
                    remoteHostIdentity = "server-1.example",
                    targetRoot = "/srv/www/site",
                    owner = "www_data",
                    group = "www_data",
                    reuseExisting3xUiCertificate = false,
                ),
                rootB,
            )
            val first = SiteWebServingPublicationPlanBoundary.prepare(request(firstPrep, null))
            val second = SiteWebServingPublicationPlanBoundary.prepare(request(secondPrep, null))
            assertNotEquals(first.publicationPlanSha256, second.publicationPlanSha256)
            assertNotEquals(first.configPath, second.configPath)
            assertNotEquals(first.desiredConfigSha256, second.desiredConfigSha256)
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test
    fun exactNginxConfigPathIsPureDeterministicAndRejectsUnsafeIdentity() {
        val first = SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
            remoteHostIdentity = "server-1.example",
            targetRoot = "/srv/www/site",
            domain = "Site.Example.COM",
            port = 8443,
        )
        val second = SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
            remoteHostIdentity = "server-1.example",
            targetRoot = "/srv/www/site",
            domain = "site.example.com",
            port = 8443,
        )
        assertEquals(first, second)
        assertTrue(first.startsWith("/etc/nginx/conf.d/velum-tegra-"))
        assertTrue(first.endsWith(".conf"))
        assertThrows(IllegalArgumentException::class.java) {
            SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
                remoteHostIdentity = "server-1.example",
                targetRoot = "/srv/www/site/",
                domain = "site.example.com",
                port = 8443,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
                remoteHostIdentity = "server-1.example\nother",
                targetRoot = "/srv/www/site",
                domain = "site.example.com",
                port = 8443,
            )
        }
    }

    private fun request(
        preparation: SiteDeployerLocalPreparationResult,
        certificate: SiteServerCertificateFileReference?,
    ) = SiteWebServingPublicationPlanRequest(
        preparation = preparation,
        staticPublicationEvidence = evidence(preparation),
        strategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
        certificateReference = certificate,
    )

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) = SiteStaticPublicationEvidence(
        preparationSha256 = preparation.preparationSha256,
        remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
        targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
        finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
        committedClean = true,
        remoteResidualStateClean = true,
    )

    private fun certificateReference(host: String) = SiteServerCertificateFileReference(
        remoteHostIdentity = host,
        certificateSha256 = "a".repeat(64),
        dnsNames = listOf("site.example.com"),
        certificatePath = "/etc/x-ui/cert/fullchain.pem",
        privateKeyPath = "/etc/x-ui/cert/private.key",
        usableNow = true,
        privateKeyPresentOnServer = true,
    )

    private fun preparation(root: Path, reuseCertificate: Boolean) = SiteDeployerLocalPreparationBoundary.prepare(
        SiteDeployerLocalPreparationRequest(
            rootSeed = DesignSeed(1156L),
            domain = "Site.Example.COM",
            servicePort = 8443,
            remoteHostIdentity = "server-1.example",
            targetRoot = "/srv/www/site",
            owner = "www_data",
            group = "www_data",
            reuseExisting3xUiCertificate = reuseCertificate,
        ),
        root,
    )

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
