package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemotePreflightCertificateTest {
    @Test
    fun `certificate reuse becomes ready only for exact domain on same trusted server`() {
        withCertificatePlan(7301L) { plan ->
            val observation = baseObservation(plan).copy(
                certificate = certificate(
                    serverKey = SERVER_KEY,
                    dnsNames = listOf("api.example.com", "www.example.com"),
                    usable = true,
                    privateKeyPresent = true,
                ),
            )
            val report = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), observation)

            assertEquals(SiteRemotePreflightStatus.READY, report.status)
            assertTrue(report.checks.first { it.code == SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN }.passed)
            assertTrue(report.checks.first { it.code == SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT }.passed)
        }
    }

    @Test
    fun `certificate mismatch expiry or off server key blocks reuse without exposing key material`() {
        withCertificatePlan(7302L) { plan ->
            val observation = baseObservation(plan).copy(
                certificate = certificate(
                    serverKey = "9".repeat(64),
                    dnsNames = listOf("api.example.com"),
                    usable = false,
                    privateKeyPresent = false,
                ),
            )
            val report = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), observation)

            assertEquals(SiteRemotePreflightStatus.BLOCKED, report.status)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.CERTIFICATE_SERVER_IDENTITY }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT }.passed)
        }
    }

    private fun certificate(
        serverKey: String,
        dnsNames: List<String>,
        usable: Boolean,
        privateKeyPresent: Boolean,
    ) = SiteRemoteCertificateObservation(
        serverKeySha256 = serverKey,
        dnsNames = dnsNames,
        certificateSha256 = "a".repeat(64),
        usableNow = usable,
        privateKeyPresentOnServer = privateKeyPresent,
    )

    private fun baseObservation(plan: SiteRemoteDeployPlan) = SiteRemotePreflightObservation(
        server = SiteRemoteServerObservation(plan.remoteHostIdentity, SERVER_KEY),
        target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
        staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
        backup = null,
        availableBytes = plan.totalBytes + SiteRemotePreflightPolicy.CAPACITY_RESERVE_BYTES,
        ownership = SiteRemoteOwnershipObservation(true, true, true, true),
    )

    private fun withCertificatePlan(seed: Long, block: (SiteRemoteDeployPlan) -> Unit) {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))))),
        )
        val exportPlan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("remote-preflight-cert-")
        try {
            val receipt = SiteLocalExportAdapter.export(exportPlan, root)
            block(
                SiteRemoteDeployBoundary.prepare(
                    exportPlan,
                    receipt,
                    SiteRemoteDeployRequest(
                        remoteHostIdentity = "vps-01.example.net",
                        targetRoot = "/var/www/site",
                        owner = "www-data",
                        group = "www-data",
                        certificateReuse = SiteCertificateReuseRequest(
                            mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                            requestedDomain = "www.example.com",
                        ),
                    ),
                ),
            )
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private companion object {
        val SERVER_KEY = "7".repeat(64)
    }
}
