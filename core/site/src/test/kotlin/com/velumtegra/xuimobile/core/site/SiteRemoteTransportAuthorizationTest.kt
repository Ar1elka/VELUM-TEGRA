package com.velumtegra.xuimobile.core.site

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteTransportAuthorizationTest {
    @Test
    fun `ready preflight produces deterministic bounded authorization`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(
            seed = 8111L,
            policy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
        )
        val capabilities = SiteRemoteTransportTestFixtures.fullCapabilities()

        val first = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, capabilities)
        val second = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, capabilities)

        assertEquals(first, second)
        assertEquals(fixture.plan.deploymentPlanSha256, first.deploymentPlanSha256)
        assertEquals(fixture.preflight.preflightSha256, first.preflightSha256)
        assertEquals(fixture.plan.fileCount, first.fileCount)
        assertEquals(fixture.plan.totalBytes, first.totalBytes)
        assertEquals(fixture.plan.fileCount, first.forwardOperations.count { it is SiteRemoteTransportOperation.UploadFile })
        assertTrue(first.forwardOperations.first() is SiteRemoteTransportOperation.AssertPathState)
        assertTrue(first.requiredCapabilities.contains(SiteRemoteTransportCapability.ROLLBACK_RENAME))
        assertTrue(first.authorizationSha256.matches(Regex("^[0-9a-f]{64}$")))
        SiteRemoteTransportPolicy.validateAuthorization(first)
    }

    @Test
    fun `require absent authorization does not require rollback rename`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(
            seed = 8112L,
            policy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
        )
        val authorization = SiteRemoteTransportBoundary.authorize(
            fixture.plan,
            fixture.preflight,
            SiteRemoteTransportTestFixtures.fullCapabilities(),
        )

        assertTrue(!authorization.requiredCapabilities.contains(SiteRemoteTransportCapability.ROLLBACK_RENAME))
        assertTrue(
            authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.AssertPathState>()
                .any { it.path == fixture.plan.publish.targetRoot && it.expectedType == SiteRemoteObservedPathType.ABSENT },
        )
    }
}

internal data class SiteRemoteTransportFixture(
    val exportPlan: SiteExportPlan,
    val plan: SiteRemoteDeployPlan,
    val preflight: SiteRemotePreflightReport,
)

internal object SiteRemoteTransportTestFixtures {
    val SERVER_KEY: String = "8".repeat(64)

    fun fullCapabilities() = SiteRemoteTransportCapabilities(
        implementationId = "fake-sftp-v1",
        capabilities = SiteRemoteTransportCapability.entries.sortedBy { it.name },
        maxFiles = SiteBuildPolicy.MAX_DOCUMENTS,
        maxTotalBytes = SiteBuildPolicy.MAX_TOTAL_BYTES,
        maxSingleFileBytes = SiteBuildPolicy.MAX_DOCUMENT_BYTES,
        maxRemotePathLength = 1024,
    )

    fun readyFixture(
        seed: Long,
        policy: SiteRemoteExistingTargetPolicy,
        certificateReuse: Boolean = false,
    ): SiteRemoteTransportFixture {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))))),
        )
        val exportPlan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        ).export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = exportPlan.manifest.outputName,
            outputPath = Path.of("/tmp/velum-transport-test/${exportPlan.manifest.outputName}"),
            fileCount = exportPlan.manifest.fileCount,
            totalBytes = exportPlan.manifest.totalBytes,
            sourceTreeSha256 = exportPlan.manifest.sourceTreeSha256,
            planSha256 = exportPlan.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val request = SiteRemoteDeployRequest(
            remoteHostIdentity = "vps-01.example.net",
            targetRoot = "/var/www/site",
            owner = "www-data",
            group = "www-data",
            existingTargetPolicy = policy,
            certificateReuse = if (certificateReuse) {
                SiteCertificateReuseRequest(
                    mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                    requestedDomain = "site.example.net",
                )
            } else {
                SiteCertificateReuseRequest()
            },
        )
        val plan = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, request)
        val certificate = if (certificateReuse) {
            SiteRemoteCertificateObservation(
                serverKeySha256 = SERVER_KEY,
                dnsNames = listOf("site.example.net"),
                certificateSha256 = "9".repeat(64),
                usableNow = true,
                privateKeyPresentOnServer = true,
            )
        } else {
            null
        }
        val observation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(plan.remoteHostIdentity, SERVER_KEY),
            target = SiteRemoteObservedPath(
                plan.publish.targetRoot,
                if (policy == SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT) {
                    SiteRemoteObservedPathType.ABSENT
                } else {
                    SiteRemoteObservedPathType.DIRECTORY
                },
            ),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
            backup = plan.publish.backupRoot?.let { SiteRemoteObservedPath(it, SiteRemoteObservedPathType.ABSENT) },
            availableBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(plan),
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = true,
                groupExists = true,
                ownershipChangeApplicable = true,
                modeChangeApplicable = true,
            ),
            certificate = certificate,
        )
        val preflight = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), observation)
        return SiteRemoteTransportFixture(exportPlan, plan, preflight)
    }
}
