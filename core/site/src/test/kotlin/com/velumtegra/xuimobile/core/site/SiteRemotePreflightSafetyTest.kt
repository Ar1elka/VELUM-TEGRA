package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class SiteRemotePreflightSafetyTest {
    @Test
    fun `wrong identity occupied stage capacity and permission gaps block preflight`() {
        withRemotePlan(7201L) { plan ->
            val observation = readyObservation(plan).copy(
                server = SiteRemoteServerObservation("other.example.net", "8".repeat(64)),
                staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.SYMLINK),
                availableBytes = plan.totalBytes,
                ownership = SiteRemoteOwnershipObservation(
                    ownerExists = false,
                    groupExists = false,
                    ownershipChangeApplicable = false,
                    modeChangeApplicable = false,
                ),
            )
            val report = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), observation)

            assertEquals(SiteRemotePreflightStatus.BLOCKED, report.status)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.SERVER_HOST_IDENTITY }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.SERVER_KEY_FINGERPRINT }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.STAGING_STATE }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.OWNER_ACCOUNT }.passed)
            assertFalse(report.checks.first { it.code == SiteRemotePreflightCheckCode.MODE_APPLICABLE }.passed)
        }
    }

    @Test
    fun `observation paths are bound exactly to deployment plan`() {
        withRemotePlan(7202L) { plan ->
            val bad = readyObservation(plan).copy(
                target = SiteRemoteObservedPath("/var/www/other", SiteRemoteObservedPathType.ABSENT),
            )
            assertThrows(IllegalArgumentException::class.java) {
                SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), bad)
            }
        }
    }

    @Test
    fun `tampered report is rejected`() {
        withRemotePlan(7203L) { plan ->
            val report = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), readyObservation(plan))
            assertThrows(IllegalArgumentException::class.java) {
                SiteRemotePreflightPolicy.validateReport(report.copy(observationSha256 = "0".repeat(64)))
            }
        }
    }

    private fun readyObservation(plan: SiteRemoteDeployPlan) = SiteRemotePreflightObservation(
        server = SiteRemoteServerObservation(plan.remoteHostIdentity, SERVER_KEY),
        target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
        staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
        backup = null,
        availableBytes = plan.totalBytes + SiteRemotePreflightPolicy.CAPACITY_RESERVE_BYTES,
        ownership = SiteRemoteOwnershipObservation(true, true, true, true),
    )

    private fun withRemotePlan(seed: Long, block: (SiteRemoteDeployPlan) -> Unit) {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))))),
        )
        val exportPlan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("remote-preflight-safety-")
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
