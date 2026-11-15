package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemotePreflightReadyTest {
    @Test
    fun `require absent plan becomes ready only from matching read only observation`() {
        withRemotePlan(7111L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT) { plan ->
            val trust = SiteRemotePreflightTrust(SERVER_KEY)
            val observation = readyObservation(plan)
            val first = SiteRemoteDeployPreflight.evaluate(plan, trust, observation)
            val second = SiteRemoteDeployPreflight.evaluate(plan, trust, observation)

            assertEquals(first, second)
            assertEquals(SiteRemotePreflightStatus.READY, first.status)
            assertTrue(first.checks.all { it.passed })
            assertEquals(plan.deploymentPlanSha256, first.deploymentPlanSha256)
            assertEquals(plan.totalBytes + SiteRemotePreflightPolicy.CAPACITY_RESERVE_BYTES, first.requiredAvailableBytes)
            assertTrue(first.preflightSha256.matches(Regex("^[0-9a-f]{64}$")))
            SiteRemotePreflightPolicy.validateReport(first)
        }
    }

    @Test
    fun `replace plan requires existing directory and absent backup`() {
        withRemotePlan(7112L, SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE) { plan ->
            val observation = readyObservation(plan).copy(
                target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.DIRECTORY, 4096),
                backup = SiteRemoteObservedPath(requireNotNull(plan.publish.backupRoot), SiteRemoteObservedPathType.ABSENT),
            )
            val report = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), observation)

            assertEquals(SiteRemotePreflightStatus.READY, report.status)
            assertTrue(report.checks.first { it.code == SiteRemotePreflightCheckCode.TARGET_STATE }.passed)
            assertTrue(report.checks.first { it.code == SiteRemotePreflightCheckCode.BACKUP_STATE }.passed)
        }
    }

    private fun readyObservation(plan: SiteRemoteDeployPlan) = SiteRemotePreflightObservation(
        server = SiteRemoteServerObservation(plan.remoteHostIdentity, SERVER_KEY),
        target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
        staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
        backup = plan.publish.backupRoot?.let { SiteRemoteObservedPath(it, SiteRemoteObservedPathType.ABSENT) },
        availableBytes = plan.totalBytes + SiteRemotePreflightPolicy.CAPACITY_RESERVE_BYTES,
        ownership = SiteRemoteOwnershipObservation(
            ownerExists = true,
            groupExists = true,
            ownershipChangeApplicable = true,
            modeChangeApplicable = true,
        ),
    )

    private fun withRemotePlan(seed: Long, policy: SiteRemoteExistingTargetPolicy, block: (SiteRemoteDeployPlan) -> Unit) {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))))),
        )
        val exportPlan = SitePreviewExportBoundary.prepare(bundle).export
        val root = Files.createTempDirectory("remote-preflight-")
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
                        existingTargetPolicy = policy,
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
