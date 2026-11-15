package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertThrows
import org.junit.Test

class SiteRemoteTransportSafetyTest {
    @Test
    fun `blocked preflight cannot authorize transport`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8121L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val blocked = fixture.preflight.copy(
            checks = fixture.preflight.checks.map { check ->
                if (check.code == SiteRemotePreflightCheckCode.STAGING_STATE) check.copy(passed = false) else check
            },
            status = SiteRemotePreflightStatus.BLOCKED,
            preflightSha256 = "",
        ).let { it.copy(preflightSha256 = SiteRemotePreflightDigest.reportSha256(it)) }

        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteTransportBoundary.authorize(fixture.plan, blocked, SiteRemoteTransportTestFixtures.fullCapabilities())
        }
    }

    @Test
    fun `incomplete forged ready report is rejected even when digest is internally consistent`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8122L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val incomplete = SiteRemotePreflightReport(
            contractVersion = SiteRemotePreflightPolicy.CONTRACT_VERSION,
            deploymentPlanSha256 = fixture.plan.deploymentPlanSha256,
            observationSha256 = fixture.preflight.observationSha256,
            requiredAvailableBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(fixture.plan),
            checks = listOf(
                SiteRemotePreflightCheck(
                    SiteRemotePreflightCheckCode.SERVER_HOST_IDENTITY,
                    passed = true,
                    detail = "forged incomplete evidence",
                ),
            ),
            status = SiteRemotePreflightStatus.READY,
            preflightSha256 = "",
        ).let { it.copy(preflightSha256 = SiteRemotePreflightDigest.reportSha256(it)) }

        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteTransportBoundary.authorize(fixture.plan, incomplete, SiteRemoteTransportTestFixtures.fullCapabilities())
        }
    }

    @Test
    fun `missing capability and undersized limits block authorization`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8123L, SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE)
        val full = SiteRemoteTransportTestFixtures.fullCapabilities()
        val missingRollback = full.copy(
            capabilities = full.capabilities.filterNot { it == SiteRemoteTransportCapability.ROLLBACK_RENAME },
        )
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, missingRollback)
        }

        val tooSmall = full.copy(maxFiles = fixture.plan.fileCount - 1)
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, tooSmall)
        }
    }

    @Test
    fun `tampered authorization and unsafe cleanup are rejected`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8124L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val authorization = SiteRemoteTransportBoundary.authorize(
            fixture.plan,
            fixture.preflight,
            SiteRemoteTransportTestFixtures.fullCapabilities(),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteTransportPolicy.validateAuthorization(authorization.copy(totalBytes = authorization.totalBytes + 1))
        }
        val unsafe = authorization.copy(
            rollbackOperations = listOf(
                SiteRemoteTransportOperation.RemoveTransactionTree(
                    path = fixture.plan.publish.targetRoot,
                    transactionOwnedOnly = false,
                ),
            ),
            authorizationSha256 = "",
        ).let { it.copy(authorizationSha256 = SiteRemoteTransportDigest.authorizationSha256(it)) }
        assertThrows(IllegalArgumentException::class.java) {
            SiteRemoteTransportPolicy.validateAuthorization(unsafe)
        }
    }
}
