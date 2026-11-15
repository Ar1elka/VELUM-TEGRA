package com.velumtegra.xuimobile.core.site

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentReadinessBoundaryTest {
    @Test
    fun `ready evidence produces approval challenge without transport authorization`() {
        val fixture = fixture(reuseCertificate = true)

        val draft = SiteProductionDeploymentReadinessBoundary.prepare(fixture.request)

        assertEquals(SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL, draft.status)
        assertEquals(SiteRemotePreflightStatus.READY, draft.preflight.status)
        assertTrue(draft.blockers.isEmpty())
        assertTrue(draft.serviceBindingChecks.all { it.passed })
        assertEquals(fixture.exportPlan.manifest, draft.exportManifest)
        assertFalse(draft.realServerMutationEnabled)
        assertFalse(draft.authorizesTransport)
        assertTrue(draft.requiresSeparateExecutionAuthorization)
    }

    @Test
    fun `exact operator approval yields ready record but still cannot mutate or authorize transport`() {
        val draft = SiteProductionDeploymentReadinessBoundary.prepare(fixture(reuseCertificate = true).request)

        val ready = SiteProductionDeploymentReadinessBoundary.approve(
            draft,
            SiteProductionOperatorApproval(
                operatorApprovalChallengeSha256 = draft.operatorApprovalChallengeSha256,
                confirmed = true,
            ),
        )

        assertEquals(SiteProductionDeploymentReadinessStatus.READY_FOR_EXPLICIT_EXECUTION, ready.status)
        assertTrue(ready.operatorApproved)
        assertFalse(ready.realServerMutationEnabled)
        assertFalse(ready.authorizesTransport)
        assertTrue(ready.requiresSeparateExecutionAuthorization)
        assertEquals(draft.deploymentPlan.deploymentPlanSha256, ready.deploymentPlanSha256)
        assertEquals(draft.preflight.preflightSha256, ready.preflightSha256)
        assertEquals(draft.exportManifest.planSha256, ready.exportPlanSha256)
        assertEquals(draft.deploymentPlan.remoteHostIdentity, ready.remoteHostIdentity)
        assertEquals(draft.deploymentPlan.publish.targetRoot, ready.targetRoot)
        assertEquals(draft.deploymentPlan.publish.stagingRoot, ready.stagingRoot)
        assertEquals(draft.deploymentPlan.publish.backupRoot, ready.backupRoot)
        assertEquals("site.example.com", ready.serviceBindingDomain)
        assertEquals(443, ready.serviceBindingPort)
    }

    @Test
    fun `serving endpoint mismatch blocks approval even when remote deploy preflight is ready`() {
        val fixture = fixture(reuseCertificate = true)
        val badEndpoint = fixture.request.serviceBindingObservation.copy(port = 8443)

        val draft = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(serviceBindingObservation = badEndpoint),
        )

        assertEquals(SiteRemotePreflightStatus.READY, draft.preflight.status)
        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertTrue(
            draft.blockers.any {
                it.scope == "SERVICE_BINDING" && it.code == SiteProductionServiceBindingCheckCode.PORT.name
            },
        )
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentReadinessBoundary.approve(
                draft,
                SiteProductionOperatorApproval(draft.operatorApprovalChallengeSha256, confirmed = true),
            )
        }
    }

    @Test
    fun `remote preflight failure blocks production readiness`() {
        val fixture = fixture(reuseCertificate = false)
        val blockedRemote = fixture.request.remoteObservation.copy(availableBytes = 0L)

        val draft = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(remoteObservation = blockedRemote),
        )

        assertEquals(SiteRemotePreflightStatus.BLOCKED, draft.preflight.status)
        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertTrue(
            draft.blockers.any {
                it.scope == "REMOTE_PREFLIGHT" && it.code == SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY.name
            },
        )
        assertFalse(draft.authorizesTransport)
    }

    @Test
    fun `operator approval is cryptographically bound to exact evidence and cannot be replayed`() {
        val first = SiteProductionDeploymentReadinessBoundary.prepare(fixture(port = 443).request)
        val secondFixture = fixture(port = 8443)
        val second = SiteProductionDeploymentReadinessBoundary.prepare(secondFixture.request)

        assertNotEquals(first.operatorApprovalChallengeSha256, second.operatorApprovalChallengeSha256)
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentReadinessBoundary.approve(
                second,
                SiteProductionOperatorApproval(first.operatorApprovalChallengeSha256, confirmed = true),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentReadinessBoundary.approve(
                second,
                SiteProductionOperatorApproval(second.operatorApprovalChallengeSha256, confirmed = false),
            )
        }
    }

    @Test
    fun `stale remote observation blocks production readiness`() {
        val fixture = fixture()
        val stale = fixture.request.copy(
            remoteObservationObservedAtEpochMillis = fixture.request.freshnessPolicy.evaluatedAtEpochMillis -
                fixture.request.freshnessPolicy.maxAgeMillis - 1L,
        )

        val draft = SiteProductionDeploymentReadinessBoundary.prepare(stale)

        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertTrue(
            draft.blockers.any {
                it.scope == "EVIDENCE_FRESHNESS" && it.code == "REMOTE_OBSERVATION_STALE"
            },
        )
    }

    @Test
    fun `stale service binding observation blocks production readiness`() {
        val fixture = fixture()
        val stale = fixture.request.copy(
            serviceBindingObservation = fixture.request.serviceBindingObservation.copy(
                observedAtEpochMillis = fixture.request.freshnessPolicy.evaluatedAtEpochMillis -
                    fixture.request.freshnessPolicy.maxAgeMillis - 1L,
            ),
        )

        val draft = SiteProductionDeploymentReadinessBoundary.prepare(stale)

        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertTrue(
            draft.blockers.any {
                it.scope == "EVIDENCE_FRESHNESS" && it.code == "SERVICE_BINDING_OBSERVATION_STALE"
            },
        )
    }

    @Test
    fun `first publication mode accepts exact unconfigured endpoint and binds mode into ready record`() {
        val fixture = fixture()
        val request = fixture.request.copy(
            serviceBindingObservation = fixture.request.serviceBindingObservation.copy(configured = false),
            serviceBindingReadinessMode =
                SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
        )

        val draft = SiteProductionDeploymentReadinessBoundary.prepare(request)

        assertEquals(SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL, draft.status)
        assertEquals(
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            draft.serviceBindingReadinessMode,
        )
        assertTrue(
            draft.serviceBindingChecks.single { it.code == SiteProductionServiceBindingCheckCode.CONFIGURED }.passed,
        )

        val ready = SiteProductionDeploymentReadinessBoundary.approve(
            draft,
            SiteProductionOperatorApproval(draft.operatorApprovalChallengeSha256, confirmed = true),
        )

        assertEquals(
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            ready.serviceBindingReadinessMode,
        )
    }

    @Test
    fun `first publication mode blocks endpoint that is already configured`() {
        val fixture = fixture()
        val draft = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(
                serviceBindingReadinessMode =
                    SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            ),
        )

        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertTrue(
            draft.blockers.any {
                it.scope == "SERVICE_BINDING" && it.code == SiteProductionServiceBindingCheckCode.CONFIGURED.name
            },
        )
    }

    @Test
    fun `legacy readiness mode still blocks endpoint that is not configured`() {
        val fixture = fixture()
        val draft = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(
                serviceBindingObservation = fixture.request.serviceBindingObservation.copy(configured = false),
            ),
        )

        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertEquals(
            SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
            draft.serviceBindingReadinessMode,
        )
        assertTrue(
            draft.blockers.any {
                it.scope == "SERVICE_BINDING" && it.code == SiteProductionServiceBindingCheckCode.CONFIGURED.name
            },
        )
    }

    @Test
    fun `operator challenge is explicitly bound to service binding readiness mode`() {
        val fixture = fixture()
        val legacy = SiteProductionDeploymentReadinessBoundary.prepare(fixture.request)
        val firstPublication = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(
                serviceBindingReadinessMode =
                    SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            ),
        )

        assertEquals(legacy.serviceBindingObservationSha256, firstPublication.serviceBindingObservationSha256)
        assertNotEquals(legacy.operatorApprovalChallengeSha256, firstPublication.operatorApprovalChallengeSha256)
    }

    @Test
    fun `certificate reuse domain must exactly match production service binding intent`() {
        val fixture = fixture(reuseCertificate = true)
        val mismatched = fixture.request.remoteRequest.copy(
            certificateReuse = SiteCertificateReuseRequest(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requestedDomain = "other.example.com",
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentReadinessBoundary.prepare(
                fixture.request.copy(remoteRequest = mismatched),
            )
        }
    }

    private data class Fixture(
        val exportPlan: SiteExportPlan,
        val request: SiteProductionDeploymentReadinessRequest,
    )

    private fun fixture(
        domain: String = "site.example.com",
        port: Int = 443,
        reuseCertificate: Boolean = false,
    ): Fixture {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(116L)),
                siteName = "Velum Production Gate",
                tagline = "Readiness without mutation",
            ),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design))
        val previewExport = SitePreviewExportBoundary.prepare(
            bundle = bundle,
            request = SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        )
        val exportPlan = previewExport.export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = exportPlan.manifest.outputName,
            outputPath = Path.of("phase11_16_verified_export"),
            fileCount = exportPlan.manifest.fileCount,
            totalBytes = exportPlan.manifest.totalBytes,
            sourceTreeSha256 = exportPlan.manifest.sourceTreeSha256,
            planSha256 = exportPlan.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = "fixture.example",
            targetRoot = "/srv/www/site",
            owner = "www_data",
            group = "www_data",
            certificateReuse = if (reuseCertificate) {
                SiteCertificateReuseRequest(
                    mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                    requestedDomain = domain,
                )
            } else {
                SiteCertificateReuseRequest()
            },
        )
        val plan = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, remoteRequest)
        val requiredBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(plan)
        val trustedKey = "a".repeat(64)
        val remoteObservation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                serverKeySha256 = trustedKey,
            ),
            target = SiteRemoteObservedPath(
                path = plan.publish.targetRoot,
                type = SiteRemoteObservedPathType.ABSENT,
            ),
            staging = SiteRemoteObservedPath(
                path = plan.publish.stagingRoot,
                type = SiteRemoteObservedPathType.ABSENT,
            ),
            backup = null,
            availableBytes = requiredBytes + 4096L,
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = true,
                groupExists = true,
                ownershipChangeApplicable = true,
                modeChangeApplicable = true,
            ),
            certificate = if (reuseCertificate) {
                SiteRemoteCertificateObservation(
                    serverKeySha256 = trustedKey,
                    dnsNames = listOf(domain.lowercase()),
                    certificateSha256 = "b".repeat(64),
                    usableNow = true,
                    privateKeyPresentOnServer = true,
                )
            } else {
                null
            },
        )
        val evaluatedAtEpochMillis = 1_800_000_000_000L
        val observedAtEpochMillis = evaluatedAtEpochMillis - 30_000L
        val request = SiteProductionDeploymentReadinessRequest(
            exportPlan = exportPlan,
            localReceipt = receipt,
            remoteRequest = remoteRequest,
            trust = SiteRemotePreflightTrust(trustedKey),
            remoteObservation = remoteObservation,
            remoteObservationObservedAtEpochMillis = observedAtEpochMillis,
            serviceBindingIntent = SiteProductionServiceBindingIntent(domain = domain, port = port),
            serviceBindingObservation = SiteProductionServiceBindingObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                serverKeySha256 = trustedKey,
                domain = domain,
                port = port,
                configured = true,
                observedAtEpochMillis = observedAtEpochMillis,
            ),
            freshnessPolicy = SiteProductionObservationFreshnessPolicy(
                evaluatedAtEpochMillis = evaluatedAtEpochMillis,
                maxAgeMillis = 300_000L,
            ),
        )
        return Fixture(exportPlan = exportPlan, request = request)
    }
}
