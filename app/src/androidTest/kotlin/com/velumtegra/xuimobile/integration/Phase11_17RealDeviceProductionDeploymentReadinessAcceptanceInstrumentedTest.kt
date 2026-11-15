package com.velumtegra.xuimobile.integration

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteBuildRequest
import com.velumtegra.xuimobile.core.site.SiteBuilder
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseRequest
import com.velumtegra.xuimobile.core.site.SiteDesignGenerator
import com.velumtegra.xuimobile.core.site.SiteDesignRequest
import com.velumtegra.xuimobile.core.site.SiteDesignSeeds
import com.velumtegra.xuimobile.core.site.SiteExportFormat
import com.velumtegra.xuimobile.core.site.SiteExportPlan
import com.velumtegra.xuimobile.core.site.SiteLocalExportReceipt
import com.velumtegra.xuimobile.core.site.SitePreviewExportBoundary
import com.velumtegra.xuimobile.core.site.SitePreviewExportRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessStatus
import com.velumtegra.xuimobile.core.site.SiteProductionObservationFreshnessPolicy
import com.velumtegra.xuimobile.core.site.SiteProductionOperatorApproval
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingIntent
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPath
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteOwnershipObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightCheckCode
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightStatus
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightTrust
import com.velumtegra.xuimobile.core.site.SiteRemoteServerObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteCertificateObservation
import com.velumtegra.xuimobile.core.site.ThemeFamily
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_17RealDeviceProductionDeploymentReadinessAcceptanceInstrumentedTest {
    @Test
    fun readinessApprovalIsDeterministicFreshBoundNonReplayableAndStillDryRunOnly() {
        val fixture = fixture(reuseCertificate = true)
        val first = SiteProductionDeploymentReadinessBoundary.prepare(fixture.request)
        val second = SiteProductionDeploymentReadinessBoundary.prepare(fixture.request)

        assertEquals(first, second)
        assertEquals(first.readinessSha256, second.readinessSha256)
        assertEquals(first.operatorApprovalChallengeSha256, second.operatorApprovalChallengeSha256)
        assertEquals(SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL, first.status)
        assertEquals(SiteRemotePreflightStatus.READY, first.preflight.status)
        assertTrue(first.blockers.isEmpty())
        assertTrue(first.serviceBindingChecks.all { it.passed })
        assertFalse(first.realServerMutationEnabled)
        assertFalse(first.authorizesTransport)
        assertTrue(first.requiresSeparateExecutionAuthorization)

        val ready = SiteProductionDeploymentReadinessBoundary.approve(
            first,
            SiteProductionOperatorApproval(
                operatorApprovalChallengeSha256 = first.operatorApprovalChallengeSha256,
                confirmed = true,
            ),
        )

        assertEquals(SiteProductionDeploymentReadinessStatus.READY_FOR_EXPLICIT_EXECUTION, ready.status)
        assertTrue(ready.operatorApproved)
        assertFalse(ready.realServerMutationEnabled)
        assertFalse(ready.authorizesTransport)
        assertTrue(ready.requiresSeparateExecutionAuthorization)
        assertEquals(first.deploymentPlan.deploymentPlanSha256, ready.deploymentPlanSha256)
        assertEquals(first.preflight.preflightSha256, ready.preflightSha256)
        assertEquals(first.exportManifest.planSha256, ready.exportPlanSha256)
        assertEquals(first.exportManifest.sourceTreeSha256, ready.sourceTreeSha256)
        assertEquals(first.deploymentPlan.remoteHostIdentity, ready.remoteHostIdentity)
        assertEquals(first.deploymentPlan.publish.targetRoot, ready.targetRoot)
        assertEquals(first.deploymentPlan.publish.stagingRoot, ready.stagingRoot)
        assertEquals(first.deploymentPlan.publish.backupRoot, ready.backupRoot)
        assertEquals(first.serviceBindingIntent.domain, ready.serviceBindingDomain)
        assertEquals(first.serviceBindingIntent.port, ready.serviceBindingPort)
        assertEquals(first.remoteObservationObservedAtEpochMillis, ready.remoteObservationObservedAtEpochMillis)
        assertEquals(first.serviceBindingObservedAtEpochMillis, ready.serviceBindingObservedAtEpochMillis)
        assertEquals(first.freshnessPolicy.evaluatedAtEpochMillis, ready.evaluatedAtEpochMillis)
        assertEquals(first.freshnessPolicy.maxAgeMillis, ready.maxObservationAgeMillis)
        assertTrue(ready.approvalRecordSha256.matches(Regex("^[0-9a-f]{64}$")))

        val changedExport = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture(seed = 117L, siteName = "Velum Changed Export", themeFamily = ThemeFamily.WARM_AMBER, reuseCertificate = true).request,
        )
        val changedDomain = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture(domain = "changed.example.com", reuseCertificate = true).request,
        )
        val changedPort = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture(port = 8443, reuseCertificate = true).request,
        )
        listOf(changedExport, changedDomain, changedPort).forEach { changed ->
            assertNotEquals(first.operatorApprovalChallengeSha256, changed.operatorApprovalChallengeSha256)
            assertIllegalArgument {
                SiteProductionDeploymentReadinessBoundary.approve(
                    changed,
                    SiteProductionOperatorApproval(first.operatorApprovalChallengeSha256, confirmed = true),
                )
            }
        }

        val staleRemote = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(
                remoteObservationObservedAtEpochMillis = fixture.request.freshnessPolicy.evaluatedAtEpochMillis -
                    fixture.request.freshnessPolicy.maxAgeMillis - 1L,
            ),
        )
        assertBlocked(staleRemote, "EVIDENCE_FRESHNESS", "REMOTE_OBSERVATION_STALE")

        val staleService = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(
                serviceBindingObservation = fixture.request.serviceBindingObservation.copy(
                    observedAtEpochMillis = fixture.request.freshnessPolicy.evaluatedAtEpochMillis -
                        fixture.request.freshnessPolicy.maxAgeMillis - 1L,
                ),
            ),
        )
        assertBlocked(staleService, "EVIDENCE_FRESHNESS", "SERVICE_BINDING_OBSERVATION_STALE")

        val noCertificate = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(remoteObservation = fixture.request.remoteObservation.copy(certificate = null)),
        )
        assertEquals(SiteRemotePreflightStatus.BLOCKED, noCertificate.preflight.status)
        assertBlocked(noCertificate, "REMOTE_PREFLIGHT", SiteRemotePreflightCheckCode.CERTIFICATE_PRESENT.name)

        val mismatchedService = SiteProductionDeploymentReadinessBoundary.prepare(
            fixture.request.copy(serviceBindingObservation = fixture.request.serviceBindingObservation.copy(port = 8443)),
        )
        assertEquals(SiteRemotePreflightStatus.READY, mismatchedService.preflight.status)
        assertBlocked(mismatchedService, "SERVICE_BINDING", "PORT")
    }

    private fun assertBlocked(
        draft: com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessDraft,
        scope: String,
        code: String,
    ) {
        assertEquals(SiteProductionDeploymentReadinessStatus.BLOCKED, draft.status)
        assertTrue(draft.blockers.any { it.scope == scope && it.code == code })
        assertFalse(draft.realServerMutationEnabled)
        assertFalse(draft.authorizesTransport)
        assertIllegalArgument {
            SiteProductionDeploymentReadinessBoundary.approve(
                draft,
                SiteProductionOperatorApproval(draft.operatorApprovalChallengeSha256, confirmed = true),
            )
        }
    }

    private fun assertIllegalArgument(block: () -> Unit) {
        var thrown = false
        try {
            block()
        } catch (_: IllegalArgumentException) {
            thrown = true
        }
        assertTrue("Expected IllegalArgumentException", thrown)
    }

    private data class Fixture(
        val exportPlan: SiteExportPlan,
        val request: SiteProductionDeploymentReadinessRequest,
    )

    private fun fixture(
        seed: Long = 116L,
        siteName: String = "Velum Production Gate",
        themeFamily: ThemeFamily? = null,
        domain: String = "site.example.com",
        port: Int = 443,
        reuseCertificate: Boolean = false,
    ): Fixture {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(seed)),
                siteName = siteName,
                tagline = "Real-device readiness acceptance",
                themeFamily = themeFamily,
            ),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design))
        val exportPlan = SitePreviewExportBoundary.prepare(
            bundle = bundle,
            request = SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        ).export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = exportPlan.manifest.outputName,
            outputPath = Path.of("phase11_17_verified_export"),
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
