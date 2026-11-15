package com.velumtegra.xuimobile.core.site

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDeployerReviewBoundaryTest {
    @Test
    fun `same request produces byte stable review identity`() {
        val first = SiteDeployerReviewBoundary.prepare(baseRequest())
        val second = SiteDeployerReviewBoundary.prepare(baseRequest())

        assertEquals(first, second)
        assertEquals(first.reviewSha256, second.reviewSha256)
        assertEquals(first.preview.treeSha256, second.preview.treeSha256)
        assertEquals(first.exportManifest.planSha256, second.exportManifest.planSha256)
    }

    @Test
    fun `review exposes selected identity theme endpoint and never enables real server mutation`() {
        val state = SiteDeployerReviewBoundary.prepare(
            baseRequest().copy(
                siteName = "Velum Nova",
                tagline = "Deterministic review boundary",
                themeFamily = ThemeFamily.WARM_AMBER,
                backgroundFamily = BackgroundFamily.TECH_GRID,
                typographyProfile = TypographyProfile.SYSTEM_TECH,
                componentStyle = ComponentStyle.OUTLINED,
                domain = "Example.COM",
                servicePort = 8443,
            ),
        )

        assertEquals("Velum Nova", state.design.siteName)
        assertEquals(ThemeFamily.WARM_AMBER, state.design.themeFamily)
        assertEquals(BackgroundFamily.TECH_GRID, state.design.backgroundFamily)
        assertEquals(TypographyProfile.SYSTEM_TECH, state.design.typographyProfile)
        assertEquals(ComponentStyle.OUTLINED, state.design.componentStyle)
        assertEquals("example.com", state.serviceBinding.domain)
        assertEquals(8443, state.serviceBinding.port)
        assertFalse(state.serviceBinding.appliedByCurrentDeployContract)
        assertFalse(state.realServerMutationEnabled)
        assertTrue(state.fixtureDeploymentOnly)
        assertEquals(SiteDeployerExecutionMode.DRY_RUN_ONLY, state.executionMode)
        assertEquals(SiteDeployerPreflightState.NOT_OBSERVED, state.preflight.state)
        assertFalse(state.preflight.authorizesTransport)
        assertEquals(state.preview.fileCount, state.exportManifest.fileCount)
    }

    @Test
    fun `ready observation exposes target and certificate reuse readiness without authorization`() {
        val request = baseRequest().copy(reuseExisting3xUiCertificate = true)
        val draft = SiteDeployerReviewBoundary.prepare(request)
        val observation = readyObservation(draft, includeCertificate = true)

        val state = SiteDeployerReviewBoundary.prepare(request.copy(observation = observation))

        assertEquals(SiteDeployerPreflightState.READY, state.preflight.state)
        assertEquals(SiteDeployerReadiness.READY, state.remoteTarget.readiness)
        assertEquals(SiteDeployerReadiness.READY, state.certificate.readiness)
        assertEquals("site.example.com", state.certificate.domain)
        assertEquals(SitePrivateKeyHandling.REMAIN_ON_SERVER, state.certificate.privateKeyHandling)
        assertTrue(state.preflightBlockers.isEmpty())
        assertFalse(state.preflight.authorizesTransport)
    }

    @Test
    fun `blocked observation surfaces exact failed preflight checks`() {
        val request = baseRequest().copy(reuseExisting3xUiCertificate = true)
        val draft = SiteDeployerReviewBoundary.prepare(request)
        val bad = readyObservation(draft, includeCertificate = true).copy(
            target = SiteRemoteObservedPath(draft.remoteTarget.targetRoot, SiteRemoteObservedPathType.FILE, 10),
            availableBytes = 0,
            certificate = SiteRemoteCertificateObservation(
                serverKeySha256 = request.trustedServerKeySha256,
                dnsNames = listOf("other.example.com"),
                certificateSha256 = "b".repeat(64),
                usableNow = false,
                privateKeyPresentOnServer = true,
            ),
        )

        val state = SiteDeployerReviewBoundary.prepare(request.copy(observation = bad))
        val codes = state.preflightBlockers.map { it.code }.toSet()

        assertEquals(SiteDeployerPreflightState.BLOCKED, state.preflight.state)
        assertEquals(SiteDeployerReadiness.BLOCKED, state.remoteTarget.readiness)
        assertEquals(SiteDeployerReadiness.BLOCKED, state.certificate.readiness)
        assertTrue(SiteRemotePreflightCheckCode.TARGET_STATE in codes)
        assertTrue(SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY in codes)
        assertTrue(SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN in codes)
        assertTrue(SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW in codes)
        assertFalse(state.preflight.authorizesTransport)
    }

    @Test
    fun `dry run check semantics match authoritative preflight when verified local export exists`() {
        val request = baseRequest().copy(
            exportFormat = SiteExportFormat.DIRECTORY,
            reuseExisting3xUiCertificate = true,
        )
        val draft = SiteDeployerReviewBoundary.prepare(request)
        val observation = readyObservation(draft, includeCertificate = true)
        val review = SiteDeployerReviewBoundary.prepare(request.copy(observation = observation))

        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(request.rootSeed),
                siteName = request.siteName,
                tagline = request.tagline,
                themeFamily = request.themeFamily,
                backgroundFamily = request.backgroundFamily,
                typographyProfile = request.typographyProfile,
                componentStyle = request.componentStyle,
            ),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design))
        val previewExport = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(request.exportFormat, request.requestedOutputBaseName),
        )
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = previewExport.export.manifest.outputName,
            outputPath = Path.of("review-fixture"),
            fileCount = previewExport.export.manifest.fileCount,
            totalBytes = previewExport.export.manifest.totalBytes,
            sourceTreeSha256 = previewExport.export.manifest.sourceTreeSha256,
            planSha256 = previewExport.export.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = request.remoteHostIdentity,
            targetRoot = request.targetRoot,
            owner = request.owner,
            group = request.group,
            existingTargetPolicy = request.existingTargetPolicy,
            certificateReuse = SiteCertificateReuseRequest(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requestedDomain = review.serviceBinding.domain,
            ),
        )
        val plan = SiteRemoteDeployBoundary.prepare(previewExport.export, receipt, remoteRequest)
        val authoritative = SiteRemoteDeployPreflight.evaluate(
            plan,
            SiteRemotePreflightTrust(request.trustedServerKeySha256),
            observation,
        )

        assertEquals(authoritative.requiredAvailableBytes, review.preflight.requiredAvailableBytes)
        assertEquals(authoritative.checks, review.preflight.checks)
        assertEquals(SiteRemotePreflightStatus.READY, authoritative.status)
        assertEquals(SiteDeployerPreflightState.READY, review.preflight.state)
        assertFalse(review.preflight.authorizesTransport)
    }

    private fun baseRequest() = SiteDeployerReviewRequest(
        rootSeed = DesignSeed(113L),
        domain = "site.example.com",
        servicePort = 443,
        remoteHostIdentity = "fixture.example",
        targetRoot = "/srv/www/site",
        owner = "www_data",
        group = "www_data",
        trustedServerKeySha256 = "a".repeat(64),
    )

    private fun readyObservation(
        state: SiteDeployerReviewState,
        includeCertificate: Boolean,
    ): SiteRemotePreflightObservation = SiteRemotePreflightObservation(
        server = SiteRemoteServerObservation(
            remoteHostIdentity = state.remoteTarget.remoteHostIdentity,
            serverKeySha256 = "a".repeat(64),
        ),
        target = SiteRemoteObservedPath(
            path = state.remoteTarget.targetRoot,
            type = when (state.remoteTarget.existingTargetPolicy) {
                SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> SiteRemoteObservedPathType.ABSENT
                SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> SiteRemoteObservedPathType.DIRECTORY
            },
        ),
        staging = SiteRemoteObservedPath(
            path = state.remoteTarget.stagingRoot,
            type = SiteRemoteObservedPathType.ABSENT,
        ),
        backup = state.remoteTarget.backupRoot?.let {
            SiteRemoteObservedPath(path = it, type = SiteRemoteObservedPathType.ABSENT)
        },
        availableBytes = state.preflight.requiredAvailableBytes + 4096,
        ownership = SiteRemoteOwnershipObservation(
            ownerExists = true,
            groupExists = true,
            ownershipChangeApplicable = true,
            modeChangeApplicable = true,
        ),
        certificate = if (includeCertificate) {
            SiteRemoteCertificateObservation(
                serverKeySha256 = "a".repeat(64),
                dnsNames = listOf(state.serviceBinding.domain),
                certificateSha256 = "b".repeat(64),
                usableNow = true,
                privateKeyPresentOnServer = true,
            )
        } else {
            null
        },
    )
}
