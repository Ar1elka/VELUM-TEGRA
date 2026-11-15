package com.velumtegra.xuimobile.core.site

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentExecutionBoundaryTest {
    @Test
    fun `exact approved readiness can prepare execution draft but still cannot mutate`() {
        val fixture = fixture()

        val draft = SiteProductionDeploymentExecutionBoundary.prepare(fixture.executionRequest)

        assertEquals(SiteProductionDeploymentExecutionStatus.AWAITING_EXECUTION_APPROVAL, draft.status)
        assertTrue(draft.blockers.isEmpty())
        assertFalse(draft.realServerMutationEnabled)
        assertFalse(draft.authorizesTransport)
        assertFalse(draft.authorizesCoordinatorHandoff)
        assertTrue(draft.requiresRuntimeMutationEnablement)
        assertEquals(fixture.readyRecord.approvalRecordSha256, draft.readyRecordSha256)
        assertEquals(fixture.readyRecord.deploymentPlanSha256, draft.deploymentPlanSha256)
        assertEquals(fixture.readyRecord.preflightSha256, draft.preflightSha256)
    }

    @Test
    fun `explicit execution approval authorizes only exact coordinator handoff`() {
        val fixture = fixture()
        val draft = SiteProductionDeploymentExecutionBoundary.prepare(fixture.executionRequest)

        val authorization = SiteProductionDeploymentExecutionBoundary.authorize(
            draft,
            SiteProductionDeploymentExecutionApproval(
                executionApprovalChallengeSha256 = draft.executionApprovalChallengeSha256,
                confirmed = true,
            ),
        )

        assertEquals(
            SiteProductionDeploymentExecutionStatus.AUTHORIZED_FOR_COORDINATOR_HANDOFF,
            authorization.status,
        )
        assertTrue(authorization.authorizesCoordinatorHandoff)
        assertFalse(authorization.authorizesTransport)
        assertFalse(authorization.realServerMutationEnabled)
        assertTrue(authorization.requiresRuntimeMutationEnablement)
        SiteProductionDeploymentExecutionBoundary.validateForCoordinatorHandoff(
            authorization,
            fixture.executionRequest,
        )
    }

    @Test
    fun `ready record cannot be paired with changed approved inputs`() {
        val fixture = fixture()
        val changedReadiness = fixture.executionRequest.readinessRequest.copy(
            serviceBindingIntent = fixture.executionRequest.readinessRequest.serviceBindingIntent.copy(port = 8443),
            serviceBindingObservation = fixture.executionRequest.readinessRequest.serviceBindingObservation.copy(port = 8443),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentExecutionBoundary.prepare(
                fixture.executionRequest.copy(readinessRequest = changedReadiness),
            )
        }
    }

    @Test
    fun `coordinator request must exactly match approved export remote request and trust`() {
        val fixture = fixture()
        val changedCoordinator = fixture.executionRequest.coordinatorRequest.copy(
            remoteRequest = fixture.executionRequest.coordinatorRequest.remoteRequest.copy(
                targetRoot = "/srv/www/other-site",
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentExecutionBoundary.prepare(
                fixture.executionRequest.copy(coordinatorRequest = changedCoordinator),
            )
        }
    }

    @Test
    fun `execution evaluation after evidence expiry is blocked`() {
        val fixture = fixture()
        val expiredAt = minOf(
            fixture.readyRecord.remoteObservationObservedAtEpochMillis + fixture.readyRecord.maxObservationAgeMillis,
            fixture.readyRecord.serviceBindingObservedAtEpochMillis + fixture.readyRecord.maxObservationAgeMillis,
        ) + 1L

        val draft = SiteProductionDeploymentExecutionBoundary.prepare(
            fixture.executionRequest.copy(evaluatedAtEpochMillis = expiredAt),
        )

        assertEquals(SiteProductionDeploymentExecutionStatus.BLOCKED, draft.status)
        assertTrue(draft.blockers.any { it.code == "READINESS_EVIDENCE_STALE" })
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentExecutionBoundary.authorize(
                draft,
                SiteProductionDeploymentExecutionApproval(draft.executionApprovalChallengeSha256, confirmed = true),
            )
        }
    }

    @Test
    fun `execution approval cannot replay across attempt identity or capability change`() {
        val first = fixture(executionAttemptId = "phase11-18-attempt-a")
        val firstDraft = SiteProductionDeploymentExecutionBoundary.prepare(first.executionRequest)
        val firstApproval = SiteProductionDeploymentExecutionApproval(
            firstDraft.executionApprovalChallengeSha256,
            confirmed = true,
        )
        val second = fixture(executionAttemptId = "phase11-18-attempt-b")
        val secondDraft = SiteProductionDeploymentExecutionBoundary.prepare(second.executionRequest)

        assertNotEquals(firstDraft.executionApprovalChallengeSha256, secondDraft.executionApprovalChallengeSha256)
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentExecutionBoundary.authorize(secondDraft, firstApproval)
        }

        val changedCapabilities = second.executionRequest.transportCapabilities.copy(
            maxRemotePathLength = second.executionRequest.transportCapabilities.maxRemotePathLength + 1,
        )
        val changedDraft = SiteProductionDeploymentExecutionBoundary.prepare(
            second.executionRequest.copy(transportCapabilities = changedCapabilities),
        )
        assertNotEquals(secondDraft.capabilityProfileSha256, changedDraft.capabilityProfileSha256)
        assertNotEquals(secondDraft.executionApprovalChallengeSha256, changedDraft.executionApprovalChallengeSha256)
    }

    @Test
    fun `authorization becomes invalid if exact coordinator handoff inputs change`() {
        val fixture = fixture()
        val draft = SiteProductionDeploymentExecutionBoundary.prepare(fixture.executionRequest)
        val authorization = SiteProductionDeploymentExecutionBoundary.authorize(
            draft,
            SiteProductionDeploymentExecutionApproval(draft.executionApprovalChallengeSha256, confirmed = true),
        )
        val changedLocalRoot = fixture.executionRequest.copy(
            coordinatorRequest = fixture.executionRequest.coordinatorRequest.copy(
                localOutputRoot = Path.of("phase11_18_other_output"),
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentExecutionBoundary.validateForCoordinatorHandoff(
                authorization,
                changedLocalRoot,
            )
        }
    }

    @Test
    fun `same immutable inputs produce deterministic execution draft`() {
        val fixture = fixture()

        val first = SiteProductionDeploymentExecutionBoundary.prepare(fixture.executionRequest)
        val second = SiteProductionDeploymentExecutionBoundary.prepare(fixture.executionRequest)

        assertEquals(first.executionDraftSha256, second.executionDraftSha256)
        assertEquals(first.executionApprovalChallengeSha256, second.executionApprovalChallengeSha256)
        assertEquals(first.coordinatorRequestSha256, second.coordinatorRequestSha256)
        assertEquals(first.candidateTransportAuthorizationSha256, second.candidateTransportAuthorizationSha256)
    }

    private data class Fixture(
        val readyRecord: SiteProductionDeploymentReadyRecord,
        val executionRequest: SiteProductionDeploymentExecutionRequest,
    )

    private fun fixture(
        executionAttemptId: String = "phase11-18-attempt-001",
    ): Fixture {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(118L)),
                siteName = "Velum Production Execution Gate",
                tagline = "Exact handoff without mutation",
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
            outputPath = Path.of("phase11_18_verified_export"),
            fileCount = exportPlan.manifest.fileCount,
            totalBytes = exportPlan.manifest.totalBytes,
            sourceTreeSha256 = exportPlan.manifest.sourceTreeSha256,
            planSha256 = exportPlan.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val domain = "site.example.com"
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = "fixture.example",
            targetRoot = "/srv/www/site",
            owner = "www_data",
            group = "www_data",
            certificateReuse = SiteCertificateReuseRequest(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requestedDomain = domain,
            ),
        )
        val plan = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, remoteRequest)
        val trustedKey = "a".repeat(64)
        val requiredBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(plan)
        val observedAt = 1_800_000_000_000L
        val evaluatedAt = observedAt + 30_000L
        val remoteObservation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                serverKeySha256 = trustedKey,
            ),
            target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
            backup = null,
            availableBytes = requiredBytes + 4096L,
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = true,
                groupExists = true,
                ownershipChangeApplicable = true,
                modeChangeApplicable = true,
            ),
            certificate = SiteRemoteCertificateObservation(
                serverKeySha256 = trustedKey,
                dnsNames = listOf(domain),
                certificateSha256 = "b".repeat(64),
                usableNow = true,
                privateKeyPresentOnServer = true,
            ),
        )
        val readinessRequest = SiteProductionDeploymentReadinessRequest(
            exportPlan = exportPlan,
            localReceipt = receipt,
            remoteRequest = remoteRequest,
            trust = SiteRemotePreflightTrust(trustedKey),
            remoteObservation = remoteObservation,
            remoteObservationObservedAtEpochMillis = observedAt,
            serviceBindingIntent = SiteProductionServiceBindingIntent(domain = domain, port = 443),
            serviceBindingObservation = SiteProductionServiceBindingObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                serverKeySha256 = trustedKey,
                domain = domain,
                port = 443,
                configured = true,
                observedAtEpochMillis = observedAt,
            ),
            freshnessPolicy = SiteProductionObservationFreshnessPolicy(
                evaluatedAtEpochMillis = evaluatedAt,
                maxAgeMillis = 300_000L,
            ),
        )
        val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(readinessRequest)
        val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            readinessDraft,
            SiteProductionOperatorApproval(readinessDraft.operatorApprovalChallengeSha256, confirmed = true),
        )
        val coordinatorRequest = SiteDeploymentCoordinatorRequest(
            exportPlan = exportPlan,
            localOutputRoot = Path.of("phase11_18_coordinator_output"),
            remoteRequest = remoteRequest,
            trust = readinessRequest.trust,
        )
        val capabilities = SiteRemoteTransportCapabilities(
            implementationId = "phase11_18_fixture",
            capabilities = SiteRemoteTransportCapability.entries.sortedBy { it.name },
            maxFiles = SiteBuildPolicy.MAX_DOCUMENTS,
            maxTotalBytes = SiteBuildPolicy.MAX_TOTAL_BYTES,
            maxSingleFileBytes = SiteBuildPolicy.MAX_DOCUMENT_BYTES,
            maxRemotePathLength = 1024,
        )
        return Fixture(
            readyRecord = readyRecord,
            executionRequest = SiteProductionDeploymentExecutionRequest(
                readyRecord = readyRecord,
                readinessRequest = readinessRequest,
                coordinatorRequest = coordinatorRequest,
                transportCapabilities = capabilities,
                executionAttemptId = executionAttemptId,
                evaluatedAtEpochMillis = evaluatedAt + 1_000L,
            ),
        )
    }
}
