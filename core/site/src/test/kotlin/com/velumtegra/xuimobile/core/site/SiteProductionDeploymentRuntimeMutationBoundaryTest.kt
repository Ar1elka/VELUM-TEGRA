package com.velumtegra.xuimobile.core.site

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentRuntimeMutationBoundaryTest {
    @Test
    fun `exact execution authorization reaches approval draft but mutation stays disabled`() {
        val fixture = fixture()

        val draft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(fixture.runtimeRequest)

        assertEquals(
            SiteProductionDeploymentRuntimeMutationStatus.AWAITING_RUNTIME_MUTATION_APPROVAL,
            draft.status,
        )
        assertTrue(draft.blockers.isEmpty())
        assertFalse(draft.realServerMutationEnabled)
        assertFalse(draft.authorizesTransport)
        assertFalse(draft.authorizesCoordinatorInvocation)
        assertTrue(draft.requiresAtomicOneShotConsumption)
        assertEquals(fixture.executionAuthorization.executionAuthorizationSha256, draft.executionAuthorizationSha256)
    }

    @Test
    fun `explicit approval only issues non active one shot permit`() {
        val fixture = fixture()
        val draft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(fixture.runtimeRequest)

        val permit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            draft,
            SiteProductionDeploymentRuntimeMutationApproval(
                runtimeMutationApprovalChallengeSha256 = draft.runtimeMutationApprovalChallengeSha256,
                confirmed = true,
            ),
        )

        assertEquals(SiteProductionDeploymentRuntimeMutationStatus.RUNTIME_MUTATION_PERMIT_ISSUED, permit.status)
        assertFalse(permit.realServerMutationEnabled)
        assertFalse(permit.authorizesTransport)
        assertFalse(permit.authorizesCoordinatorInvocation)
        assertTrue(permit.requiresAtomicOneShotConsumption)
        assertTrue(permit.permitExpiresAtEpochMillis <= permit.readinessEvidenceExpiresAtEpochMillis)
    }

    @Test
    fun `atomic first consumption authorizes one exact coordinator invocation without direct transport authority`() {
        val fixture = fixture()
        val draft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(fixture.runtimeRequest)
        val permit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            draft,
            SiteProductionDeploymentRuntimeMutationApproval(draft.runtimeMutationApprovalChallengeSha256, true),
        )
        val consumed = mutableSetOf<String>()
        val replayFence = SiteProductionDeploymentRuntimeMutationConsumptionPort { consumed.add(it) }

        val invocation = SiteProductionDeploymentRuntimeMutationBoundary.consumeForSingleCoordinatorInvocation(
            permit = permit,
            request = fixture.runtimeRequest,
            consumedAtEpochMillis = fixture.runtimeRequest.evaluatedAtEpochMillis + 1_000L,
            consumptionPort = replayFence,
        )

        assertEquals(
            SiteProductionDeploymentRuntimeMutationStatus.AUTHORIZED_FOR_SINGLE_COORDINATOR_INVOCATION,
            invocation.status,
        )
        assertTrue(invocation.realServerMutationEnabled)
        assertTrue(invocation.authorizesCoordinatorInvocation)
        assertTrue(invocation.singleUseConsumed)
        assertFalse(invocation.authorizesTransport)
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentRuntimeMutationBoundary.consumeForSingleCoordinatorInvocation(
                permit = permit,
                request = fixture.runtimeRequest,
                consumedAtEpochMillis = fixture.runtimeRequest.evaluatedAtEpochMillis + 2_000L,
                consumptionPort = replayFence,
            )
        }
    }

    @Test
    fun `expired execution evidence blocks runtime mutation gate`() {
        val fixture = fixture()
        val expiredTime = fixture.executionAuthorization.evidenceExpiresAtEpochMillis + 1L

        val draft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(
            fixture.runtimeRequest.copy(evaluatedAtEpochMillis = expiredTime),
        )

        assertEquals(SiteProductionDeploymentRuntimeMutationStatus.BLOCKED, draft.status)
        assertTrue(draft.blockers.any { it.code == "EXECUTION_EVIDENCE_STALE" })
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentRuntimeMutationBoundary.authorize(
                draft,
                SiteProductionDeploymentRuntimeMutationApproval(draft.runtimeMutationApprovalChallengeSha256, true),
            )
        }
    }

    @Test
    fun `runtime identity must match approved host implementation and capability profile`() {
        val fixture = fixture()

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentRuntimeMutationBoundary.prepare(
                fixture.runtimeRequest.copy(
                    runtimeIdentity = fixture.runtimeRequest.runtimeIdentity.copy(remoteHostIdentity = "other.example"),
                ),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentRuntimeMutationBoundary.prepare(
                fixture.runtimeRequest.copy(
                    runtimeIdentity = fixture.runtimeRequest.runtimeIdentity.copy(
                        transportImplementationId = "different-runtime",
                    ),
                ),
            )
        }
    }

    @Test
    fun `approval cannot replay across runtime session or coordinator invocation identity`() {
        val first = fixture(runtimeSessionId = "phase11-19-runtime-a", coordinatorInvocationId = "phase11-19-invoke-a")
        val firstDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(first.runtimeRequest)
        val approval = SiteProductionDeploymentRuntimeMutationApproval(
            firstDraft.runtimeMutationApprovalChallengeSha256,
            true,
        )
        val second = fixture(runtimeSessionId = "phase11-19-runtime-b", coordinatorInvocationId = "phase11-19-invoke-b")
        val secondDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(second.runtimeRequest)

        assertNotEquals(firstDraft.runtimeIdentitySha256, secondDraft.runtimeIdentitySha256)
        assertNotEquals(firstDraft.runtimeMutationApprovalChallengeSha256, secondDraft.runtimeMutationApprovalChallengeSha256)
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentRuntimeMutationBoundary.authorize(secondDraft, approval)
        }
    }

    @Test
    fun `permit consumption fails closed after permit expiry`() {
        val fixture = fixture(permitLifetimeMillis = 5_000L)
        val draft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(fixture.runtimeRequest)
        val permit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            draft,
            SiteProductionDeploymentRuntimeMutationApproval(draft.runtimeMutationApprovalChallengeSha256, true),
        )

        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentRuntimeMutationBoundary.consumeForSingleCoordinatorInvocation(
                permit = permit,
                request = fixture.runtimeRequest,
                consumedAtEpochMillis = permit.permitExpiresAtEpochMillis + 1L,
                consumptionPort = SiteProductionDeploymentRuntimeMutationConsumptionPort { true },
            )
        }
    }

    @Test
    fun `same exact inputs produce deterministic runtime mutation challenge and permit`() {
        val fixture = fixture()
        val firstDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(fixture.runtimeRequest)
        val secondDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(fixture.runtimeRequest)
        val firstPermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            firstDraft,
            SiteProductionDeploymentRuntimeMutationApproval(firstDraft.runtimeMutationApprovalChallengeSha256, true),
        )
        val secondPermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            secondDraft,
            SiteProductionDeploymentRuntimeMutationApproval(secondDraft.runtimeMutationApprovalChallengeSha256, true),
        )

        assertEquals(firstDraft.runtimeMutationDraftSha256, secondDraft.runtimeMutationDraftSha256)
        assertEquals(firstDraft.runtimeMutationApprovalChallengeSha256, secondDraft.runtimeMutationApprovalChallengeSha256)
        assertEquals(firstPermit.permitSha256, secondPermit.permitSha256)
    }

    private data class Fixture(
        val executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
        val runtimeRequest: SiteProductionDeploymentRuntimeMutationRequest,
    )

    private fun fixture(
        runtimeSessionId: String = "phase11-19-runtime-001",
        coordinatorInvocationId: String = "phase11-19-invoke-001",
        permitLifetimeMillis: Long = 30_000L,
    ): Fixture {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(119L)),
                siteName = "Velum Runtime Mutation Gate",
                tagline = "Exact single-use production invocation",
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
            outputPath = Path.of("phase11_19_verified_export"),
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
        val readinessEvaluatedAt = observedAt + 30_000L
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
                evaluatedAtEpochMillis = readinessEvaluatedAt,
                maxAgeMillis = 300_000L,
            ),
        )
        val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(readinessRequest)
        val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            readinessDraft,
            SiteProductionOperatorApproval(readinessDraft.operatorApprovalChallengeSha256, true),
        )
        val coordinatorRequest = SiteDeploymentCoordinatorRequest(
            exportPlan = exportPlan,
            localOutputRoot = Path.of("phase11_19_coordinator_output"),
            remoteRequest = remoteRequest,
            trust = readinessRequest.trust,
        )
        val capabilities = SiteRemoteTransportCapabilities(
            implementationId = "phase11_19_fixture",
            capabilities = SiteRemoteTransportCapability.entries.sortedBy { it.name },
            maxFiles = SiteBuildPolicy.MAX_DOCUMENTS,
            maxTotalBytes = SiteBuildPolicy.MAX_TOTAL_BYTES,
            maxSingleFileBytes = SiteBuildPolicy.MAX_DOCUMENT_BYTES,
            maxRemotePathLength = 1024,
        )
        val executionRequest = SiteProductionDeploymentExecutionRequest(
            readyRecord = readyRecord,
            readinessRequest = readinessRequest,
            coordinatorRequest = coordinatorRequest,
            transportCapabilities = capabilities,
            executionAttemptId = "phase11-19-execution-001",
            evaluatedAtEpochMillis = readinessEvaluatedAt + 1_000L,
        )
        val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
        val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
            executionDraft,
            SiteProductionDeploymentExecutionApproval(executionDraft.executionApprovalChallengeSha256, true),
        )
        val runtimeIdentity = SiteProductionDeploymentRuntimeIdentity(
            runtimeSessionId = runtimeSessionId,
            remoteHostIdentity = readyRecord.remoteHostIdentity,
            transportImplementationId = capabilities.implementationId,
            capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities),
        )
        return Fixture(
            executionAuthorization = executionAuthorization,
            runtimeRequest = SiteProductionDeploymentRuntimeMutationRequest(
                executionAuthorization = executionAuthorization,
                executionRequest = executionRequest,
                runtimeIdentity = runtimeIdentity,
                coordinatorInvocationId = coordinatorInvocationId,
                evaluatedAtEpochMillis = executionRequest.evaluatedAtEpochMillis + 1_000L,
                requestedPermitLifetimeMillis = permitLifetimeMillis,
            ),
        )
    }
}
