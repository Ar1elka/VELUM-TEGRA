package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentFixtureCoordinatorInvocationBridgeTest {
    @Test
    fun `fixture bridge invokes coordinator exactly once with exact approved evidence and zero real VPS access`() {
        val fixture = fixture()
        val runtime = FakeFixtureRuntime(fixture)
        val replayRoot = Files.createTempDirectory("phase11-21-handoff-fence-").toFile()
        val usePort = SiteProductionDeploymentDurableReplayFence.open(replayRoot)
            .coordinatorInvocationUsePort()

        val receipt = runSuspend {
            SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                request = fixture.bridgeRequest,
                runtime = runtime,
                invocationUsePort = usePort,
            )
        }

        assertTrue(receipt.coordinatorResult is SiteDeploymentCoordinatorResult.Committed)
        assertTrue(receipt.fixtureOnly)
        assertFalse(receipt.productionTransportEnabled)
        assertFalse(receipt.realVpsAccessAllowed)
        assertEquals(1, runtime.executeCalls)
        assertEquals(
            fixture.executionAuthorization.candidateTransportAuthorizationSha256,
            runtime.transportAuthorizationSha256,
        )
        assertThrows(IllegalArgumentException::class.java) {
            runSuspend {
                SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                    request = fixture.bridgeRequest,
                    runtime = runtime,
                    invocationUsePort = SiteProductionDeploymentDurableReplayFence.open(replayRoot)
                        .coordinatorInvocationUsePort(),
                )
            }
        }
        assertEquals(1, runtime.executeCalls)
    }

    @Test
    fun `bridge rejects any runtime that allows production transport or real VPS access`() {
        val fixture = fixture()
        val runtime = FakeFixtureRuntime(fixture, productionTransportEnabled = true)
        assertThrows(IllegalArgumentException::class.java) {
            runSuspend {
                SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                    request = fixture.bridgeRequest,
                    runtime = runtime,
                    invocationUsePort = SiteProductionDeploymentCoordinatorInvocationUsePort { true },
                )
            }
        }
        assertEquals(0, runtime.executeCalls)

        val realVpsRuntime = FakeFixtureRuntime(fixture, realVpsAccessAllowed = true)
        assertThrows(IllegalArgumentException::class.java) {
            runSuspend {
                SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                    request = fixture.bridgeRequest,
                    runtime = realVpsRuntime,
                    invocationUsePort = SiteProductionDeploymentCoordinatorInvocationUsePort { true },
                )
            }
        }
        assertEquals(0, realVpsRuntime.executeCalls)
    }

    @Test
    fun `changed runtime identity is rejected before coordinator handoff`() {
        val fixture = fixture()
        val runtime = FakeFixtureRuntime(
            fixture = fixture,
            runtimeIdentityOverride = fixture.runtimeRequest.runtimeIdentity.copy(runtimeSessionId = "phase11-20-runtime-other"),
        )
        assertThrows(IllegalArgumentException::class.java) {
            runSuspend {
                SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                    request = fixture.bridgeRequest,
                    runtime = runtime,
                    invocationUsePort = SiteProductionDeploymentCoordinatorInvocationUsePort { true },
                )
            }
        }
        assertEquals(0, runtime.executeCalls)
    }

    @Test
    fun `changed fixture observation is rejected before transport execute`() {
        val fixture = fixture()
        val runtime = FakeFixtureRuntime(
            fixture = fixture,
            observationOverride = fixture.readinessRequest.remoteObservation.copy(
                availableBytes = fixture.readinessRequest.remoteObservation.availableBytes + 1L,
            ),
        )
        assertThrows(SiteDeploymentCoordinatorException::class.java) {
            runSuspend {
                SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                    request = fixture.bridgeRequest,
                    runtime = runtime,
                    invocationUsePort = SiteProductionDeploymentCoordinatorInvocationUsePort { true },
                )
            }
        }
        assertEquals(0, runtime.executeCalls)
    }

    @Test
    fun `expired invocation authorization is rejected before handoff fence consumption`() {
        val fixture = fixture()
        var consumeCalls = 0
        val expired = fixture.bridgeRequest.copy(
            invokedAtEpochMillis = fixture.invocationAuthorization.permitExpiresAtEpochMillis + 1L,
        )
        assertThrows(IllegalArgumentException::class.java) {
            runSuspend {
                SiteProductionDeploymentFixtureCoordinatorInvocationBridge.invoke(
                    request = expired,
                    runtime = FakeFixtureRuntime(fixture),
                    invocationUsePort = SiteProductionDeploymentCoordinatorInvocationUsePort {
                        consumeCalls += 1
                        true
                    },
                )
            }
        }
        assertEquals(0, consumeCalls)
    }

    private data class Fixture(
        val readinessRequest: SiteProductionDeploymentReadinessRequest,
        val executionRequest: SiteProductionDeploymentExecutionRequest,
        val executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
        val runtimeRequest: SiteProductionDeploymentRuntimeMutationRequest,
        val invocationAuthorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
        val bridgeRequest: SiteProductionDeploymentFixtureInvocationRequest,
    )

    private fun fixture(): Fixture {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(1120L)),
                siteName = "Phase 11.20 Fixture Bridge",
                tagline = "Fixture-only exact coordinator invocation",
            ),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design))
        val exportPlan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        ).export
        val localRoot = Files.createTempDirectory("phase11-20-export-")
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = exportPlan.manifest.outputName,
            outputPath = localRoot.resolve(exportPlan.manifest.outputName),
            fileCount = exportPlan.manifest.fileCount,
            totalBytes = exportPlan.manifest.totalBytes,
            sourceTreeSha256 = exportPlan.manifest.sourceTreeSha256,
            planSha256 = exportPlan.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val domain = "fixture.example.com"
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = "phase11-20.fixture.invalid",
            targetRoot = "/srv/www/phase11-20-fixture",
            owner = "www_data",
            group = "www_data",
            certificateReuse = SiteCertificateReuseRequest(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requestedDomain = domain,
            ),
        )
        val plan = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, remoteRequest)
        val trustedKey = "a".repeat(64)
        val observedAt = 1_900_000_000_000L
        val readinessEvaluatedAt = observedAt + 10_000L
        val observation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(plan.remoteHostIdentity, trustedKey),
            target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
            backup = null,
            availableBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(plan) + 4096L,
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
            remoteObservation = observation,
            remoteObservationObservedAtEpochMillis = observedAt,
            serviceBindingIntent = SiteProductionServiceBindingIntent(domain, 443),
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
        val capabilities = SiteRemoteTransportCapabilities(
            implementationId = "phase11_20_fixture_transport",
            capabilities = SiteRemoteTransportCapability.entries.sortedBy { it.name },
            maxFiles = SiteBuildPolicy.MAX_DOCUMENTS,
            maxTotalBytes = SiteBuildPolicy.MAX_TOTAL_BYTES,
            maxSingleFileBytes = SiteBuildPolicy.MAX_DOCUMENT_BYTES,
            maxRemotePathLength = 1024,
        )
        val coordinatorRequest = SiteDeploymentCoordinatorRequest(
            exportPlan = exportPlan,
            localOutputRoot = localRoot,
            remoteRequest = remoteRequest,
            trust = readinessRequest.trust,
        )
        val executionRequest = SiteProductionDeploymentExecutionRequest(
            readyRecord = readyRecord,
            readinessRequest = readinessRequest,
            coordinatorRequest = coordinatorRequest,
            transportCapabilities = capabilities,
            executionAttemptId = "phase11-20-execution-001",
            evaluatedAtEpochMillis = readinessEvaluatedAt + 1_000L,
        )
        val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
        val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
            executionDraft,
            SiteProductionDeploymentExecutionApproval(executionDraft.executionApprovalChallengeSha256, true),
        )
        val runtimeIdentity = SiteProductionDeploymentRuntimeIdentity(
            runtimeSessionId = "phase11-20-runtime-001",
            remoteHostIdentity = readyRecord.remoteHostIdentity,
            transportImplementationId = capabilities.implementationId,
            capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities),
        )
        val runtimeRequest = SiteProductionDeploymentRuntimeMutationRequest(
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeIdentity = runtimeIdentity,
            coordinatorInvocationId = "phase11-20-invoke-001",
            evaluatedAtEpochMillis = executionRequest.evaluatedAtEpochMillis + 1_000L,
            requestedPermitLifetimeMillis = 30_000L,
        )
        val mutationDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(runtimeRequest)
        val permit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            mutationDraft,
            SiteProductionDeploymentRuntimeMutationApproval(mutationDraft.runtimeMutationApprovalChallengeSha256, true),
        )
        val permitFenceRoot = Files.createTempDirectory("phase11-21-permit-fence-").toFile()
        val invocation = SiteProductionDeploymentRuntimeMutationBoundary.consumeForSingleCoordinatorInvocation(
            permit = permit,
            request = runtimeRequest,
            consumedAtEpochMillis = runtimeRequest.evaluatedAtEpochMillis + 1_000L,
            consumptionPort = SiteProductionDeploymentDurableReplayFence.open(permitFenceRoot)
                .runtimeMutationConsumptionPort(),
        )
        return Fixture(
            readinessRequest = readinessRequest,
            executionRequest = executionRequest,
            executionAuthorization = executionAuthorization,
            runtimeRequest = runtimeRequest,
            invocationAuthorization = invocation,
            bridgeRequest = SiteProductionDeploymentFixtureInvocationRequest(
                invocationAuthorization = invocation,
                runtimeMutationRequest = runtimeRequest,
                invokedAtEpochMillis = invocation.consumedAtEpochMillis + 1_000L,
            ),
        )
    }

    private class FakeFixtureRuntime(
        fixture: Fixture,
        productionTransportEnabled: Boolean = false,
        realVpsAccessAllowed: Boolean = false,
        runtimeIdentityOverride: SiteProductionDeploymentRuntimeIdentity? = null,
        private val observationOverride: SiteRemotePreflightObservation? = null,
    ) : SiteProductionDeploymentFixtureRuntime {
        override val capabilities: SiteRemoteTransportCapabilities = fixture.executionRequest.transportCapabilities
        override val fixtureBinding = SiteProductionDeploymentFixtureRuntimeBinding(
            fixtureId = "phase11-20-fixture-001",
            runtimeIdentity = runtimeIdentityOverride ?: fixture.runtimeRequest.runtimeIdentity,
            fixtureOnly = true,
            productionTransportEnabled = productionTransportEnabled,
            realVpsAccessAllowed = realVpsAccessAllowed,
        )
        private val approvedObservation = fixture.readinessRequest.remoteObservation
        var executeCalls: Int = 0
        var transportAuthorizationSha256: String? = null

        override suspend fun observe(plan: SiteRemoteDeployPlan): SiteRemotePreflightObservation =
            observationOverride ?: approvedObservation

        override suspend fun execute(
            authorization: SiteRemoteTransportAuthorization,
            source: SiteRemoteTransportSource,
        ): SiteRemoteTransportResult {
            executeCalls += 1
            transportAuthorizationSha256 = authorization.authorizationSha256
            var bytes = 0L
            authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.UploadFile>().forEach { upload ->
                val payload = source.read(upload.relativePath)
                assertEquals(upload.byteSize, payload.size)
                assertEquals(upload.sha256, SiteBundleDigest.sha256(payload))
                bytes += payload.size
            }
            return SiteRemoteTransportResult(
                authorizationSha256 = authorization.authorizationSha256,
                outcome = SiteRemoteTransportOutcome.COMMITTED,
                uploadedFileCount = authorization.fileCount,
                uploadedBytes = bytes,
                publishedTreeSha256 = authorization.sourceTreeSha256,
                rollbackPerformed = false,
            ).also { SiteRemoteTransportPolicy.validateResult(authorization, it) }
        }
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var completed: Result<T>? = null
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext
            override fun resumeWith(result: Result<T>) {
                completed = result
            }
        })
        return requireNotNull(completed).getOrThrow()
    }
}
