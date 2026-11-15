package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SiteDeploymentCoordinatorTest {
    @Test
    fun `happy path composes export preflight authorization and committed transport`() {
        val fixture = fixture()
        val states = mutableListOf<SiteDeploymentCoordinatorState>()
        val runtime = FakeRuntime(fixture.readyObservation)

        val result = runSuspend {
            SiteDeploymentCoordinator.deploy(
                request = fixture.request,
                runtime = runtime,
                stateSink = SiteDeploymentStateSink { states += it.state },
            )
        }

        assertTrue(result is SiteDeploymentCoordinatorResult.Committed)
        val committed = result as SiteDeploymentCoordinatorResult.Committed
        assertTrue(committed.receipt.verified)
        assertEquals(SiteRemotePreflightStatus.READY, committed.preflight.status)
        assertEquals(SiteRemoteTransportOutcome.COMMITTED, committed.transport.outcome)
        assertEquals(committed.authorization.authorizationSha256, runtime.authorizationSeen)
        assertEquals(fixture.plan.entries.map { it.path }.sorted(), runtime.sourcePaths.sorted())
        assertEquals(
            listOf(
                SiteDeploymentCoordinatorState.STARTED,
                SiteDeploymentCoordinatorState.EXPORTING,
                SiteDeploymentCoordinatorState.EXPORTED,
                SiteDeploymentCoordinatorState.PLAN_PREPARED,
                SiteDeploymentCoordinatorState.PREFLIGHTING,
                SiteDeploymentCoordinatorState.PREFLIGHT_READY,
                SiteDeploymentCoordinatorState.AUTHORIZING,
                SiteDeploymentCoordinatorState.AUTHORIZED,
                SiteDeploymentCoordinatorState.DEPLOYING,
                SiteDeploymentCoordinatorState.COMMITTED,
            ),
            states,
        )
    }

    @Test
    fun `blocked preflight returns typed blocked result without opening transport`() {
        val fixture = fixture()
        val runtime = FakeRuntime(
            fixture.readyObservation.copy(availableBytes = 0),
        )

        val result = runSuspend { SiteDeploymentCoordinator.deploy(fixture.request, runtime) }

        assertTrue(result is SiteDeploymentCoordinatorResult.Blocked)
        assertFalse(runtime.executeCalled)
    }

    @Test
    fun `cancellation after authorization is honored before any remote mutation`() {
        val fixture = fixture()
        val runtime = FakeRuntime(fixture.readyObservation)
        var checks = 0
        val cancellation = SiteDeploymentCancellationSignal {
            checks += 1
            checks >= 5
        }

        val result = runSuspend {
            SiteDeploymentCoordinator.deploy(fixture.request, runtime, cancellation)
        }

        assertTrue(result is SiteDeploymentCoordinatorResult.Cancelled)
        result as SiteDeploymentCoordinatorResult.Cancelled
        assertEquals(SiteDeploymentCoordinatorStage.TRANSPORT, result.beforeStage)
        assertFalse(runtime.executeCalled)
        assertTrue(result.authorization != null)
    }

    @Test
    fun `proven transport rollback maps to typed rolled back result`() {
        val fixture = fixture()
        val runtime = FakeRuntime(fixture.readyObservation, rollBack = true)

        val result = runSuspend { SiteDeploymentCoordinator.deploy(fixture.request, runtime) }

        assertTrue(result is SiteDeploymentCoordinatorResult.RolledBack)
        result as SiteDeploymentCoordinatorResult.RolledBack
        assertTrue(result.transport.rollbackPerformed)
        assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.transport.outcome)
    }

    @Test
    fun `transport failure preserves cause and reports exact stage`() {
        val fixture = fixture()
        val runtime = FakeRuntime(fixture.readyObservation, failExecute = true)

        try {
            runSuspend { SiteDeploymentCoordinator.deploy(fixture.request, runtime) }
            fail("Expected coordinator failure")
        } catch (error: SiteDeploymentCoordinatorException) {
            assertEquals(SiteDeploymentCoordinatorStage.TRANSPORT, error.stage)
            assertTrue(error.cause is IllegalStateException)
            assertEquals("transport-boom", error.cause?.message)
        }
    }

    private data class Fixture(
        val plan: SiteExportPlan,
        val request: SiteDeploymentCoordinatorRequest,
        val readyObservation: SiteRemotePreflightObservation,
    )

    private fun fixture(): Fixture {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(
                design = SiteDesignGenerator.generate(
                    SiteDesignRequest(
                        seeds = SiteDesignSeeds.fromRoot(DesignSeed(1212L)),
                        siteName = "Coordinator Fixture",
                    ),
                ),
            ),
        )
        val plan = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY, requestedBaseName = "coordinator-fixture"),
        ).export
        val remote = SiteRemoteDeployRequest(
            remoteHostIdentity = "fixture.invalid",
            targetRoot = "/srv/www/coordinator-fixture",
            owner = "www-data",
            group = "www-data",
        )
        val staging = SiteRemoteDeployPolicy.buildStagingRoot(remote.targetRoot, plan.manifest.sourceTreeSha256)
        val trust = SiteRemotePreflightTrust("a".repeat(64))
        val observation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(remote.remoteHostIdentity, trust.expectedServerKeySha256),
            target = SiteRemoteObservedPath(remote.targetRoot, SiteRemoteObservedPathType.ABSENT),
            staging = SiteRemoteObservedPath(staging, SiteRemoteObservedPathType.ABSENT),
            backup = null,
            availableBytes = SiteBuildPolicy.MAX_TOTAL_BYTES.toLong() * 4,
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = true,
                groupExists = true,
                ownershipChangeApplicable = true,
                modeChangeApplicable = true,
            ),
        )
        return Fixture(
            plan = plan,
            request = SiteDeploymentCoordinatorRequest(
                exportPlan = plan,
                localOutputRoot = Files.createTempDirectory("phase1112-coordinator-"),
                remoteRequest = remote,
                trust = trust,
            ),
            readyObservation = observation,
        )
    }

    private class FakeRuntime(
        private val observation: SiteRemotePreflightObservation,
        private val rollBack: Boolean = false,
        private val failExecute: Boolean = false,
    ) : SiteDeploymentRemoteRuntime {
        override val capabilities: SiteRemoteTransportCapabilities = SiteRemoteTransportCapabilities(
            implementationId = "phase1112-fake",
            capabilities = SiteRemoteTransportCapability.entries.sortedBy { it.name },
            maxFiles = SiteBuildPolicy.MAX_DOCUMENTS,
            maxTotalBytes = SiteBuildPolicy.MAX_TOTAL_BYTES,
            maxSingleFileBytes = SiteBuildPolicy.MAX_DOCUMENT_BYTES,
            maxRemotePathLength = 1024,
        )
        var executeCalled = false
        var authorizationSeen: String? = null
        val sourcePaths = mutableListOf<String>()

        override suspend fun observe(plan: SiteRemoteDeployPlan): SiteRemotePreflightObservation = observation

        override suspend fun execute(
            authorization: SiteRemoteTransportAuthorization,
            source: SiteRemoteTransportSource,
        ): SiteRemoteTransportResult {
            executeCalled = true
            authorizationSeen = authorization.authorizationSha256
            if (failExecute) error("transport-boom")
            var bytes = 0L
            authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.UploadFile>().forEach { upload ->
                val payload = source.read(upload.relativePath)
                sourcePaths += upload.relativePath
                assertEquals(upload.byteSize, payload.size)
                assertEquals(upload.sha256, SiteBundleDigest.sha256(payload))
                bytes += payload.size
            }
            return if (rollBack) {
                SiteRemoteTransportResult(
                    authorizationSha256 = authorization.authorizationSha256,
                    outcome = SiteRemoteTransportOutcome.ROLLED_BACK,
                    uploadedFileCount = authorization.fileCount,
                    uploadedBytes = bytes,
                    publishedTreeSha256 = null,
                    rollbackPerformed = true,
                )
            } else {
                SiteRemoteTransportResult(
                    authorizationSha256 = authorization.authorizationSha256,
                    outcome = SiteRemoteTransportOutcome.COMMITTED,
                    uploadedFileCount = authorization.fileCount,
                    uploadedBytes = bytes,
                    publishedTreeSha256 = authorization.sourceTreeSha256,
                    rollbackPerformed = false,
                )
            }.also { SiteRemoteTransportPolicy.validateResult(authorization, it) }
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
        return requireNotNull(completed) { "Test suspend block unexpectedly suspended" }.getOrThrow()
    }
}
