package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.site.*
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionReadinessStatus
import java.nio.file.Path
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_24RealDeviceTransportAcquisitionReadinessGateAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun productionTransportAcquisitionReadinessIsExactFreshAndStillNonExecuting() {
        val fixture = fixture()
        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val first = application.siteProductionDeploymentTransportAcquisitionReadiness(
            composition = fixture.composition,
            executionAuthorization = fixture.executionAuthorization,
            executionRequest = fixture.executionRequest,
            runtimeMutationPermit = fixture.runtimeMutationPermit,
            runtimeMutationRequest = fixture.runtimeMutationRequest,
            evaluatedAtEpochMillis = fixture.gateEvaluatedAt,
        )
        val second = application.siteProductionDeploymentTransportAcquisitionReadiness(
            composition = fixture.composition,
            executionAuthorization = fixture.executionAuthorization,
            executionRequest = fixture.executionRequest,
            runtimeMutationPermit = fixture.runtimeMutationPermit,
            runtimeMutationRequest = fixture.runtimeMutationRequest,
            evaluatedAtEpochMillis = fixture.gateEvaluatedAt,
        )
        val after = application.siteProductionDeploymentReplayFence.snapshot()

        SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate.validate(first)
        assertEquals(first, second)
        assertEquals(SiteProductionDeploymentTransportAcquisitionReadinessStatus.READY_FOR_SEPARATE_TRANSPORT_ACQUISITION, first.status)
        assertTrue(first.blockers.isEmpty())
        assertTrue(first.readinessOnly)
        assertFalse(first.productionTransportEnabled)
        assertFalse(first.authorizesTransport)
        assertFalse(first.resolvesCredentials)
        assertFalse(first.acquiresSshSession)
        assertFalse(first.opensSftpChannel)
        assertFalse(first.invokesCoordinator)
        assertFalse(first.exposesDeployUiAction)
        assertFalse(first.realVpsAccessAllowed)
        assertTrue(first.requiresSeparateTransportAcquisitionAuthorization)
        assertTrue(first.requiresDurableReplayConsumptionBeforeCoordinatorInvocation)
        assertEquals(SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId, first.boundedSftpImplementationId)
        assertEquals(
            SiteRemoteTransportPolicy.capabilityProfileSha256(SiteRemoteSftpPrimitiveFactory.CAPABILITIES),
            first.boundedSftpCapabilityProfileSha256,
        )
        assertEquals(fixture.composition.descriptorSha256, first.compositionDescriptorSha256)
        assertEquals(fixture.executionAuthorization.executionAuthorizationSha256, first.executionAuthorizationSha256)
        assertEquals(fixture.runtimeMutationPermit.permitSha256, first.runtimeMutationPermitSha256)
        assertEquals(fixture.runtimeMutationPermit.candidateTransportAuthorizationSha256, first.candidateTransportAuthorizationSha256)
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertEquals(before.coordinatorInvocationAuthorizationMarkerCount, after.coordinatorInvocationAuthorizationMarkerCount)
        assertFalse(first.toString().contains(fixture.secretId.value))

        val expired = application.siteProductionDeploymentTransportAcquisitionReadiness(
            composition = fixture.composition,
            executionAuthorization = fixture.executionAuthorization,
            executionRequest = fixture.executionRequest,
            runtimeMutationPermit = fixture.runtimeMutationPermit,
            runtimeMutationRequest = fixture.runtimeMutationRequest,
            evaluatedAtEpochMillis = fixture.runtimeMutationPermit.permitExpiresAtEpochMillis + 1L,
        )
        assertEquals(SiteProductionDeploymentTransportAcquisitionReadinessStatus.BLOCKED, expired.status)
        assertTrue(expired.blockers.any { it.code == "RUNTIME_MUTATION_PERMIT_EXPIRED" })
        assertFalse(expired.authorizesTransport)
        assertFalse(expired.acquiresSshSession)
        assertFalse(expired.realVpsAccessAllowed)

        val changedComposition = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = fixture.serverAccess,
            runtimeSessionId = "phase11_24_runtime_0002",
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentTransportAcquisitionReadiness(
                composition = changedComposition,
                executionAuthorization = fixture.executionAuthorization,
                executionRequest = fixture.executionRequest,
                runtimeMutationPermit = fixture.runtimeMutationPermit,
                runtimeMutationRequest = fixture.runtimeMutationRequest,
                evaluatedAtEpochMillis = fixture.gateEvaluatedAt,
            )
        }
    }

    private data class Fixture(
        val secretId: SecretId,
        val serverAccess: ServerAccess,
        val composition: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCompositionDescriptor,
        val executionRequest: SiteProductionDeploymentExecutionRequest,
        val executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
        val runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
        val runtimeMutationPermit: SiteProductionDeploymentRuntimeMutationPermit,
        val gateEvaluatedAt: Long,
    )

    private fun fixture(): Fixture {
        val rawHostKey = "phase11.24-host-key".encodeToByteArray()
        val canonicalHostKey = CanonicalHostKeyFingerprint.fromRawHostKey(rawHostKey)
        val trustedKey = canonicalHostKey.asHexSha256()
        val secretId = SecretId("phase11_24_secret_ref_must_not_leak")
        val host = "203.0.113.24"
        val serverAccess = ServerAccess(
            id = ServerAccessId("phase11_24_access"),
            serverId = ServerId("phase11_24_server"),
            endpoint = SshEndpoint(host = host, port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = canonicalHostKey.asModel(),
        )
        val composition = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = serverAccess,
            runtimeSessionId = "phase11_24_runtime_0001",
        )

        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(124L)),
                siteName = "Velum Transport Acquisition Gate",
                tagline = "Fresh exact evidence without transport",
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
            outputPath = Path.of("phase11_24_verified_export"),
            fileCount = exportPlan.manifest.fileCount,
            totalBytes = exportPlan.manifest.totalBytes,
            sourceTreeSha256 = exportPlan.manifest.sourceTreeSha256,
            planSha256 = exportPlan.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val domain = "site.example.com"
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = host,
            targetRoot = "/srv/www/site",
            owner = "www_data",
            group = "www_data",
            certificateReuse = SiteCertificateReuseRequest(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requestedDomain = domain,
            ),
        )
        val plan = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, remoteRequest)
        val observedAt = 1_800_000_000_000L
        val readinessEvaluatedAt = observedAt + 30_000L
        val remoteObservation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(host, trustedKey),
            target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
            backup = null,
            availableBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(plan) + 4096L,
            ownership = SiteRemoteOwnershipObservation(true, true, true, true),
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
            serviceBindingIntent = SiteProductionServiceBindingIntent(domain, 443),
            serviceBindingObservation = SiteProductionServiceBindingObservation(
                remoteHostIdentity = host,
                serverKeySha256 = trustedKey,
                domain = domain,
                port = 443,
                configured = true,
                observedAtEpochMillis = observedAt,
            ),
            freshnessPolicy = SiteProductionObservationFreshnessPolicy(readinessEvaluatedAt, 300_000L),
        )
        val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(readinessRequest)
        val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            readinessDraft,
            SiteProductionOperatorApproval(readinessDraft.operatorApprovalChallengeSha256, true),
        )
        val executionEvaluatedAt = readinessEvaluatedAt + 1_000L
        val executionRequest = SiteProductionDeploymentExecutionRequest(
            readyRecord = readyRecord,
            readinessRequest = readinessRequest,
            coordinatorRequest = SiteDeploymentCoordinatorRequest(
                exportPlan = exportPlan,
                localOutputRoot = Path.of("phase11_24_coordinator_output"),
                remoteRequest = remoteRequest,
                trust = readinessRequest.trust,
            ),
            transportCapabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
            executionAttemptId = "phase11_24_attempt_0001",
            evaluatedAtEpochMillis = executionEvaluatedAt,
        )
        val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
        val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
            executionDraft,
            SiteProductionDeploymentExecutionApproval(executionDraft.executionApprovalChallengeSha256, true),
        )
        val runtimeEvaluatedAt = executionEvaluatedAt + 1_000L
        val runtimeMutationRequest = SiteProductionDeploymentRuntimeMutationRequest(
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeIdentity = composition.runtimeIdentity,
            coordinatorInvocationId = "phase11_24_invocation_0001",
            evaluatedAtEpochMillis = runtimeEvaluatedAt,
            requestedPermitLifetimeMillis = 60_000L,
        )
        val runtimeDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(runtimeMutationRequest)
        val runtimePermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            runtimeDraft,
            SiteProductionDeploymentRuntimeMutationApproval(runtimeDraft.runtimeMutationApprovalChallengeSha256, true),
        )
        return Fixture(
            secretId = secretId,
            serverAccess = serverAccess,
            composition = composition,
            executionRequest = executionRequest,
            executionAuthorization = executionAuthorization,
            runtimeMutationRequest = runtimeMutationRequest,
            runtimeMutationPermit = runtimePermit,
            gateEvaluatedAt = runtimeEvaluatedAt + 1_000L,
        )
    }
}
