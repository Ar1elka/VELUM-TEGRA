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
import com.velumtegra.xuimobile.sitedeployer.*
import java.nio.file.Path
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_25RealDeviceTransportAcquisitionAuthorizationBoundaryAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun transportAcquisitionAuthorizationIsExactShortLivedAndStillNonExecuting() {
        val fixture = fixture()
        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val request = SiteProductionDeploymentTransportAcquisitionAuthorizationRequest(
            readinessRequest = fixture.readinessRequest,
            readinessDescriptor = fixture.readinessDescriptor,
            authorizationAttemptId = "phase11_25_acquisition_0001",
            evaluatedAtEpochMillis = fixture.authorizationEvaluatedAt,
            requestedAuthorizationLifetimeMillis = 30_000L,
        )
        val firstDraft = application.siteProductionDeploymentTransportAcquisitionAuthorizationDraft(request)
        val secondDraft = application.siteProductionDeploymentTransportAcquisitionAuthorizationDraft(request)

        SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary.validateDraft(firstDraft)
        assertEquals(firstDraft, secondDraft)
        assertEquals(
            SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AWAITING_TRANSPORT_ACQUISITION_APPROVAL,
            firstDraft.status,
        )
        assertTrue(firstDraft.blockers.isEmpty())
        assertTrue(firstDraft.authorizationOnly)
        assertFalse(firstDraft.productionTransportEnabled)
        assertFalse(firstDraft.authorizesTransport)
        assertFalse(firstDraft.authorizesCredentialResolution)
        assertFalse(firstDraft.authorizesSshSessionAcquisition)
        assertFalse(firstDraft.authorizesSftpChannelOpen)
        assertFalse(firstDraft.authorizesCoordinatorInvocation)
        assertFalse(firstDraft.authorizesSingleTransportAcquisitionHandoff)
        assertFalse(firstDraft.exposesDeployUiAction)
        assertFalse(firstDraft.realVpsAccessAllowed)
        assertTrue(firstDraft.requiresExplicitApproval)
        assertTrue(firstDraft.requiresDurableOneShotConsumptionBeforeAcquisition)
        assertEquals(fixture.readinessDescriptor.readinessSha256, firstDraft.readinessSha256)
        assertEquals(
            SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId,
            firstDraft.boundedSftpImplementationId,
        )

        val authorization = application.siteProductionDeploymentTransportAcquisitionAuthorization(
            draft = firstDraft,
            approval = SiteProductionDeploymentTransportAcquisitionApproval(
                approvalChallengeSha256 = firstDraft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary.validateAuthorization(authorization)
        assertEquals(
            SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AUTHORIZED_FOR_SINGLE_TRANSPORT_ACQUISITION_HANDOFF,
            authorization.status,
        )
        assertTrue(authorization.authorizationOnly)
        assertFalse(authorization.productionTransportEnabled)
        assertFalse(authorization.authorizesTransport)
        assertFalse(authorization.authorizesCredentialResolution)
        assertFalse(authorization.authorizesSshSessionAcquisition)
        assertFalse(authorization.authorizesSftpChannelOpen)
        assertFalse(authorization.authorizesCoordinatorInvocation)
        assertTrue(authorization.authorizesSingleTransportAcquisitionHandoff)
        assertFalse(authorization.exposesDeployUiAction)
        assertFalse(authorization.realVpsAccessAllowed)
        assertTrue(authorization.requiresDurableOneShotConsumptionBeforeAcquisition)
        assertTrue(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis)
        assertTrue(
            authorization.authorizationExpiresAtEpochMillis <=
                fixture.runtimeMutationPermit.permitExpiresAtEpochMillis,
        )
        assertEquals(fixture.readinessDescriptor.readinessSha256, authorization.readinessSha256)
        assertEquals(
            fixture.readinessDescriptor.candidateTransportAuthorizationSha256,
            authorization.candidateTransportAuthorizationSha256,
        )

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertEquals(before.coordinatorInvocationAuthorizationMarkerCount, after.coordinatorInvocationAuthorizationMarkerCount)
        assertFalse(firstDraft.toString().contains(fixture.secretId.value))
        assertFalse(authorization.toString().contains(fixture.secretId.value))

        val staleRequest = request.copy(
            authorizationAttemptId = "phase11_25_acquisition_0002",
            evaluatedAtEpochMillis = fixture.runtimeMutationPermit.permitExpiresAtEpochMillis + 1L,
        )
        val staleDraft = application.siteProductionDeploymentTransportAcquisitionAuthorizationDraft(staleRequest)
        assertEquals(SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.BLOCKED, staleDraft.status)
        assertTrue(staleDraft.blockers.any { it.code == "TRANSPORT_ACQUISITION_EVIDENCE_STALE" })
        assertFalse(staleDraft.authorizesSingleTransportAcquisitionHandoff)

        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentTransportAcquisitionAuthorization(
                draft = firstDraft,
                approval = SiteProductionDeploymentTransportAcquisitionApproval(
                    approvalChallengeSha256 = "0".repeat(64),
                    confirmed = true,
                ),
            )
        }
    }

    private data class Fixture(
        val secretId: SecretId,
        val readinessRequest: SiteProductionDeploymentTransportAcquisitionReadinessRequest,
        val readinessDescriptor: SiteProductionDeploymentTransportAcquisitionReadinessDescriptor,
        val runtimeMutationPermit: SiteProductionDeploymentRuntimeMutationPermit,
        val authorizationEvaluatedAt: Long,
    )

    private fun fixture(): Fixture {
        val rawHostKey = "phase11.25-host-key".encodeToByteArray()
        val canonicalHostKey = CanonicalHostKeyFingerprint.fromRawHostKey(rawHostKey)
        val trustedKey = canonicalHostKey.asHexSha256()
        val secretId = SecretId("phase11_25_secret_ref_must_not_leak")
        val host = "203.0.113.25"
        val serverAccess = ServerAccess(
            id = ServerAccessId("phase11_25_access"),
            serverId = ServerId("phase11_25_server"),
            endpoint = SshEndpoint(host = host, port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = canonicalHostKey.asModel(),
        )
        val composition = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = serverAccess,
            runtimeSessionId = "phase11_25_runtime_0001",
        )

        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(125L)),
                siteName = "Velum Transport Acquisition Authorization",
                tagline = "Explicit handoff without transport acquisition",
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
            outputPath = Path.of("phase11_25_verified_export"),
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
        val observedAt = 1_800_000_100_000L
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
                certificateSha256 = "c".repeat(64),
                usableNow = true,
                privateKeyPresentOnServer = true,
            ),
        )
        val productionReadinessRequest = SiteProductionDeploymentReadinessRequest(
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
        val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(productionReadinessRequest)
        val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            readinessDraft,
            SiteProductionOperatorApproval(readinessDraft.operatorApprovalChallengeSha256, true),
        )
        val executionEvaluatedAt = readinessEvaluatedAt + 1_000L
        val executionRequest = SiteProductionDeploymentExecutionRequest(
            readyRecord = readyRecord,
            readinessRequest = productionReadinessRequest,
            coordinatorRequest = SiteDeploymentCoordinatorRequest(
                exportPlan = exportPlan,
                localOutputRoot = Path.of("phase11_25_coordinator_output"),
                remoteRequest = remoteRequest,
                trust = productionReadinessRequest.trust,
            ),
            transportCapabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
            executionAttemptId = "phase11_25_attempt_0001",
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
            coordinatorInvocationId = "phase11_25_invocation_0001",
            evaluatedAtEpochMillis = runtimeEvaluatedAt,
            requestedPermitLifetimeMillis = 60_000L,
        )
        val runtimeDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(runtimeMutationRequest)
        val runtimeMutationPermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            runtimeDraft,
            SiteProductionDeploymentRuntimeMutationApproval(runtimeDraft.runtimeMutationApprovalChallengeSha256, true),
        )
        val transportReadinessEvaluatedAt = runtimeEvaluatedAt + 1_000L
        val transportReadinessRequest = SiteProductionDeploymentTransportAcquisitionReadinessRequest(
            composition = composition,
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeMutationPermit = runtimeMutationPermit,
            runtimeMutationRequest = runtimeMutationRequest,
            evaluatedAtEpochMillis = transportReadinessEvaluatedAt,
        )
        val transportReadinessDescriptor = application.siteProductionDeploymentTransportAcquisitionReadiness(
            composition = composition,
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeMutationPermit = runtimeMutationPermit,
            runtimeMutationRequest = runtimeMutationRequest,
            evaluatedAtEpochMillis = transportReadinessEvaluatedAt,
        )
        return Fixture(
            secretId = secretId,
            readinessRequest = transportReadinessRequest,
            readinessDescriptor = transportReadinessDescriptor,
            runtimeMutationPermit = runtimeMutationPermit,
            authorizationEvaluatedAt = transportReadinessEvaluatedAt + 1_000L,
        )
    }
}
