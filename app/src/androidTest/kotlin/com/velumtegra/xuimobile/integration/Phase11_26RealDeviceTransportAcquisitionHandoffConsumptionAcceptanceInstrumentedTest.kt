package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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
class Phase11_26RealDeviceTransportAcquisitionHandoffConsumptionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun durableHandoffConsumptionIsOneShotPersistentAndStillNonExecuting() {
        val nonce = requiredRunNonce()
        val fixture = fixture()
        val request = SiteProductionDeploymentTransportAcquisitionAuthorizationRequest(
            readinessRequest = fixture.readinessRequest,
            readinessDescriptor = fixture.readinessDescriptor,
            authorizationAttemptId = "phase11_26_$nonce",
            evaluatedAtEpochMillis = fixture.authorizationEvaluatedAt,
            requestedAuthorizationLifetimeMillis = 30_000L,
        )
        val draft = application.siteProductionDeploymentTransportAcquisitionAuthorizationDraft(request)
        val authorization = application.siteProductionDeploymentTransportAcquisitionAuthorization(
            draft = draft,
            approval = SiteProductionDeploymentTransportAcquisitionApproval(
                approvalChallengeSha256 = draft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val consumedAt = authorization.evaluatedAtEpochMillis + 1L
        val receipt = application.siteProductionDeploymentConsumeTransportAcquisitionHandoff(
            authorization = authorization,
            consumedAtEpochMillis = consumedAt,
        )
        SiteProductionDeploymentAndroidTransportAcquisitionHandoffConsumptionBoundary.validateReceipt(receipt)

        assertEquals(
            SiteProductionDeploymentTransportAcquisitionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_ACQUISITION_BOUNDARY,
            receipt.status,
        )
        assertTrue(receipt.singleUseConsumed)
        assertFalse(receipt.productionTransportEnabled)
        assertFalse(receipt.authorizesTransport)
        assertFalse(receipt.authorizesTransportAcquisitionExecution)
        assertFalse(receipt.authorizesCredentialResolution)
        assertFalse(receipt.authorizesSshSessionAcquisition)
        assertFalse(receipt.authorizesSftpChannelOpen)
        assertFalse(receipt.authorizesCoordinatorInvocation)
        assertFalse(receipt.exposesDeployUiAction)
        assertFalse(receipt.realVpsAccessAllowed)
        assertTrue(receipt.requiresSeparateAcquisitionExecutionBoundary)
        assertEquals(authorization.authorizationSha256, receipt.authorizationSha256)
        assertEquals(authorization.readinessSha256, receipt.readinessSha256)
        assertFalse(receipt.toString().contains(fixture.secretId.value))

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertEquals(
            before.coordinatorInvocationAuthorizationMarkerCount,
            after.coordinatorInvocationAuthorizationMarkerCount,
        )
        assertEquals(
            before.transportAcquisitionHandoffAuthorizationMarkerCount + 1,
            after.transportAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )

        val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructed.transportAcquisitionHandoffConsumptionPort()
                .consumeOnce(authorization.authorizationSha256),
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeTransportAcquisitionHandoff(
                authorization = authorization,
                consumedAtEpochMillis = consumedAt + 1L,
            )
        }
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString(ARG_RUN_NONCE)
            ?.trim()
            ?.lowercase()
            ?: throw AssertionError("Missing $ARG_RUN_NONCE instrumentation argument")
        require(RUN_NONCE.matches(nonce)) {
            "Phase 11.26 run nonce must be exactly 32 lowercase hex characters"
        }
        return nonce
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
    companion object {
        private const val ARG_RUN_NONCE = "phase11_26_run_nonce"
        private val RUN_NONCE = Regex("^[0-9a-f]{32}$")
    }
}
