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
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real-device proof that Phase 11.36 can freeze a candidate real-VPS read-only preflight binding
 * without touching the network or credential material and without authorizing any execution.
 */
@RunWith(AndroidJUnit4::class)
class Phase11_36RealDeviceRealVpsReadOnlyPreflightAdmissionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactCandidateBindingIsAdmittedForSeparateApprovalWithoutAnyNetworkExecution() {
        val secretId = SecretId("phase11_36_secret_ref_must_not_leak")
        val access = candidateAccess(secretId = secretId, host = "203.0.113.36")
        val before = application.siteProductionDeploymentReplayFence.snapshot()

        val first = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("index.html", "assets"),
            admissionAttemptId = "phase11_36_admission_0001",
            evaluatedAtEpochMillis = 36_000L,
        )
        val second = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("assets", "index.html"),
            admissionAttemptId = "phase11_36_admission_0001",
            evaluatedAtEpochMillis = 36_000L,
        )
        val after = application.siteProductionDeploymentReplayFence.snapshot()

        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary.validate(first)
        assertEquals(first, second)
        assertEquals(
            SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
                .ADMITTED_FOR_SEPARATE_EXPLICIT_READ_ONLY_PREFLIGHT_AUTHORIZATION,
            first.status,
        )
        assertTrue(first.admissionOnly)
        assertTrue(first.candidateEndpointIsNonLoopback)
        assertTrue(first.requiresExplicitSeparateAuthorization)
        assertTrue(first.requiresLiveRemoteHostKeyVerification)
        assertTrue(first.requiresSeparateCredentialResolutionBoundary)
        assertTrue(first.requiresSeparateSshSessionAcquisitionBoundary)
        assertTrue(first.requiresSeparateSftpChannelOpenBoundary)
        assertTrue(first.requiresSeparateReadOnlyExecutionBoundary)
        assertTrue(first.requiresSeparateMutationBoundary)
        assertFalse(first.productionNetworkTouched)
        assertFalse(first.credentialLeaseMaterialRead)
        assertFalse(first.hostKeyPinVerifiedAgainstRemote)
        assertFalse(first.authorizesNetworkAccess)
        assertFalse(first.authorizesCredentialResolution)
        assertFalse(first.authorizesSshSessionAcquisition)
        assertFalse(first.authorizesSftpChannelOpen)
        assertFalse(first.authorizesReadOnlyPreflightExecution)
        assertFalse(first.authorizesMutation)
        assertFalse(first.authorizesCoordinatorInvocation)
        assertFalse(first.exposesDeployUiAction)
        assertFalse(first.realVpsAccessAllowed)
        assertEquals(access.id.value, first.serverAccessId)
        assertEquals(access.serverId.value, first.serverId)
        assertEquals(access.endpoint.host, first.remoteHostIdentity)
        assertEquals(access.endpoint.port, first.remotePort)
        assertEquals(access.username, first.sshUsername)
        assertEquals(listOf("assets", "index.html"), first.expectedTargetEntryNames)
        assertEquals(
            SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                .EXACT_READ_ONLY_OPERATION_VOCABULARY,
            first.approvedReadOnlyOperationVocabulary,
        )
        assertEquals(SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES, first.maxTargetEntries)
        assertEquals(SiteRemoteSftpReadOnlyPreflightProbe::class.java.name, first.sftpReadOnlyProbeImplementation)
        assertEquals(before, after)
        assertFalse("Raw SecretId leaked into admission", first.toString().contains(secretId.value))

        val changedRoot = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site2",
            stagingRoot = "/srv/velum/site2-stage",
            backupRoot = "/srv/velum/site2-backup",
            expectedTargetEntryNames = listOf("assets", "index.html"),
            admissionAttemptId = "phase11_36_admission_0001",
            evaluatedAtEpochMillis = 36_000L,
        )
        assertNotEquals(first.requestSha256, changedRoot.requestSha256)
        assertNotEquals(first.admissionSha256, changedRoot.admissionSha256)

        val loopback = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = candidateAccess(secretId = secretId, host = "127.0.0.1"),
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("assets", "index.html"),
            admissionAttemptId = "phase11_36_admission_loopback",
            evaluatedAtEpochMillis = 36_000L,
        )
        assertEquals(SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus.BLOCKED, loopback.status)
        assertFalse(loopback.candidateEndpointIsNonLoopback)
        assertFalse(loopback.realVpsAccessAllowed)
        assertFalse(loopback.authorizesNetworkAccess)
    }

    private fun candidateAccess(secretId: SecretId, host: String): ServerAccess =
        ServerAccess(
            id = ServerAccessId("phase11_36_access"),
            serverId = ServerId("phase11_36_server"),
            endpoint = SshEndpoint(host = host, port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.36-candidate-host-key".encodeToByteArray())
                .asModel(),
        )
}
