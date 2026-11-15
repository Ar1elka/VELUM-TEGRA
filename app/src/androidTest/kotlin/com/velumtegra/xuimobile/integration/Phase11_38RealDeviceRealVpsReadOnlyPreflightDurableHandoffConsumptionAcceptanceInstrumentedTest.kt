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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_38RealDeviceRealVpsReadOnlyPreflightDurableHandoffConsumptionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_37AuthorizationIsDurablyConsumedOnceWithoutNetworkAccess() {
        val nonce = requiredRunNonce()
        val secretId = SecretId("phase11_38_secret_ref_must_not_leak_$nonce")
        val access = ServerAccess(
            id = ServerAccessId("phase11_38_access_$nonce"),
            serverId = ServerId("phase11_38_server_$nonce"),
            endpoint = SshEndpoint(host = "203.0.113.38", port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.38-candidate-host-key-$nonce".encodeToByteArray())
                .asModel(),
        )
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("index.html", "assets"),
            admissionAttemptId = "phase11_38_admission_$nonce",
            evaluatedAtEpochMillis = 38_000L,
        )
        val draft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_38_authorization_$nonce",
            evaluatedAtEpochMillis = 38_100L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        val authorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            draft = draft,
            approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                approvalChallengeSha256 = draft.approvalChallengeSha256,
                confirmed = true,
            ),
        )

        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val consumedAt = authorization.evaluatedAtEpochMillis + 1L
        val receipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            authorization = authorization,
            consumedAtEpochMillis = consumedAt,
        )
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary
            .validateReceipt(receipt)

        assertEquals(
            SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_AND_TRANSPORT_BOUNDARIES,
            receipt.status,
        )
        assertTrue(receipt.singleUseConsumed)
        assertFalse(receipt.productionNetworkTouched)
        assertFalse(receipt.credentialLeaseMaterialRead)
        assertFalse(receipt.hostKeyPinVerifiedAgainstRemote)
        assertFalse(receipt.authorizesNetworkAccess)
        assertFalse(receipt.authorizesCredentialResolution)
        assertFalse(receipt.authorizesSshSessionAcquisition)
        assertFalse(receipt.authorizesSftpChannelOpen)
        assertFalse(receipt.authorizesReadOnlyPreflightExecution)
        assertFalse(receipt.authorizesMutation)
        assertFalse(receipt.authorizesCoordinatorInvocation)
        assertFalse(receipt.exposesDeployUiAction)
        assertFalse(receipt.realVpsAccessAllowed)
        assertTrue(receipt.requiresLiveRemoteHostKeyVerification)
        assertTrue(receipt.requiresSeparateCredentialResolutionBoundary)
        assertTrue(receipt.requiresSeparateSshSessionAcquisitionBoundary)
        assertTrue(receipt.requiresSeparateSftpChannelOpenBoundary)
        assertTrue(receipt.requiresSeparateReadOnlyExecutionBoundary)
        assertTrue(receipt.requiresSeparateMutationBoundary)
        assertEquals(authorization.authorizationSha256, receipt.authorizationSha256)
        assertEquals(authorization.admissionSha256, receipt.admissionSha256)
        assertEquals(authorization.serverAccessBindingSha256, receipt.serverAccessBindingSha256)
        assertEquals(authorization.requestSha256, receipt.requestSha256)
        assertEquals(authorization.capabilityProfileSha256, receipt.capabilityProfileSha256)
        assertFalse(receipt.toString().contains(secretId.value))

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            before.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount + 1,
            after.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
        )
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertEquals(
            before.coordinatorInvocationAuthorizationMarkerCount,
            after.coordinatorInvocationAuthorizationMarkerCount,
        )
        assertEquals(
            before.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount,
            after.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )

        val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructed.realVpsReadOnlyPreflightHandoffConsumptionPort()
                .consumeOnce(authorization.authorizationSha256),
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
                authorization = authorization,
                consumedAtEpochMillis = consumedAt + 1L,
            )
        }

        val finalSnapshot = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            after.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
            finalSnapshot.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
        )
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_38_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_38_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
