package com.velumtegra.xuimobile.integration

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpChannelLifecycleProbe
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionStatus
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_46RealDeviceRealVpsSftpChannelOpenDurableHandoffConsumptionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_45SftpAuthorizationIsDurablyConsumedOnceWithoutNetworkOrCredentialRead() {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")

        val authorization = validPhase11_45Authorization(nonce)
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary
            .validateAuthorization(authorization)
        mark("STEP_02_AUTHORIZATION_VALIDATED")

        val before = application.siteProductionDeploymentReplayFence.snapshot()

        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeRealVpsSftpChannelOpenHandoff(
                authorization = authorization,
                consumedAtEpochMillis = authorization.authorizationExpiresAtEpochMillis + 1L,
            )
        }
        assertEquals(before, application.siteProductionDeploymentReplayFence.snapshot())
        mark("STEP_03_EXPIRED_CONSUMPTION_REJECTED_WITHOUT_MARKER")

        val consumedAt = authorization.evaluatedAtEpochMillis + 1L
        val receipt = application.siteProductionDeploymentConsumeRealVpsSftpChannelOpenHandoff(
            authorization = authorization,
            consumedAtEpochMillis = consumedAt,
        )
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary
            .validateReceipt(receipt)
        mark("STEP_04_HANDOFF_DURABLY_CONSUMED")

        assertEquals(
            SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_FRESH_CREDENTIAL_SSH_AND_SEPARATE_SFTP_EXECUTION_BOUNDARY,
            receipt.status,
        )
        assertTrue(receipt.singleUseConsumed)
        assertFalse(receipt.credentialLeaseMaterialRead)
        assertFalse(receipt.productionNetworkTouched)
        assertTrue(receipt.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        assertFalse(receipt.authorizesNetworkAccess)
        assertFalse(receipt.authorizesCredentialResolution)
        assertFalse(receipt.authorizesSshSessionAcquisition)
        assertFalse(receipt.authorizesSftpChannelOpen)
        assertFalse(receipt.authorizesReadOnlyPreflightExecution)
        assertFalse(receipt.authorizesMutation)
        assertFalse(receipt.authorizesCoordinatorInvocation)
        assertFalse(receipt.exposesDeployUiAction)
        assertFalse(receipt.realVpsAccessAllowed)
        assertTrue(receipt.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
        assertTrue(receipt.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
        assertTrue(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeSftpChannelOpenExecution)
        assertTrue(receipt.requiresSeparateSftpChannelOpenExecutionBoundary)
        assertTrue(receipt.requiresSeparateReadOnlyExecutionBoundary)
        assertTrue(receipt.requiresSeparateMutationBoundary)
        assertEquals(authorization.authorizationSha256, receipt.authorizationSha256)
        assertEquals(authorization.priorSshExecutionProofSha256, receipt.priorSshExecutionProofSha256)
        assertEquals(authorization.priorSshExecutionReceiptSha256, receipt.priorSshExecutionReceiptSha256)
        assertEquals(authorization.serverAccessBindingSha256, receipt.serverAccessBindingSha256)
        assertEquals(authorization.requestSha256, receipt.requestSha256)
        assertEquals(authorization.capabilityProfileSha256, receipt.capabilityProfileSha256)
        assertEquals(authorization.serverAccessId, receipt.serverAccessId)
        assertEquals(authorization.remoteHostIdentity, receipt.remoteHostIdentity)
        assertEquals(authorization.remotePort, receipt.remotePort)
        assertEquals(authorization.username, receipt.username)
        assertEquals(authorization.pinnedHostKeySha256, receipt.pinnedHostKeySha256)
        assertEquals(authorization.secretReferenceType, receipt.secretReferenceType)
        assertEquals(authorization.secretReferenceSha256, receipt.secretReferenceSha256)
        assertEquals(JschSshConnectionFactory::class.java.name, receipt.sshConnectionFactoryImplementation)
        assertEquals(ExactSessionRegistry::class.java.name, receipt.exactSessionRegistryImplementation)
        assertEquals(
            SiteRemoteSftpChannelLifecycleProbe::class.java.name,
            receipt.sftpLifecycleProbeImplementation,
        )

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            before.copy(
                realVpsSftpChannelOpenHandoffAuthorizationMarkerCount =
                    before.realVpsSftpChannelOpenHandoffAuthorizationMarkerCount + 1,
            ),
            after,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        mark("STEP_05_ONLY_NEW_REAL_VPS_SFTP_MARKER_CHANGED")

        val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructed.realVpsSftpChannelOpenHandoffConsumptionPort()
                .consumeOnce(authorization.authorizationSha256),
        )
        mark("STEP_06_RECONSTRUCTED_FENCE_REJECTED_REPLAY")

        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeRealVpsSftpChannelOpenHandoff(
                authorization = authorization,
                consumedAtEpochMillis = consumedAt + 1L,
            )
        }
        assertEquals(after, application.siteProductionDeploymentReplayFence.snapshot())
        mark("STEP_07_APP_LEVEL_REPLAY_REJECTED")

        assertFalse(receipt.toString().contains("credential material", ignoreCase = true))
        mark("STEP_08_TEST_BODY_COMPLETE")
    }

    private fun validPhase11_45Authorization(
        nonce: String,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization {
        val base = SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization(
            contractVersion = SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary
                .CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            authorizesNetworkAccess = false,
            authorizesSftpChannelOpen = false,
            authorizesSingleSftpChannelOpenHandoff = true,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeSftpChannelOpen = true,
            requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution = true,
            requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution = true,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            priorSshExecutionProofSha256 = sha256("phase11.46-prior-proof-$nonce"),
            priorSshExecutionReceiptSha256 = sha256("phase11.46-prior-receipt-$nonce"),
            serverAccessBindingSha256 = sha256("phase11.46-access-binding-$nonce"),
            requestSha256 = sha256("phase11.46-request-$nonce"),
            capabilityProfileSha256 = sha256("phase11.46-profile-$nonce"),
            serverAccessId = "phase11_46_access_$nonce",
            remoteHostIdentity = "203.0.113.46",
            remotePort = 2246,
            username = "velum-site",
            pinnedHostKeySha256 = sha256("phase11.46-pinned-host-key-$nonce"),
            secretReferenceType = "private-key",
            secretReferenceSha256 = sha256("phase11.46-secret-reference-$nonce"),
            sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
            exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
            sftpLifecycleProbeImplementation = SiteRemoteSftpChannelLifecycleProbe::class.java.name,
            authorizationAttemptId = "phase11_46_auth_$nonce",
            evaluatedAtEpochMillis = 46_000L,
            authorizationExpiresAtEpochMillis = 56_000L,
            approvalChallengeSha256 = sha256("phase11.46-approval-$nonce"),
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = phase11_45AuthorizationSha256(base))
    }

    private fun phase11_45AuthorizationSha256(
        authorization: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization,
    ): String = sha256(
        buildString {
            append("phase=11.45\n")
            append("status=").append(authorization.status.name).append('\n')
            append("priorSshExecutionProofSha256=").append(authorization.priorSshExecutionProofSha256).append('\n')
            append("priorSshExecutionReceiptSha256=").append(authorization.priorSshExecutionReceiptSha256).append('\n')
            append("serverAccessBindingSha256=").append(authorization.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(authorization.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(authorization.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(authorization.serverAccessId).append('\n')
            append("host=").append(authorization.remoteHostIdentity).append('\n')
            append("port=").append(authorization.remotePort).append('\n')
            append("username=").append(authorization.username).append('\n')
            append("pinnedHostKeySha256=").append(authorization.pinnedHostKeySha256).append('\n')
            append("secretReferenceType=").append(authorization.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(authorization.secretReferenceSha256).append('\n')
            append("sshFactory=").append(authorization.sshConnectionFactoryImplementation).append('\n')
            append("registry=").append(authorization.exactSessionRegistryImplementation).append('\n')
            append("sftpProbe=").append(authorization.sftpLifecycleProbeImplementation).append('\n')
            append("attemptId=").append(authorization.authorizationAttemptId).append('\n')
            append("evaluatedAt=").append(authorization.evaluatedAtEpochMillis).append('\n')
            append("expiresAt=").append(authorization.authorizationExpiresAtEpochMillis).append('\n')
            append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
        },
    )

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun mark(step: String) {
        Log.i("Phase11_46Diag", step)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_46_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_46_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
