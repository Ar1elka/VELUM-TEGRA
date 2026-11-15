package com.velumtegra.xuimobile.integration

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionStatus
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_49RealDeviceRealVpsSftpReadOnlyPreflightDurableHandoffConsumptionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_48ReadOnlyPreflightAuthorizationIsDurablyConsumedOnceWithoutNetworkOrCredentialRead() {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")

        val authorization = validPhase11_48Authorization(nonce)
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary
            .validateAuthorization(authorization)
        mark("STEP_02_AUTHORIZATION_VALIDATED")

        val before = application.siteProductionDeploymentReplayFence.snapshot()

        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeRealVpsSftpReadOnlyPreflightHandoff(
                authorization = authorization,
                consumedAtEpochMillis = authorization.authorizationExpiresAtEpochMillis + 1L,
            )
        }
        assertEquals(before, application.siteProductionDeploymentReplayFence.snapshot())
        mark("STEP_03_EXPIRED_CONSUMPTION_REJECTED_WITHOUT_MARKER")

        val consumedAt = authorization.evaluatedAtEpochMillis + 1L
        val receipt = application.siteProductionDeploymentConsumeRealVpsSftpReadOnlyPreflightHandoff(
            authorization = authorization,
            consumedAtEpochMillis = consumedAt,
        )
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary
            .validateReceipt(receipt)
        mark("STEP_04_HANDOFF_DURABLY_CONSUMED")

        assertEquals(
            SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_FRESH_CREDENTIAL_SSH_SFTP_AND_SEPARATE_READ_ONLY_EXECUTION_BOUNDARY,
            receipt.status,
        )
        assertTrue(receipt.singleUseConsumed)
        assertFalse(receipt.credentialLeaseMaterialRead)
        assertFalse(receipt.productionNetworkTouched)
        assertTrue(receipt.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        assertTrue(receipt.priorSftpChannelOpenedAndClosedWithoutOperation)
        assertFalse(receipt.authorizesNetworkAccess)
        assertFalse(receipt.authorizesCredentialResolution)
        assertFalse(receipt.authorizesSshSessionAcquisition)
        assertFalse(receipt.authorizesSftpChannelOpen)
        assertFalse(receipt.authorizesReadOnlyPreflightExecution)
        assertFalse(receipt.authorizesMutation)
        assertFalse(receipt.authorizesCoordinatorInvocation)
        assertFalse(receipt.exposesDeployUiAction)
        assertFalse(receipt.realVpsAccessAllowed)
        assertTrue(receipt.requiresFreshCredentialResolutionBeforeReadOnlyExecution)
        assertTrue(receipt.requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution)
        assertTrue(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeReadOnlyExecution)
        assertTrue(receipt.requiresFreshSftpChannelOpenBeforeReadOnlyExecution)
        assertTrue(receipt.requiresSeparateReadOnlyExecutionBoundary)
        assertTrue(receipt.requiresSeparateMutationBoundary)
        assertEquals(authorization.authorizationSha256, receipt.authorizationSha256)
        assertEquals(authorization.priorSftpExecutionProofSha256, receipt.priorSftpExecutionProofSha256)
        assertEquals(authorization.priorSftpExecutionReceiptSha256, receipt.priorSftpExecutionReceiptSha256)
        assertEquals(
            authorization.preflightHandoffConsumptionReceiptSha256,
            receipt.preflightHandoffConsumptionReceiptSha256,
        )
        assertEquals(authorization.sourcePreflightAuthorizationSha256, receipt.sourcePreflightAuthorizationSha256)
        assertEquals(authorization.admissionSha256, receipt.admissionSha256)
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
        assertEquals(authorization.targetRoot, receipt.targetRoot)
        assertEquals(authorization.stagingRoot, receipt.stagingRoot)
        assertEquals(authorization.backupRoot, receipt.backupRoot)
        assertEquals(authorization.expectedTargetEntryNames, receipt.expectedTargetEntryNames)
        assertEquals(authorization.approvedReadOnlyOperationVocabulary, receipt.approvedReadOnlyOperationVocabulary)
        assertEquals(authorization.maxTargetEntries, receipt.maxTargetEntries)
        assertEquals(SiteRemoteSftpReadOnlyPreflightProbe::class.java.name, receipt.sftpReadOnlyProbeImplementation)

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            before.copy(
                realVpsSftpReadOnlyPreflightHandoffAuthorizationMarkerCount =
                    before.realVpsSftpReadOnlyPreflightHandoffAuthorizationMarkerCount + 1,
            ),
            after,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        mark("STEP_05_ONLY_NEW_REAL_VPS_READ_ONLY_PREFLIGHT_MARKER_CHANGED")

        val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructed.realVpsSftpReadOnlyPreflightHandoffConsumptionPort()
                .consumeOnce(authorization.authorizationSha256),
        )
        mark("STEP_06_RECONSTRUCTED_FENCE_REJECTED_REPLAY")

        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeRealVpsSftpReadOnlyPreflightHandoff(
                authorization = authorization,
                consumedAtEpochMillis = consumedAt + 1L,
            )
        }
        assertEquals(after, application.siteProductionDeploymentReplayFence.snapshot())
        mark("STEP_07_APP_LEVEL_REPLAY_REJECTED")

        assertFalse(receipt.toString().contains("credential material", ignoreCase = true))
        mark("STEP_08_TEST_BODY_COMPLETE")
    }

    private fun validPhase11_48Authorization(
        nonce: String,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization {
        val base = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization(
            contractVersion = SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary
                .CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_READ_ONLY_PREFLIGHT_HANDOFF,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            priorSftpChannelOpenedAndClosedWithoutOperation = true,
            authorizesNetworkAccess = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesSingleReadOnlyPreflightHandoff = true,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeReadOnlyPreflight = true,
            requiresFreshCredentialResolutionBeforeReadOnlyExecution = true,
            requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution = true,
            requiresFreshSftpChannelOpenBeforeReadOnlyExecution = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            priorSftpExecutionProofSha256 = sha256("phase11.49-prior-sftp-proof-$nonce"),
            priorSftpExecutionReceiptSha256 = sha256("phase11.49-prior-sftp-receipt-$nonce"),
            preflightHandoffConsumptionReceiptSha256 = sha256("phase11.49-preflight-handoff-$nonce"),
            sourcePreflightAuthorizationSha256 = sha256("phase11.49-source-preflight-auth-$nonce"),
            admissionSha256 = sha256("phase11.49-admission-$nonce"),
            serverAccessBindingSha256 = sha256("phase11.49-access-binding-$nonce"),
            requestSha256 = sha256("phase11.49-request-$nonce"),
            capabilityProfileSha256 = sha256("phase11.49-profile-$nonce"),
            serverAccessId = "phase11_49_access_$nonce",
            remoteHostIdentity = "203.0.113.49",
            remotePort = 2249,
            username = "velum-site",
            pinnedHostKeySha256 = sha256("phase11.49-pinned-host-key-$nonce"),
            secretReferenceType = "private-key",
            secretReferenceSha256 = sha256("phase11.49-secret-reference-$nonce"),
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/.site-stage",
            backupRoot = "/srv/velum/.site-backup",
            expectedTargetEntryNames = listOf("assets", "index.html"),
            approvedReadOnlyOperationVocabulary =
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
            maxTargetEntries = SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES,
            sftpReadOnlyProbeImplementation = SiteRemoteSftpReadOnlyPreflightProbe::class.java.name,
            authorizationAttemptId = "phase11_49_auth_$nonce",
            evaluatedAtEpochMillis = 49_000L,
            authorizationExpiresAtEpochMillis = 59_000L,
            approvalChallengeSha256 = sha256("phase11.49-approval-$nonce"),
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = phase11_48AuthorizationSha256(base))
    }

    private fun phase11_48AuthorizationSha256(
        authorization: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization,
    ): String = sha256(buildString {
        append("phase=11.48\n")
        append("status=").append(authorization.status.name).append('\n')
        append("priorSftpExecutionProofSha256=").append(authorization.priorSftpExecutionProofSha256).append('\n')
        append("priorSftpExecutionReceiptSha256=").append(authorization.priorSftpExecutionReceiptSha256).append('\n')
        append("preflightHandoffConsumptionReceiptSha256=").append(authorization.preflightHandoffConsumptionReceiptSha256).append('\n')
        append("sourcePreflightAuthorizationSha256=").append(authorization.sourcePreflightAuthorizationSha256).append('\n')
        append("admissionSha256=").append(authorization.admissionSha256).append('\n')
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
        append("targetRoot=").append(authorization.targetRoot).append('\n')
        append("stagingRoot=").append(authorization.stagingRoot).append('\n')
        append("backupRoot=").append(authorization.backupRoot).append('\n')
        append("expected=").append(authorization.expectedTargetEntryNames.joinToString(",")).append('\n')
        append("ops=").append(authorization.approvedReadOnlyOperationVocabulary.joinToString(",")).append('\n')
        append("maxTargetEntries=").append(authorization.maxTargetEntries).append('\n')
        append("probe=").append(authorization.sftpReadOnlyProbeImplementation).append('\n')
        append("attemptId=").append(authorization.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(authorization.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(authorization.authorizationExpiresAtEpochMillis).append('\n')
        append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
    })

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun mark(step: String) {
        Log.i("Phase11_49Diag", step)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_49_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_49_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
