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
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_40RealDeviceRealVpsCredentialResolutionDurableHandoffConsumptionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_39CredentialAuthorizationIsDurablyConsumedOnceWithoutSecretReadOrNetwork() {
        val nonce = requiredRunNonce()
        val secretId = SecretId("phase11_40_secret_ref_must_not_leak_$nonce")
        val access = ServerAccess(
            id = ServerAccessId("phase11_40_access_$nonce"),
            serverId = ServerId("phase11_40_server_$nonce"),
            endpoint = SshEndpoint(host = "203.0.113.40", port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.40-candidate-host-key-$nonce".encodeToByteArray())
                .asModel(),
        )

        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("index.html", "assets"),
            admissionAttemptId = "phase11_40_admission_$nonce",
            evaluatedAtEpochMillis = 40_000L,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_40_preflight_auth_$nonce",
            evaluatedAtEpochMillis = 40_100L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            draft = preflightDraft,
            approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                approvalChallengeSha256 = preflightDraft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            authorization = preflightAuthorization,
            consumedAtEpochMillis = 40_101L,
        )
        val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = preflightReceipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_40_credential_auth_$nonce",
            evaluatedAtEpochMillis = 40_200L,
            requestedAuthorizationLifetimeMillis = 5_000L,
        )
        val credentialAuthorization =
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = credentialDraft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = credentialDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )

        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val consumedAt = credentialAuthorization.evaluatedAtEpochMillis + 1L
        val receipt = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
            authorization = credentialAuthorization,
            consumedAtEpochMillis = consumedAt,
        )
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionHandoffConsumptionBoundary
            .validateReceipt(receipt)

        assertEquals(
            SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
            receipt.status,
        )
        assertTrue(receipt.singleUseConsumed)
        assertTrue(receipt.credentialReferenceBound)
        assertTrue(receipt.requiresSeparateCredentialResolutionExecutionBoundary)
        assertTrue(receipt.requiresLiveRemoteHostKeyVerification)
        assertFalse(receipt.secretStoreReadPerformed)
        assertFalse(receipt.credentialLeaseMaterialRead)
        assertFalse(receipt.productionNetworkTouched)
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
        assertEquals(credentialAuthorization.authorizationSha256, receipt.authorizationSha256)
        assertEquals(credentialAuthorization.secretReferenceSha256, receipt.secretReferenceSha256)
        assertEquals(
            preflightReceipt.consumptionReceiptSha256,
            receipt.handoffConsumptionReceiptSha256,
        )
        assertFalse(receipt.toString().contains(secretId.value))

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            before.realVpsCredentialResolutionHandoffAuthorizationMarkerCount + 1,
            after.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            before.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
            after.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
        )
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope
                    .REAL_VPS_CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                credentialAuthorization.authorizationSha256,
            ),
        )

        val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope
                    .REAL_VPS_CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                credentialAuthorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructed.realVpsCredentialResolutionHandoffConsumptionPort()
                .consumeOnce(credentialAuthorization.authorizationSha256),
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                authorization = credentialAuthorization,
                consumedAtEpochMillis = consumedAt + 1L,
            )
        }

        val finalSnapshot = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            after.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
            finalSnapshot.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
        )
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_40_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_40_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
