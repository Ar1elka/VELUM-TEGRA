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
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_39RealDeviceRealVpsCredentialResolutionAuthorizationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactConsumedHandoffCanAuthorizeOneFutureCredentialResolutionWithoutReadingSecretOrNetwork() {
        val nonce = requiredRunNonce()
        val secretId = SecretId("phase11_39_secret_ref_must_not_leak_$nonce")
        val access = candidateAccess(secretId = secretId, host = "203.0.113.39")

        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("index.html", "assets"),
            admissionAttemptId = "phase11_39_admission_$nonce",
            evaluatedAtEpochMillis = 39_000L,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_39_preflight_auth_$nonce",
            evaluatedAtEpochMillis = 39_100L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            draft = preflightDraft,
            approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                approvalChallengeSha256 = preflightDraft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        val receipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            authorization = preflightAuthorization,
            consumedAtEpochMillis = 39_101L,
        )
        val replayBeforeAuthorization = application.siteProductionDeploymentReplayFence.snapshot()

        val draft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = receipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_39_credential_auth_$nonce",
            evaluatedAtEpochMillis = 39_200L,
            requestedAuthorizationLifetimeMillis = 5_000L,
        )
        assertEquals(
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                .AWAITING_EXPLICIT_CREDENTIAL_RESOLUTION_APPROVAL,
            draft.status,
        )
        assertTrue(draft.authorizationOnly)
        assertTrue(draft.requiresExplicitApproval)
        assertTrue(draft.requiresDurableOneShotConsumptionBeforeCredentialResolution)
        assertTrue(draft.requiresLiveRemoteHostKeyVerification)
        assertFalse(draft.secretStoreReadPerformed)
        assertFalse(draft.credentialLeaseMaterialRead)
        assertFalse(draft.productionNetworkTouched)
        assertFalse(draft.hostKeyPinVerifiedAgainstRemote)
        assertFalse(draft.authorizesNetworkAccess)
        assertFalse(draft.authorizesCredentialResolution)
        assertFalse(draft.authorizesSingleCredentialResolutionHandoff)
        assertFalse(draft.authorizesSshSessionAcquisition)
        assertFalse(draft.authorizesSftpChannelOpen)
        assertFalse(draft.authorizesReadOnlyPreflightExecution)
        assertFalse(draft.authorizesMutation)
        assertFalse(draft.authorizesCoordinatorInvocation)
        assertFalse(draft.exposesDeployUiAction)
        assertFalse(draft.realVpsAccessAllowed)
        assertEquals(AndroidKeystoreSecretStore::class.java.name, draft.credentialStoreImplementation)
        assertEquals(receipt.consumptionReceiptSha256, draft.handoffConsumptionReceiptSha256)
        assertEquals(receipt.serverAccessBindingSha256, draft.serverAccessBindingSha256)
        assertFalse(draft.toString().contains(secretId.value))

        val wrongAccess = candidateAccess(
            secretId = SecretId("phase11_39_wrong_secret_$nonce"),
            host = "203.0.113.39",
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = receipt,
                serverAccess = wrongAccess,
                authorizationAttemptId = "phase11_39_wrong_binding_$nonce",
                evaluatedAtEpochMillis = 39_200L,
                requestedAuthorizationLifetimeMillis = 5_000L,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = draft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = "0".repeat(64),
                    confirmed = true,
                ),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = draft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = draft.approvalChallengeSha256,
                    confirmed = false,
                ),
            )
        }

        val authorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            draft = draft,
            approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                approvalChallengeSha256 = draft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        assertEquals(
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
            authorization.status,
        )
        assertTrue(authorization.authorizesSingleCredentialResolutionHandoff)
        assertFalse(authorization.secretStoreReadPerformed)
        assertFalse(authorization.credentialLeaseMaterialRead)
        assertFalse(authorization.productionNetworkTouched)
        assertFalse(authorization.hostKeyPinVerifiedAgainstRemote)
        assertFalse(authorization.authorizesNetworkAccess)
        assertFalse(authorization.authorizesCredentialResolution)
        assertFalse(authorization.authorizesSshSessionAcquisition)
        assertFalse(authorization.authorizesSftpChannelOpen)
        assertFalse(authorization.authorizesReadOnlyPreflightExecution)
        assertFalse(authorization.authorizesMutation)
        assertFalse(authorization.authorizesCoordinatorInvocation)
        assertFalse(authorization.exposesDeployUiAction)
        assertFalse(authorization.realVpsAccessAllowed)
        assertEquals(draft.secretReferenceSha256, authorization.secretReferenceSha256)
        assertEquals(AndroidKeystoreSecretStore::class.java.name, authorization.credentialStoreImplementation)
        assertFalse(authorization.toString().contains(secretId.value))

        val blockedDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = receipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_39_expired_$nonce",
            evaluatedAtEpochMillis = receipt.authorizationExpiresAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 1L,
        )
        assertEquals(
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus.BLOCKED,
            blockedDraft.status,
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = blockedDraft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = blockedDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
        }

        val replayAfterAuthorization = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(replayBeforeAuthorization, replayAfterAuthorization)
    }

    private fun candidateAccess(secretId: SecretId, host: String): ServerAccess =
        ServerAccess(
            id = ServerAccessId("phase11_39_access"),
            serverId = ServerId("phase11_39_server"),
            endpoint = SshEndpoint(host = host, port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.39-candidate-host-key".encodeToByteArray())
                .asModel(),
        )

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_39_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_39_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
