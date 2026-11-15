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
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_37RealDeviceRealVpsReadOnlyPreflightExplicitAuthorizationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactAdmissionRequiresFreshExplicitApprovalAndStillAuthorizesNoNetworkExecution() {
        val secretId = SecretId("phase11_37_secret_ref_must_not_leak")
        val access = candidateAccess(secretId = secretId, host = "203.0.113.37")
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("index.html", "assets"),
            admissionAttemptId = "phase11_37_admission_0001",
            evaluatedAtEpochMillis = 37_000L,
        )
        val before = application.siteProductionDeploymentReplayFence.snapshot()

        val draft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_37_authorization_0001",
            evaluatedAtEpochMillis = 37_100L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        assertEquals(
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                .AWAITING_EXPLICIT_REAL_VPS_READ_ONLY_PREFLIGHT_APPROVAL,
            draft.status,
        )
        assertTrue(draft.authorizationOnly)
        assertTrue(draft.requiresExplicitApproval)
        assertTrue(draft.requiresDurableOneShotConsumptionBeforeAnyNetworkAccess)
        assertTrue(draft.requiresLiveRemoteHostKeyVerification)
        assertFalse(draft.productionNetworkTouched)
        assertFalse(draft.credentialLeaseMaterialRead)
        assertFalse(draft.hostKeyPinVerifiedAgainstRemote)
        assertFalse(draft.authorizesNetworkAccess)
        assertFalse(draft.authorizesCredentialResolution)
        assertFalse(draft.authorizesSshSessionAcquisition)
        assertFalse(draft.authorizesSftpChannelOpen)
        assertFalse(draft.authorizesReadOnlyPreflightExecution)
        assertFalse(draft.authorizesSingleRealVpsReadOnlyPreflightHandoff)
        assertFalse(draft.authorizesMutation)
        assertFalse(draft.authorizesCoordinatorInvocation)
        assertFalse(draft.exposesDeployUiAction)
        assertFalse(draft.realVpsAccessAllowed)

        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                draft = draft,
                approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                    approvalChallengeSha256 = "0".repeat(64),
                    confirmed = true,
                ),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                draft = draft,
                approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                    approvalChallengeSha256 = draft.approvalChallengeSha256,
                    confirmed = false,
                ),
            )
        }

        val authorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            draft = draft,
            approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                approvalChallengeSha256 = draft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        assertEquals(
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF,
            authorization.status,
        )
        assertTrue(authorization.authorizesSingleRealVpsReadOnlyPreflightHandoff)
        assertTrue(authorization.requiresDurableOneShotConsumptionBeforeAnyNetworkAccess)
        assertTrue(authorization.requiresLiveRemoteHostKeyVerification)
        assertFalse(authorization.productionNetworkTouched)
        assertFalse(authorization.credentialLeaseMaterialRead)
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
        assertEquals(admission.admissionSha256, authorization.admissionSha256)
        assertEquals(admission.serverAccessBindingSha256, authorization.serverAccessBindingSha256)
        assertEquals(admission.requestSha256, authorization.requestSha256)
        assertEquals(admission.capabilityProfileSha256, authorization.capabilityProfileSha256)
        assertFalse(draft.toString().contains(secretId.value))
        assertFalse(authorization.toString().contains(secretId.value))

        val changedAdmission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/srv/velum/site-next",
            stagingRoot = "/srv/velum/site-next-stage",
            backupRoot = "/srv/velum/site-next-backup",
            expectedTargetEntryNames = listOf("assets", "index.html"),
            admissionAttemptId = "phase11_37_admission_0002",
            evaluatedAtEpochMillis = 37_000L,
        )
        val changedDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = changedAdmission,
            authorizationAttemptId = "phase11_37_authorization_0001",
            evaluatedAtEpochMillis = 37_100L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        assertNotEquals(draft.approvalChallengeSha256, changedDraft.approvalChallengeSha256)
        assertNotEquals(draft.draftSha256, changedDraft.draftSha256)

        val blockedAdmission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = candidateAccess(secretId = secretId, host = "127.0.0.1"),
            targetRoot = "/srv/velum/site",
            stagingRoot = "/srv/velum/site-stage",
            backupRoot = "/srv/velum/site-backup",
            expectedTargetEntryNames = listOf("assets", "index.html"),
            admissionAttemptId = "phase11_37_admission_loopback",
            evaluatedAtEpochMillis = 37_000L,
        )
        val blockedDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = blockedAdmission,
            authorizationAttemptId = "phase11_37_authorization_loopback",
            evaluatedAtEpochMillis = 37_100L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        assertEquals(
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus.BLOCKED,
            blockedDraft.status,
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                draft = blockedDraft,
                approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                    approvalChallengeSha256 = blockedDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
        }

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(before, after)
    }

    private fun candidateAccess(secretId: SecretId, host: String): ServerAccess =
        ServerAccess(
            id = ServerAccessId("phase11_37_access"),
            serverId = ServerId("phase11_37_server"),
            endpoint = SshEndpoint(host = host, port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.37-candidate-host-key".encodeToByteArray())
                .asModel(),
        )
}
