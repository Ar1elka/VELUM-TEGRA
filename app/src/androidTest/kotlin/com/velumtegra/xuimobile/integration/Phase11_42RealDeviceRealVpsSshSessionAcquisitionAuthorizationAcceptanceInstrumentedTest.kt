package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.sitedeployer.*
import java.security.MessageDigest
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_42RealDeviceRealVpsSshSessionAcquisitionAuthorizationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_41ProofAndLeaseAuthorizeOnlyFutureSshHandoffWithoutNetworkOrLeaseRead() = runBlocking {
        val nonce = requiredRunNonce()
        val secretId = SecretId("phase11_42_secret_$nonce")
        val access = ServerAccess(
            id = ServerAccessId("phase11_42_access_$nonce"),
            serverId = ServerId("phase11_42_server_$nonce"),
            endpoint = SshEndpoint(host = "203.0.113.42", port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.42-candidate-host-key-$nonce".encodeToByteArray())
                .asModel(),
        )
        val secretStore = AndroidKeystoreSecretStore(context)
        val fixtureBytes = "phase11_42_ephemeral_fixture_$nonce".encodeToByteArray()
        val expectedDigest = MessageDigest.getInstance("SHA-256")
            .digest(fixtureBytes)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        val material = SecretMaterial.fromBytes(fixtureBytes)
        try {
            assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
        } finally {
            material.close()
        }

        try {
            val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
                serverAccess = access,
                targetRoot = "/srv/velum/site",
                stagingRoot = "/srv/velum/site-stage",
                backupRoot = "/srv/velum/site-backup",
                expectedTargetEntryNames = listOf("index.html", "assets"),
                admissionAttemptId = "phase11_42_admission_$nonce",
                evaluatedAtEpochMillis = 42_000L,
            )
            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_42_preflight_auth_$nonce",
                evaluatedAtEpochMillis = 42_100L,
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
                consumedAtEpochMillis = 42_101L,
            )
            val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_42_credential_auth_$nonce",
                evaluatedAtEpochMillis = 42_200L,
                requestedAuthorizationLifetimeMillis = 5_000L,
            )
            val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = credentialDraft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = credentialDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            val credentialReceipt = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                authorization = credentialAuthorization,
                consumedAtEpochMillis = 42_201L,
            )
            val resolution = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                receipt = credentialReceipt,
                serverAccess = access,
                resolvedAtEpochMillis = 42_202L,
            )
            assertTrue(resolution is SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved)
            val resolved = resolution as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(resolved.proof)

            val beforeAuthorization = application.siteProductionDeploymentReplayFence.snapshot()
            val draft = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
                resolutionProof = resolved.proof,
                credentialLease = resolved.lease,
                serverAccess = access,
                authorizationAttemptId = "phase11_42_ssh_auth_$nonce",
                evaluatedAtEpochMillis = 42_203L,
                requestedAuthorizationLifetimeMillis = 4_000L,
            )
            val draftAgain = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
                resolutionProof = resolved.proof,
                credentialLease = resolved.lease,
                serverAccess = access,
                authorizationAttemptId = "phase11_42_ssh_auth_$nonce",
                evaluatedAtEpochMillis = 42_203L,
                requestedAuthorizationLifetimeMillis = 4_000L,
            )
            assertEquals(draft, draftAgain)
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary.validateDraft(draft)
            assertEquals(
                SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                    .AWAITING_EXPLICIT_SSH_SESSION_ACQUISITION_APPROVAL,
                draft.status,
            )
            assertTrue(draft.authorizationOnly)
            assertFalse(draft.credentialLeaseMaterialRead)
            assertFalse(draft.productionNetworkTouched)
            assertFalse(draft.hostKeyPinVerifiedAgainstRemote)
            assertFalse(draft.authorizesNetworkAccess)
            assertFalse(draft.authorizesSshSessionAcquisition)
            assertFalse(draft.authorizesSingleSshSessionAcquisitionHandoff)
            assertFalse(draft.authorizesSftpChannelOpen)
            assertFalse(draft.authorizesReadOnlyPreflightExecution)
            assertFalse(draft.authorizesMutation)
            assertFalse(draft.authorizesCoordinatorInvocation)
            assertFalse(draft.exposesDeployUiAction)
            assertFalse(draft.realVpsAccessAllowed)
            assertTrue(draft.requiresExplicitApproval)
            assertTrue(draft.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
            assertTrue(draft.requiresLiveRemoteHostKeyVerification)
            assertTrue(draft.requiresSeparateSshSessionAcquisitionExecutionBoundary)
            assertTrue(draft.requiresSeparateSftpChannelOpenBoundary)
            assertTrue(draft.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(draft.requiresSeparateMutationBoundary)
            assertEquals(resolved.proof.resolutionProofSha256, draft.resolutionProofSha256)
            assertEquals(resolved.proof.serverAccessBindingSha256, draft.serverAccessBindingSha256)
            assertEquals(JschSshConnectionFactory::class.java.name, draft.sshConnectionFactoryImplementation)
            assertEquals(ExactSessionRegistry::class.java.name, draft.exactSessionRegistryImplementation)
            assertFalse(draft.toString().contains(secretId.value))
            assertFalse(draft.toString().contains(String(fixtureBytes)))

            assertTrue(
                runCatching {
                    application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization(
                        draft = draft,
                        approval = SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval(
                            approvalChallengeSha256 = "0".repeat(64),
                            confirmed = true,
                        ),
                    )
                }.isFailure,
            )
            val authorization = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization(
                draft = draft,
                approval = SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval(
                    approvalChallengeSha256 = draft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary
                .validateAuthorization(authorization)
            assertEquals(
                SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_SSH_SESSION_ACQUISITION_HANDOFF,
                authorization.status,
            )
            assertTrue(authorization.authorizationOnly)
            assertFalse(authorization.credentialLeaseMaterialRead)
            assertFalse(authorization.productionNetworkTouched)
            assertFalse(authorization.hostKeyPinVerifiedAgainstRemote)
            assertFalse(authorization.authorizesNetworkAccess)
            assertFalse(authorization.authorizesSshSessionAcquisition)
            assertTrue(authorization.authorizesSingleSshSessionAcquisitionHandoff)
            assertFalse(authorization.authorizesSftpChannelOpen)
            assertFalse(authorization.authorizesReadOnlyPreflightExecution)
            assertFalse(authorization.authorizesMutation)
            assertFalse(authorization.authorizesCoordinatorInvocation)
            assertFalse(authorization.exposesDeployUiAction)
            assertFalse(authorization.realVpsAccessAllowed)
            assertTrue(authorization.requiresLiveRemoteHostKeyVerification)
            assertEquals(beforeAuthorization, application.siteProductionDeploymentReplayFence.snapshot())
            assertFalse(authorization.toString().contains(secretId.value))
            assertFalse(authorization.toString().contains(String(fixtureBytes)))

            val leaseDigest = resolved.lease.useMaterialOnce { secret ->
                secret.useBytes { bytes ->
                    MessageDigest.getInstance("SHA-256")
                        .digest(bytes)
                        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
                }
            }
            assertEquals(expectedDigest, leaseDigest)
            assertTrue(
                runCatching {
                    resolved.lease.useMaterialOnce { secret -> secret.useBytes { it.size } }
                }.isFailure,
            )
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            Arrays.fill(fixtureBytes, 0)
        }
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_42_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_42_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
