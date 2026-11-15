package com.velumtegra.xuimobile.integration

import android.content.Context
import android.util.Log
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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.sitedeployer.*
import java.security.MessageDigest
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_43RealDeviceRealVpsSshSessionAcquisitionDurableHandoffConsumptionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_42SshAuthorizationIsDurablyConsumedOnceWithoutNetworkOrLeaseRead() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        val secretId = SecretId("phase11_43_secret_$nonce")
        val access = ServerAccess(
            id = ServerAccessId("phase11_43_access_$nonce"),
            serverId = ServerId("phase11_43_server_$nonce"),
            endpoint = SshEndpoint(host = "203.0.113.43", port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.43-candidate-host-key-$nonce".encodeToByteArray())
                .asModel(),
        )
        val secretStore = AndroidKeystoreSecretStore(context)
        val fixtureBytes = "phase11_43_ephemeral_fixture_$nonce".encodeToByteArray()
        val expectedDigest = MessageDigest.getInstance("SHA-256")
            .digest(fixtureBytes)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        val material = SecretMaterial.fromBytes(fixtureBytes)
        mark("STEP_02_BEFORE_SECRET_CREATE")
        try {
            assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
            mark("STEP_03_SECRET_CREATED")
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
                admissionAttemptId = "phase11_43_admission_$nonce",
                evaluatedAtEpochMillis = 43_000L,
            )
            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_43_preflight_auth_$nonce",
                evaluatedAtEpochMillis = 43_100L,
                requestedAuthorizationLifetimeMillis = 10_000L,
            )
            val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                draft = preflightDraft,
                approval = SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                    approvalChallengeSha256 = preflightDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            mark("STEP_04_BEFORE_PREFLIGHT_CONSUME")
            val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
                authorization = preflightAuthorization,
                consumedAtEpochMillis = 43_101L,
            )
            mark("STEP_05_PREFLIGHT_CONSUMED")
            val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_43_credential_auth_$nonce",
                evaluatedAtEpochMillis = 43_200L,
                requestedAuthorizationLifetimeMillis = 5_000L,
            )
            val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = credentialDraft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = credentialDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            mark("STEP_06_BEFORE_CREDENTIAL_CONSUME")
            val credentialReceipt = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                authorization = credentialAuthorization,
                consumedAtEpochMillis = 43_201L,
            )
            mark("STEP_07_CREDENTIAL_CONSUMED")
            val resolution = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                receipt = credentialReceipt,
                serverAccess = access,
                resolvedAtEpochMillis = 43_202L,
            )
            assertTrue(resolution is SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved)
            val resolved = resolution as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            mark("STEP_08_CREDENTIAL_RESOLVED")
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(resolved.proof)

            mark("STEP_09_BEFORE_SSH_AUTH_DRAFT")
            val sshDraft = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
                resolutionProof = resolved.proof,
                credentialLease = resolved.lease,
                serverAccess = access,
                authorizationAttemptId = "phase11_43_ssh_auth_$nonce",
                evaluatedAtEpochMillis = 43_203L,
                requestedAuthorizationLifetimeMillis = 4_000L,
            )
            val sshAuthorization = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization(
                draft = sshDraft,
                approval = SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval(
                    approvalChallengeSha256 = sshDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary
                .validateAuthorization(sshAuthorization)
            mark("STEP_10_SSH_AUTHORIZED")

            val before = application.siteProductionDeploymentReplayFence.snapshot()
            val consumedAt = sshAuthorization.evaluatedAtEpochMillis + 1L
            mark("STEP_11_BEFORE_SSH_HANDOFF_CONSUME")
            val receipt = application.siteProductionDeploymentConsumeRealVpsSshSessionAcquisitionHandoff(
                authorization = sshAuthorization,
                consumedAtEpochMillis = consumedAt,
            )
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionHandoffConsumptionBoundary
                .validateReceipt(receipt)
            mark("STEP_12_SSH_HANDOFF_CONSUMED")

            assertEquals(
                SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
                receipt.status,
            )
            assertTrue(receipt.singleUseConsumed)
            assertFalse(receipt.credentialLeaseMaterialRead)
            assertFalse(receipt.productionNetworkTouched)
            assertFalse(receipt.hostKeyPinVerifiedAgainstRemote)
            assertFalse(receipt.authorizesNetworkAccess)
            assertFalse(receipt.authorizesSshSessionAcquisition)
            assertFalse(receipt.authorizesSftpChannelOpen)
            assertFalse(receipt.authorizesReadOnlyPreflightExecution)
            assertFalse(receipt.authorizesMutation)
            assertFalse(receipt.authorizesCoordinatorInvocation)
            assertFalse(receipt.exposesDeployUiAction)
            assertFalse(receipt.realVpsAccessAllowed)
            assertTrue(receipt.requiresLiveRemoteHostKeyVerification)
            assertTrue(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary)
            assertTrue(receipt.requiresSeparateSftpChannelOpenBoundary)
            assertTrue(receipt.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(receipt.requiresSeparateMutationBoundary)
            assertEquals(sshAuthorization.authorizationSha256, receipt.authorizationSha256)
            assertEquals(resolved.proof.resolutionProofSha256, receipt.resolutionProofSha256)
            assertEquals(access.id.value, receipt.serverAccessId)
            assertEquals(access.endpoint.host, receipt.remoteHostIdentity)
            assertEquals(access.endpoint.port, receipt.remotePort)
            assertEquals(JschSshConnectionFactory::class.java.name, receipt.sshConnectionFactoryImplementation)
            assertEquals(ExactSessionRegistry::class.java.name, receipt.exactSessionRegistryImplementation)
            assertFalse(receipt.toString().contains(secretId.value))
            assertFalse(receipt.toString().contains(String(fixtureBytes)))

            mark("STEP_13_BEFORE_REPLAY_SNAPSHOT")
            val after = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                before.realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount + 1,
                after.realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount,
            )
            assertEquals(
                before.realVpsCredentialResolutionExecutionReceiptMarkerCount,
                after.realVpsCredentialResolutionExecutionReceiptMarkerCount,
            )
            assertEquals(
                before.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
                after.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
            )
            assertEquals(
                before.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
                after.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount,
            )
            assertTrue(
                application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope
                        .REAL_VPS_SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                    sshAuthorization.authorizationSha256,
                ),
            )

            mark("STEP_14_SNAPSHOT_VERIFIED")
            val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
            assertTrue(
                reconstructed.hasConsumed(
                    SiteProductionDeploymentReplayScope
                        .REAL_VPS_SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                    sshAuthorization.authorizationSha256,
                ),
            )
            assertFalse(
                reconstructed.realVpsSshSessionAcquisitionHandoffConsumptionPort()
                    .consumeOnce(sshAuthorization.authorizationSha256),
            )
            mark("STEP_15_RECONSTRUCTED_FENCE_VERIFIED")
            assertThrows(IllegalArgumentException::class.java) {
                application.siteProductionDeploymentConsumeRealVpsSshSessionAcquisitionHandoff(
                    authorization = sshAuthorization,
                    consumedAtEpochMillis = consumedAt + 1L,
                )
            }
            assertEquals(after, application.siteProductionDeploymentReplayFence.snapshot())

            mark("STEP_16_REPLAY_REJECTED")
            val leaseDigest = resolved.lease.useMaterialOnce { secret ->
                secret.useBytes { bytes ->
                    MessageDigest.getInstance("SHA-256")
                        .digest(bytes)
                        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
                }
            }
            assertEquals(expectedDigest, leaseDigest)
            mark("STEP_17_LEASE_READ_ONCE_VERIFIED")
            assertTrue(
                runCatching {
                    resolved.lease.useMaterialOnce { secret -> secret.useBytes { it.size } }
                }.isFailure,
            )
            mark("STEP_18_TEST_BODY_COMPLETE")
        } finally {
            mark("STEP_19_CLEANUP_START")
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            Arrays.fill(fixtureBytes, 0)
            mark("STEP_20_CLEANUP_COMPLETE")
        }
    }

    private fun mark(step: String) {
        Log.i("Phase11_43Diag", step)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_43_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_43_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
