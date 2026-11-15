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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.security.MessageDigest
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_41RealDeviceRealVpsCredentialResolutionExecutionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_40ReceiptResolvesOneAppPrivateCredentialIntoEphemeralLeaseWithoutNetwork() = runBlocking {
        val nonce = requiredRunNonce()
        val secretId = SecretId("phase11_41_secret_$nonce")
        val access = ServerAccess(
            id = ServerAccessId("phase11_41_access_$nonce"),
            serverId = ServerId("phase11_41_server_$nonce"),
            endpoint = SshEndpoint(host = "203.0.113.41", port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.41-candidate-host-key-$nonce".encodeToByteArray())
                .asModel(),
        )
        val secretStore = AndroidKeystoreSecretStore(context)
        val fixtureBytes = "phase11_41_ephemeral_fixture_$nonce".encodeToByteArray()
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
                admissionAttemptId = "phase11_41_admission_$nonce",
                evaluatedAtEpochMillis = 41_000L,
            )
            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_41_preflight_auth_$nonce",
                evaluatedAtEpochMillis = 41_100L,
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
                consumedAtEpochMillis = 41_101L,
            )
            val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_41_credential_auth_$nonce",
                evaluatedAtEpochMillis = 41_200L,
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
            val credentialReceipt = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                authorization = credentialAuthorization,
                consumedAtEpochMillis = 41_201L,
            )

            val before = application.siteProductionDeploymentReplayFence.snapshot()
            val resolvedAt = 41_202L
            val resolution = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                receipt = credentialReceipt,
                serverAccess = access,
                resolvedAtEpochMillis = resolvedAt,
            )
            assertTrue(resolution is SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved)
            val resolved = resolution as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(resolved.proof)

            assertEquals(
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
                resolved.proof.status,
            )
            assertTrue(resolved.proof.durableHandoffConsumed)
            assertTrue(resolved.proof.executionReceiptConsumed)
            assertTrue(resolved.proof.secretStoreReadPerformed)
            assertFalse(resolved.proof.credentialLeaseMaterialRead)
            assertFalse(resolved.proof.credentialMaterialPersisted)
            assertFalse(resolved.proof.productionNetworkTouched)
            assertFalse(resolved.proof.hostKeyPinVerifiedAgainstRemote)
            assertFalse(resolved.proof.authorizesNetworkAccess)
            assertFalse(resolved.proof.authorizesCredentialResolution)
            assertFalse(resolved.proof.authorizesSshSessionAcquisition)
            assertFalse(resolved.proof.authorizesSftpChannelOpen)
            assertFalse(resolved.proof.authorizesReadOnlyPreflightExecution)
            assertFalse(resolved.proof.authorizesMutation)
            assertFalse(resolved.proof.authorizesCoordinatorInvocation)
            assertFalse(resolved.proof.exposesDeployUiAction)
            assertFalse(resolved.proof.realVpsAccessAllowed)
            assertTrue(resolved.proof.requiresLiveRemoteHostKeyVerification)
            assertTrue(resolved.proof.requiresSeparateSshSessionAcquisitionBoundary)
            assertTrue(resolved.proof.requiresSeparateSftpChannelOpenBoundary)
            assertTrue(resolved.proof.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(resolved.proof.requiresSeparateMutationBoundary)
            assertEquals(
                credentialReceipt.credentialResolutionConsumptionReceiptSha256,
                resolved.proof.credentialResolutionConsumptionReceiptSha256,
            )
            assertEquals(credentialReceipt.serverAccessBindingSha256, resolved.proof.serverAccessBindingSha256)
            assertEquals(credentialReceipt.secretReferenceSha256, resolved.proof.secretReferenceSha256)
            assertEquals(AndroidKeystoreSecretStore::class.java.name, resolved.proof.credentialStoreImplementation)
            assertFalse(resolved.proof.toString().contains(secretId.value))
            assertFalse(resolved.lease.toString().contains(String(fixtureBytes)))

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

            val after = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                before.realVpsCredentialResolutionExecutionReceiptMarkerCount + 1,
                after.realVpsCredentialResolutionExecutionReceiptMarkerCount,
            )
            assertEquals(
                before.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
                after.realVpsCredentialResolutionHandoffAuthorizationMarkerCount,
            )
            assertTrue(
                application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                    credentialReceipt.credentialResolutionConsumptionReceiptSha256,
                ),
            )

            val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
            assertTrue(
                reconstructed.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                    credentialReceipt.credentialResolutionConsumptionReceiptSha256,
                ),
            )
            assertFalse(
                reconstructed.realVpsCredentialResolutionExecutionUsePort()
                    .consumeOnce(credentialReceipt.credentialResolutionConsumptionReceiptSha256),
            )
            assertTrue(
                runCatching {
                    application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                        receipt = credentialReceipt,
                        serverAccess = access,
                        resolvedAtEpochMillis = resolvedAt + 1L,
                    )
                }.isFailure,
            )
            assertEquals(after, application.siteProductionDeploymentReplayFence.snapshot())
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            Arrays.fill(fixtureBytes, 0)
        }
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_41_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_41_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }
}
