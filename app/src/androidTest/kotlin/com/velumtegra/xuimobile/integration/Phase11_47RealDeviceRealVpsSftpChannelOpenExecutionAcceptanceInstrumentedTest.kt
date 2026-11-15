package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpChannelLifecycleProbe
import com.velumtegra.xuimobile.sitedeployer.*
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_47RealDeviceRealVpsSftpChannelOpenExecutionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_46ReceiptUsesFreshCredentialFreshPinnedSshAndOpensOnlyOneSftpChannel() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.47 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_47Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_47_acceptance_credential")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_47_access_$nonce"),
                serverId = ServerId("phase11_47_server_$nonce"),
                endpoint = SshEndpoint(host = config.host, port = config.port),
                username = config.username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
            )
            val material = config.toSecretMaterial()
            try {
                assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
            } finally {
                material.close()
                config.closeSensitiveBytes()
            }
            mark("STEP_02_SECRET_CREATED")

            val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
                serverAccess = access,
                targetRoot = "/srv/velum/site",
                stagingRoot = "/srv/velum/site-stage",
                backupRoot = "/srv/velum/site-backup",
                expectedTargetEntryNames = listOf("index.html", "assets"),
                admissionAttemptId = "phase11_47_admission_$nonce",
                evaluatedAtEpochMillis = 47_000L,
            )
            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_47_preflight_$nonce",
                evaluatedAtEpochMillis = 47_100L,
                requestedAuthorizationLifetimeMillis = 14_000L,
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
                consumedAtEpochMillis = 47_101L,
            )
            mark("STEP_03_PREFLIGHT_HANDOFF_READY")

            val firstCredentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_47_cred_first_$nonce",
                evaluatedAtEpochMillis = 47_200L,
                requestedAuthorizationLifetimeMillis = 8_000L,
            )
            val firstCredentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = firstCredentialDraft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = firstCredentialDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            val firstCredentialReceipt = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                authorization = firstCredentialAuthorization,
                consumedAtEpochMillis = 47_201L,
            )
            val firstResolution = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                receipt = firstCredentialReceipt,
                serverAccess = access,
                resolvedAtEpochMillis = 47_202L,
            ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            mark("STEP_04_FIRST_CREDENTIAL_RESOLVED")

            val sshDraft = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
                resolutionProof = firstResolution.proof,
                credentialLease = firstResolution.lease,
                serverAccess = access,
                authorizationAttemptId = "phase11_47_ssh_prior_$nonce",
                evaluatedAtEpochMillis = 47_203L,
                requestedAuthorizationLifetimeMillis = 7_000L,
            )
            val sshAuthorization = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization(
                draft = sshDraft,
                approval = SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval(
                    approvalChallengeSha256 = sshDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            val sshReceipt = application.siteProductionDeploymentConsumeRealVpsSshSessionAcquisitionHandoff(
                authorization = sshAuthorization,
                consumedAtEpochMillis = 47_204L,
            )
            val priorSshProof = application.siteProductionDeploymentAcquireRealVpsSshSessionOnce(
                receipt = sshReceipt,
                credentialLease = firstResolution.lease,
                serverAccess = access,
                executionAttemptId = "phase11_47_prior_ssh_$nonce",
                executedAtEpochMillis = 47_205L,
            )
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary.validateProof(priorSshProof)
            assertTrue(priorSshProof.sessionClosed)
            assertFalse(priorSshProof.sftpChannelOpened)
            mark("STEP_05_PRIOR_PHASE11_44_STYLE_PROOF_CLOSED")

            val sftpDraft = application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft(
                sshExecutionProof = priorSshProof,
                serverAccess = access,
                authorizationAttemptId = "phase11_47_sftp_auth_$nonce",
                evaluatedAtEpochMillis = 47_206L,
                requestedAuthorizationLifetimeMillis = 6_000L,
            )
            val sftpAuthorization = application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorization(
                draft = sftpDraft,
                approval = SiteProductionDeploymentRealVpsSftpChannelOpenApproval(
                    approvalChallengeSha256 = sftpDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            val sftpReceipt = application.siteProductionDeploymentConsumeRealVpsSftpChannelOpenHandoff(
                authorization = sftpAuthorization,
                consumedAtEpochMillis = 47_207L,
            )
            SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary.validateReceipt(sftpReceipt)
            mark("STEP_06_PHASE11_46_RECEIPT_DURABLE")

            val freshCredentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_47_cred_fresh_$nonce",
                evaluatedAtEpochMillis = 47_208L,
                requestedAuthorizationLifetimeMillis = 5_000L,
            )
            val freshCredentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                draft = freshCredentialDraft,
                approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    approvalChallengeSha256 = freshCredentialDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            val freshCredentialReceipt = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                authorization = freshCredentialAuthorization,
                consumedAtEpochMillis = 47_209L,
            )
            val freshResolution = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                receipt = freshCredentialReceipt,
                serverAccess = access,
                resolvedAtEpochMillis = 47_210L,
            ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(freshResolution.proof)
            assertTrue(freshResolution.proof.resolvedAtEpochMillis >= sftpReceipt.consumedAtEpochMillis)
            assertFalse(freshResolution.proof.productionNetworkTouched)
            mark("STEP_07_FRESH_POST_HANDOFF_CREDENTIAL_RESOLVED")

            val beforeExecution = application.siteProductionDeploymentReplayFence.snapshot()
            mark("STEP_08_BEFORE_PHASE11_47_NETWORK")
            val proof = application.siteProductionDeploymentOpenRealVpsSftpChannelOnce(
                receipt = sftpReceipt,
                freshResolutionProof = freshResolution.proof,
                freshCredentialLease = freshResolution.lease,
                serverAccess = access,
                executionAttemptId = "phase11_47_exec_$nonce",
                executedAtEpochMillis = 47_211L,
            )
            mark("STEP_09_SFTP_CHANNEL_AND_SESSION_CLOSED")
            SiteProductionDeploymentAndroidRealVpsSftpChannelOpenExecutionBoundary.validateProof(proof)

            assertEquals(
                SiteProductionDeploymentRealVpsSftpChannelOpenExecutionStatus
                    .REAL_VPS_SFTP_CHANNEL_OPENED_AND_CLOSED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
                proof.status,
            )
            assertTrue(proof.durableHandoffConsumed)
            assertTrue(proof.executionReceiptConsumed)
            assertTrue(proof.freshCredentialResolutionProofValidated)
            assertTrue(proof.credentialLeaseMaterialConsumed)
            assertTrue(proof.productionNetworkTouched)
            assertTrue(proof.hostKeyPinVerifiedAgainstRemote)
            assertTrue(proof.productionSshAdapterUsed)
            assertTrue(proof.freshSshSessionAcquisitionExecuted)
            assertTrue(proof.exactSessionRegistryUsed)
            assertTrue(proof.sessionRegistered)
            assertTrue(proof.exactRegistryLookupMatched)
            assertTrue(proof.sftpChannelOpened)
            assertTrue(proof.sftpChannelClosed)
            assertFalse(proof.sftpOperationPerformed)
            assertFalse(proof.remoteCommandDispatched)
            assertFalse(proof.remoteReadPerformed)
            assertFalse(proof.mutationPerformed)
            assertTrue(proof.sessionClosed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            assertTrue(proof.realVpsAccessPerformed)
            assertTrue(proof.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(proof.requiresSeparateMutationBoundary)
            assertEquals(access.id.value, proof.serverAccessId)
            assertEquals(access.endpoint.host, proof.remoteHostIdentity)
            assertEquals(access.endpoint.port, proof.remotePort)
            assertEquals(access.username, proof.username)
            assertEquals(sftpReceipt.authorizationSha256, proof.authorizationSha256)
            assertEquals(
                sftpReceipt.sftpChannelOpenConsumptionReceiptSha256,
                proof.sftpChannelOpenConsumptionReceiptSha256,
            )
            assertEquals(freshResolution.proof.resolutionProofSha256, proof.freshCredentialResolutionProofSha256)
            assertEquals(sftpReceipt.pinnedHostKeySha256, proof.verifiedHostKeySha256)
            assertEquals(JschSshConnectionFactory::class.java.name, proof.sshConnectionFactoryImplementation)
            assertEquals(ExactSessionRegistry::class.java.name, proof.exactSessionRegistryImplementation)
            assertEquals(SiteRemoteSftpChannelLifecycleProbe::class.java.name, proof.sftpLifecycleProbeImplementation)
            assertFalse(proof.toString().contains(secretId.value))

            val afterExecution = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                beforeExecution.copy(
                    realVpsSftpChannelOpenExecutionReceiptMarkerCount =
                        beforeExecution.realVpsSftpChannelOpenExecutionReceiptMarkerCount + 1,
                ),
                afterExecution,
            )
            assertTrue(
                application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_EXECUTION_RECEIPT,
                    sftpReceipt.sftpChannelOpenConsumptionReceiptSha256,
                ),
            )
            mark("STEP_10_ONLY_EXECUTION_RECEIPT_MARKER_CHANGED")

            val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
            assertTrue(
                reconstructed.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_EXECUTION_RECEIPT,
                    sftpReceipt.sftpChannelOpenConsumptionReceiptSha256,
                ),
            )
            assertFalse(
                reconstructed.realVpsSftpChannelOpenExecutionUsePort()
                    .consumeOnce(sftpReceipt.sftpChannelOpenConsumptionReceiptSha256),
            )
            assertTrue(
                runCatching {
                    application.siteProductionDeploymentOpenRealVpsSftpChannelOnce(
                        receipt = sftpReceipt,
                        freshResolutionProof = freshResolution.proof,
                        freshCredentialLease = freshResolution.lease,
                        serverAccess = access,
                        executionAttemptId = "phase11_47_replay_$nonce",
                        executedAtEpochMillis = 47_212L,
                    )
                }.isFailure,
            )
            assertEquals(afterExecution, application.siteProductionDeploymentReplayFence.snapshot())
            assertTrue(
                runCatching {
                    freshResolution.lease.useMaterialOnce { secret -> secret.useBytes { it.size } }
                }.isFailure,
            )
            mark("STEP_11_REPLAY_AND_FRESH_LEASE_REUSE_REJECTED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            runCatching { configFile.delete() }
            mark("STEP_12_CLEANUP_COMPLETE")
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_47_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_47_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }

    private fun mark(step: String) {
        Log.i("Phase11_47Diag", step)
    }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_47_real_vps_sftp_acceptance.properties"
    }
}

private class OneShotPhase11_47Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial {
        val bytes = password ?: error("Phase 11.47 password material is already closed")
        return SecretMaterial.fromBytes(bytes)
    }

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_47Config {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES) { "Phase 11.47 acceptance config size is invalid" }
                val text = bytes.toString(StandardCharsets.US_ASCII)
                val values = text.lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val separator = line.indexOf('=')
                        require(separator > 0) { "Phase 11.47 acceptance config line is malformed" }
                        line.substring(0, separator) to line.substring(separator + 1)
                    }
                require(values["version"] == "1") { "Phase 11.47 acceptance config version is unsupported" }
                require(values["auth"] == "password") { "Phase 11.47 acceptance is fixed to password Test Lab auth" }
                val host = decodeUtf8(values.requireValue("host_b64"), "host")
                val username = decodeUtf8(values.requireValue("username_b64"), "username")
                val hostKey = decodeUtf8(values.requireValue("hostkey_b64"), "host key")
                require(host.isNotBlank() && host == host.trim())
                require(username.isNotBlank() && username == username.trim())
                require(hostKey.startsWith("SHA256:") && hostKey.length > 7)
                val port = values.requireValue("port").toIntOrNull()
                    ?: throw IllegalArgumentException("Phase 11.47 SSH port is invalid")
                require(port in 1..65535)
                val password = decodeBytes(values.requireValue("password_b64"), "password")
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_47Config(
                    host = host,
                    port = port,
                    username = username,
                    hostKeySha256 = hostKey,
                    password = password,
                )
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun decodeUtf8(value: String, label: String): String {
            val decoded = decodeBytes(value, label)
            return try {
                decoded.toString(StandardCharsets.UTF_8)
            } finally {
                Arrays.fill(decoded, 0)
            }
        }

        private fun decodeBytes(value: String, label: String): ByteArray = try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Phase 11.47 $label Base64 is invalid", error)
        }

        private fun Map<String, String>.requireValue(key: String): String =
            this[key] ?: throw IllegalArgumentException("Phase 11.47 acceptance config missing $key")
    }
}
