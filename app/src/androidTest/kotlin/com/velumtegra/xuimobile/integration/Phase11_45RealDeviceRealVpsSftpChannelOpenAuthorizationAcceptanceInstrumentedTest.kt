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
class Phase11_45RealDeviceRealVpsSftpChannelOpenAuthorizationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_45ProofAuthorizesOnlyFutureSftpHandoffWithoutNewNetworkOrSftp() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.45 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_45Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_45_acceptance_credential")
        try {
            // Never overwrite any production secret. This fixed acceptance-only id is cleaned before create
            // in case a prior interrupted acceptance left only encrypted app-private test material.
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_45_access_$nonce"),
                serverId = ServerId("phase11_45_server_$nonce"),
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
                admissionAttemptId = "phase11_45_admission_$nonce",
                evaluatedAtEpochMillis = 45_000L,
            )
            assertEquals(
                SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
                    .ADMITTED_FOR_SEPARATE_EXPLICIT_READ_ONLY_PREFLIGHT_AUTHORIZATION,
                admission.status,
            )
            mark("STEP_03_ADMISSION_READY")

            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_45_preflight_auth_$nonce",
                evaluatedAtEpochMillis = 45_100L,
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
                consumedAtEpochMillis = 45_101L,
            )
            mark("STEP_04_PREFLIGHT_HANDOFF_CONSUMED")

            val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_45_credential_auth_$nonce",
                evaluatedAtEpochMillis = 45_200L,
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
                consumedAtEpochMillis = 45_201L,
            )
            val resolution = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                receipt = credentialReceipt,
                serverAccess = access,
                resolvedAtEpochMillis = 45_202L,
            )
            assertTrue(resolution is SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved)
            val resolved = resolution as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(resolved.proof)
            mark("STEP_05_CREDENTIAL_RESOLVED_TO_LEASE")

            val sshDraft = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
                resolutionProof = resolved.proof,
                credentialLease = resolved.lease,
                serverAccess = access,
                authorizationAttemptId = "phase11_45_ssh_auth_$nonce",
                evaluatedAtEpochMillis = 45_203L,
                requestedAuthorizationLifetimeMillis = 4_000L,
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
                consumedAtEpochMillis = 45_204L,
            )
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionHandoffConsumptionBoundary
                .validateReceipt(sshReceipt)
            mark("STEP_06_SSH_HANDOFF_CONSUMED")

            val beforeExecution = application.siteProductionDeploymentReplayFence.snapshot()
            mark("STEP_07_BEFORE_REAL_VPS_NETWORK")
            val proof = application.siteProductionDeploymentAcquireRealVpsSshSessionOnce(
                receipt = sshReceipt,
                credentialLease = resolved.lease,
                serverAccess = access,
                executionAttemptId = "phase11_45_exec_$nonce",
                executedAtEpochMillis = 45_205L,
            )
            mark("STEP_08_REAL_VPS_SESSION_CLOSED")
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary.validateProof(proof)

            assertEquals(
                SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionStatus
                    .REAL_VPS_SESSION_ACQUIRED_VERIFIED_REGISTERED_AND_CLOSED,
                proof.status,
            )
            assertTrue(proof.durableHandoffConsumed)
            assertTrue(proof.executionReceiptConsumed)
            assertTrue(proof.credentialLeaseMaterialConsumed)
            assertTrue(proof.productionNetworkTouched)
            assertTrue(proof.hostKeyPinVerifiedAgainstRemote)
            assertTrue(proof.productionSshAdapterUsed)
            assertTrue(proof.sshSessionAcquisitionExecuted)
            assertTrue(proof.exactSessionRegistryUsed)
            assertTrue(proof.sessionRegistered)
            assertTrue(proof.exactRegistryLookupMatched)
            assertTrue(proof.sessionClosed)
            assertFalse(proof.remoteCommandDispatched)
            assertFalse(proof.sftpChannelOpened)
            assertFalse(proof.remoteReadPerformed)
            assertFalse(proof.mutationPerformed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            assertTrue(proof.realVpsAccessPerformed)
            assertTrue(proof.requiresSeparateSftpChannelOpenBoundary)
            assertTrue(proof.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(proof.requiresSeparateMutationBoundary)
            assertEquals(access.id.value, proof.serverAccessId)
            assertEquals(access.endpoint.host, proof.remoteHostIdentity)
            assertEquals(access.endpoint.port, proof.remotePort)
            assertEquals(access.username, proof.username)
            assertEquals(sshReceipt.authorizationSha256, proof.authorizationSha256)
            assertEquals(
                sshReceipt.sshSessionAcquisitionConsumptionReceiptSha256,
                proof.sshSessionAcquisitionConsumptionReceiptSha256,
            )
            assertEquals(sshReceipt.pinnedHostKeySha256, proof.verifiedHostKeySha256)
            assertEquals(JschSshConnectionFactory::class.java.name, proof.sshConnectionFactoryImplementation)
            assertEquals(ExactSessionRegistry::class.java.name, proof.exactSessionRegistryImplementation)
            assertFalse(proof.toString().contains(secretId.value))

            val afterExecution = application.siteProductionDeploymentReplayFence.snapshot()
            mark("STEP_09_PHASE11_44_PROOF_READY")
            val sftpDraft = application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft(
                sshExecutionProof = proof,
                serverAccess = access,
                authorizationAttemptId = "phase11_45_sftp_auth_$nonce",
                evaluatedAtEpochMillis = 45_206L,
                requestedAuthorizationLifetimeMillis = 5_000L,
            )
            val sftpDraftAgain = application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft(
                sshExecutionProof = proof,
                serverAccess = access,
                authorizationAttemptId = "phase11_45_sftp_auth_$nonce",
                evaluatedAtEpochMillis = 45_206L,
                requestedAuthorizationLifetimeMillis = 5_000L,
            )
            assertEquals(sftpDraft, sftpDraftAgain)
            SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary.validateDraft(sftpDraft)
            assertEquals(
                SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                    .AWAITING_EXPLICIT_SFTP_CHANNEL_OPEN_APPROVAL,
                sftpDraft.status,
            )
            assertTrue(sftpDraft.authorizationOnly)
            assertFalse(sftpDraft.credentialLeaseMaterialRead)
            assertFalse(sftpDraft.productionNetworkTouched)
            assertTrue(sftpDraft.hostKeyPinVerifiedAgainstRemoteByPriorProof)
            assertFalse(sftpDraft.authorizesNetworkAccess)
            assertFalse(sftpDraft.authorizesSftpChannelOpen)
            assertFalse(sftpDraft.authorizesSingleSftpChannelOpenHandoff)
            assertFalse(sftpDraft.authorizesReadOnlyPreflightExecution)
            assertFalse(sftpDraft.authorizesMutation)
            assertFalse(sftpDraft.authorizesCoordinatorInvocation)
            assertFalse(sftpDraft.exposesDeployUiAction)
            assertFalse(sftpDraft.realVpsAccessAllowed)
            assertTrue(sftpDraft.requiresExplicitApproval)
            assertTrue(sftpDraft.requiresDurableOneShotConsumptionBeforeSftpChannelOpen)
            assertTrue(sftpDraft.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
            assertTrue(sftpDraft.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
            assertTrue(sftpDraft.requiresSeparateSftpChannelOpenExecutionBoundary)
            assertTrue(sftpDraft.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(sftpDraft.requiresSeparateMutationBoundary)
            assertEquals(proof.executionProofSha256, sftpDraft.priorSshExecutionProofSha256)
            assertEquals(proof.serverAccessBindingSha256, sftpDraft.serverAccessBindingSha256)
            assertEquals(SiteRemoteSftpChannelLifecycleProbe::class.java.name, sftpDraft.sftpLifecycleProbeImplementation)
            assertFalse(sftpDraft.toString().contains(secretId.value))

            assertTrue(
                runCatching {
                    application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorization(
                        draft = sftpDraft,
                        approval = SiteProductionDeploymentRealVpsSftpChannelOpenApproval(
                            approvalChallengeSha256 = "0".repeat(64),
                            confirmed = true,
                        ),
                    )
                }.isFailure,
            )
            val sftpAuthorization = application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorization(
                draft = sftpDraft,
                approval = SiteProductionDeploymentRealVpsSftpChannelOpenApproval(
                    approvalChallengeSha256 = sftpDraft.approvalChallengeSha256,
                    confirmed = true,
                ),
            )
            SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary
                .validateAuthorization(sftpAuthorization)
            assertEquals(
                SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF,
                sftpAuthorization.status,
            )
            assertTrue(sftpAuthorization.authorizationOnly)
            assertFalse(sftpAuthorization.credentialLeaseMaterialRead)
            assertFalse(sftpAuthorization.productionNetworkTouched)
            assertTrue(sftpAuthorization.hostKeyPinVerifiedAgainstRemoteByPriorProof)
            assertFalse(sftpAuthorization.authorizesNetworkAccess)
            assertFalse(sftpAuthorization.authorizesSftpChannelOpen)
            assertTrue(sftpAuthorization.authorizesSingleSftpChannelOpenHandoff)
            assertFalse(sftpAuthorization.authorizesReadOnlyPreflightExecution)
            assertFalse(sftpAuthorization.authorizesMutation)
            assertFalse(sftpAuthorization.authorizesCoordinatorInvocation)
            assertFalse(sftpAuthorization.exposesDeployUiAction)
            assertFalse(sftpAuthorization.realVpsAccessAllowed)
            assertTrue(sftpAuthorization.requiresDurableOneShotConsumptionBeforeSftpChannelOpen)
            assertTrue(sftpAuthorization.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
            assertTrue(sftpAuthorization.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
            assertTrue(sftpAuthorization.requiresSeparateSftpChannelOpenExecutionBoundary)
            assertTrue(sftpAuthorization.requiresSeparateReadOnlyExecutionBoundary)
            assertTrue(sftpAuthorization.requiresSeparateMutationBoundary)
            assertEquals(proof.executionProofSha256, sftpAuthorization.priorSshExecutionProofSha256)
            assertEquals(afterExecution, application.siteProductionDeploymentReplayFence.snapshot())
            assertFalse(sftpAuthorization.toString().contains(secretId.value))
            mark("STEP_10_SFTP_HANDOFF_AUTHORIZED_WITHOUT_NEW_NETWORK_OR_SFTP")

            assertEquals(
                beforeExecution.realVpsSshSessionAcquisitionExecutionReceiptMarkerCount + 1,
                afterExecution.realVpsSshSessionAcquisitionExecutionReceiptMarkerCount,
            )
            assertEquals(
                beforeExecution.realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount,
                afterExecution.realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount,
            )
            assertEquals(
                beforeExecution.realVpsCredentialResolutionExecutionReceiptMarkerCount,
                afterExecution.realVpsCredentialResolutionExecutionReceiptMarkerCount,
            )
            assertTrue(
                application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_RECEIPT,
                    sshReceipt.sshSessionAcquisitionConsumptionReceiptSha256,
                ),
            )
            mark("STEP_11_EXECUTION_RECEIPT_DURABLE")

            val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
            assertTrue(
                reconstructed.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_RECEIPT,
                    sshReceipt.sshSessionAcquisitionConsumptionReceiptSha256,
                ),
            )
            assertFalse(
                reconstructed.realVpsSshSessionAcquisitionExecutionUsePort()
                    .consumeOnce(sshReceipt.sshSessionAcquisitionConsumptionReceiptSha256),
            )
            assertTrue(
                runCatching {
                    application.siteProductionDeploymentAcquireRealVpsSshSessionOnce(
                        receipt = sshReceipt,
                        credentialLease = resolved.lease,
                        serverAccess = access,
                        executionAttemptId = "phase11_45_replay_$nonce",
                        executedAtEpochMillis = 45_206L,
                    )
                }.isFailure,
            )
            assertEquals(afterExecution, application.siteProductionDeploymentReplayFence.snapshot())
            assertTrue(
                runCatching {
                    resolved.lease.useMaterialOnce { secret -> secret.useBytes { it.size } }
                }.isFailure,
            )
            mark("STEP_12_REPLAY_AND_LEASE_REUSE_REJECTED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            runCatching { configFile.delete() }
            mark("STEP_13_CLEANUP_COMPLETE")
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(
            info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true,
        )
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_45_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_45_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }

    private fun mark(step: String) {
        Log.i("Phase11_45Diag", step)
    }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_45_real_vps_ssh_acceptance.properties"
    }
}

private class OneShotPhase11_45Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial {
        val bytes = password ?: error("Phase 11.45 password material is already closed")
        return SecretMaterial.fromBytes(bytes)
    }

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_45Config {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES) { "Phase 11.45 acceptance config size is invalid" }
                val text = bytes.toString(StandardCharsets.US_ASCII)
                val values = text.lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val separator = line.indexOf('=')
                        require(separator > 0) { "Phase 11.45 acceptance config line is malformed" }
                        line.substring(0, separator) to line.substring(separator + 1)
                    }
                require(values["version"] == "1") { "Phase 11.45 acceptance config version is unsupported" }
                require(values["auth"] == "password") { "Phase 11.45 acceptance is fixed to password Test Lab auth" }
                val host = decodeUtf8(values.requireValue("host_b64"), "host")
                val username = decodeUtf8(values.requireValue("username_b64"), "username")
                val hostKey = decodeUtf8(values.requireValue("hostkey_b64"), "host key")
                require(host.isNotBlank() && host == host.trim())
                require(username.isNotBlank() && username == username.trim())
                require(hostKey.startsWith("SHA256:") && hostKey.length > 7)
                val port = values.requireValue("port").toIntOrNull()
                    ?: throw IllegalArgumentException("Phase 11.45 SSH port is invalid")
                require(port in 1..65535)
                val password = decodeBytes(values.requireValue("password_b64"), "password")
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_45Config(
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
            throw IllegalArgumentException("Phase 11.45 $label Base64 is invalid", error)
        }

        private fun Map<String, String>.requireValue(key: String): String =
            this[key] ?: throw IllegalArgumentException("Phase 11.45 acceptance config missing $key")
    }
}
