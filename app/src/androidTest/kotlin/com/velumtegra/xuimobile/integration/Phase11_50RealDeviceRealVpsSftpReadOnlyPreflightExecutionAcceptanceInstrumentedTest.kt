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
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
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
class Phase11_50RealDeviceRealVpsSftpReadOnlyPreflightExecutionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_49ReceiptUsesFreshCredentialPinnedSshAndOnlyThreeLstatPlusOneBoundedList() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.50 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_50Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_50_acceptance_credential")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_50_access_$nonce"),
                serverId = ServerId("phase11_50_server_$nonce"),
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

            // Fixed reviewed Test Lab read-only target. No target/path override exists in the runner.
            val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
                serverAccess = access,
                targetRoot = "/etc/skel",
                stagingRoot = "/etc/skel-stage",
                backupRoot = "/etc/skel-backup",
                expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
                admissionAttemptId = "phase11_50_admission_$nonce",
                evaluatedAtEpochMillis = 50_000L,
            )
            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_50_preflight_$nonce",
                evaluatedAtEpochMillis = 50_010L,
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
                consumedAtEpochMillis = 50_011L,
            )
            mark("STEP_03_PHASE11_38_PREFLIGHT_HANDOFF_READY")

            val firstResolution = resolveFreshCredential(
                receipt = preflightReceipt,
                access = access,
                nonce = nonce,
                label = "prior_ssh",
                evaluatedAt = 50_020L,
                consumedAt = 50_021L,
                resolvedAt = 50_022L,
                lifetimeMillis = 8_000L,
            )
            val sshDraft = application.siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
                resolutionProof = firstResolution.proof,
                credentialLease = firstResolution.lease,
                serverAccess = access,
                authorizationAttemptId = "phase11_50_ssh_prior_$nonce",
                evaluatedAtEpochMillis = 50_023L,
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
                consumedAtEpochMillis = 50_024L,
            )
            val priorSshProof = application.siteProductionDeploymentAcquireRealVpsSshSessionOnce(
                receipt = sshReceipt,
                credentialLease = firstResolution.lease,
                serverAccess = access,
                executionAttemptId = "phase11_50_prior_ssh_$nonce",
                executedAtEpochMillis = 50_025L,
            )
            SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary.validateProof(priorSshProof)
            assertTrue(priorSshProof.sessionClosed)
            mark("STEP_04_PRIOR_SSH_PROOF_CLOSED")

            val sftpDraft = application.siteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft(
                sshExecutionProof = priorSshProof,
                serverAccess = access,
                authorizationAttemptId = "phase11_50_sftp_auth_$nonce",
                evaluatedAtEpochMillis = 50_026L,
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
                consumedAtEpochMillis = 50_027L,
            )
            val phase11_47Resolution = resolveFreshCredential(
                receipt = preflightReceipt,
                access = access,
                nonce = nonce,
                label = "phase11_47",
                evaluatedAt = 50_028L,
                consumedAt = 50_029L,
                resolvedAt = 50_030L,
                lifetimeMillis = 5_000L,
            )
            val priorSftpProof = application.siteProductionDeploymentOpenRealVpsSftpChannelOnce(
                receipt = sftpReceipt,
                freshResolutionProof = phase11_47Resolution.proof,
                freshCredentialLease = phase11_47Resolution.lease,
                serverAccess = access,
                executionAttemptId = "phase11_50_prior_sftp_$nonce",
                executedAtEpochMillis = 50_031L,
            )
            SiteProductionDeploymentAndroidRealVpsSftpChannelOpenExecutionBoundary.validateProof(priorSftpProof)
            assertFalse(priorSftpProof.sftpOperationPerformed)
            assertTrue(priorSftpProof.sessionClosed)
            mark("STEP_05_PHASE11_47_SFTP_OPEN_PROOF_CLOSED")

            val readOnlyDraft = application.siteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft(
                sftpExecutionProof = priorSftpProof,
                preflightReceipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_50_read_only_auth_$nonce",
                evaluatedAtEpochMillis = 50_032L,
                requestedAuthorizationLifetimeMillis = 4_000L,
            )
            val readOnlyAuthorization =
                application.siteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization(
                    draft = readOnlyDraft,
                    approval = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightApproval(
                        approvalChallengeSha256 = readOnlyDraft.approvalChallengeSha256,
                        confirmed = true,
                    ),
                )
            val phase11_49Receipt = application.siteProductionDeploymentConsumeRealVpsSftpReadOnlyPreflightHandoff(
                authorization = readOnlyAuthorization,
                consumedAtEpochMillis = 50_033L,
            )
            SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary
                .validateReceipt(phase11_49Receipt)
            mark("STEP_06_PHASE11_49_RECEIPT_DURABLE")

            val freshResolution = resolveFreshCredential(
                receipt = preflightReceipt,
                access = access,
                nonce = nonce,
                label = "phase11_50",
                evaluatedAt = 50_034L,
                consumedAt = 50_035L,
                resolvedAt = 50_036L,
                lifetimeMillis = 3_000L,
            )
            assertTrue(freshResolution.proof.resolvedAtEpochMillis >= phase11_49Receipt.consumedAtEpochMillis)
            assertFalse(freshResolution.proof.productionNetworkTouched)
            mark("STEP_07_FRESH_POST_PHASE11_49_CREDENTIAL_RESOLVED")

            val beforeExecution = application.siteProductionDeploymentReplayFence.snapshot()
            mark("STEP_08_BEFORE_PHASE11_50_NETWORK")
            val proof = application.siteProductionDeploymentObserveRealVpsSftpReadOnlyPreflightOnce(
                receipt = phase11_49Receipt,
                freshResolutionProof = freshResolution.proof,
                freshCredentialLease = freshResolution.lease,
                serverAccess = access,
                executionAttemptId = "phase11_50_exec_$nonce",
                executedAtEpochMillis = 50_037L,
            )
            mark("STEP_09_BOUNDED_READ_ONLY_PREFLIGHT_AND_SESSION_CLOSED")
            SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightExecutionBoundary.validateProof(proof)

            assertEquals(
                SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionStatus
                    .REAL_VPS_BOUNDED_SFTP_READ_ONLY_PREFLIGHT_VERIFIED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
                proof.status,
            )
            assertTrue(proof.executionReceiptConsumed)
            assertTrue(proof.freshCredentialResolutionProofValidated)
            assertTrue(proof.credentialLeaseMaterialConsumed)
            assertTrue(proof.productionNetworkTouched)
            assertTrue(proof.hostKeyPinVerifiedAgainstRemote)
            assertTrue(proof.sftpChannelOpened)
            assertTrue(proof.sftpChannelClosed)
            assertTrue(proof.boundedReadOnlyPreflightPerformed)
            assertTrue(proof.remoteMetadataReadPerformed)
            assertFalse(proof.fileContentReadPerformed)
            assertEquals(3, proof.lstatOperationCount)
            assertEquals(1, proof.listOperationCount)
            assertFalse(proof.mutationOperationPerformed)
            assertFalse(proof.remoteCommandDispatched)
            assertTrue(proof.sessionClosed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            assertTrue(proof.realVpsAccessPerformed)
            assertTrue(proof.requiresSeparateMutationBoundary)
            assertEquals(SiteRemoteObservedPathType.DIRECTORY, proof.targetType)
            assertEquals(SiteRemoteObservedPathType.ABSENT, proof.stagingType)
            assertEquals(SiteRemoteObservedPathType.ABSENT, proof.backupType)
            assertEquals(listOf(".bash_logout", ".bashrc", ".profile"), proof.targetEntryNames)
            assertEquals(
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
                proof.approvedReadOnlyOperationVocabulary,
            )
            assertEquals(SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES, proof.maxTargetEntries)
            assertEquals(access.id.value, proof.serverAccessId)
            assertEquals(access.endpoint.host, proof.remoteHostIdentity)
            assertEquals(access.endpoint.port, proof.remotePort)
            assertEquals(phase11_49Receipt.authorizationSha256, proof.authorizationSha256)
            assertEquals(
                phase11_49Receipt.readOnlyPreflightConsumptionReceiptSha256,
                proof.readOnlyPreflightConsumptionReceiptSha256,
            )
            assertEquals(freshResolution.proof.resolutionProofSha256, proof.freshCredentialResolutionProofSha256)
            assertEquals(phase11_49Receipt.pinnedHostKeySha256, proof.verifiedHostKeySha256)
            assertEquals(JschSshConnectionFactory::class.java.name, proof.sshConnectionFactoryImplementation)
            assertEquals(ExactSessionRegistry::class.java.name, proof.exactSessionRegistryImplementation)
            assertFalse(proof.toString().contains(secretId.value))

            val afterExecution = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                beforeExecution.copy(
                    realVpsSftpReadOnlyPreflightExecutionReceiptMarkerCount =
                        beforeExecution.realVpsSftpReadOnlyPreflightExecutionReceiptMarkerCount + 1,
                ),
                afterExecution,
            )
            assertTrue(
                application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_EXECUTION_RECEIPT,
                    phase11_49Receipt.readOnlyPreflightConsumptionReceiptSha256,
                ),
            )
            mark("STEP_10_ONLY_PHASE11_50_EXECUTION_RECEIPT_MARKER_CHANGED")

            val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
            assertTrue(
                reconstructed.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_EXECUTION_RECEIPT,
                    phase11_49Receipt.readOnlyPreflightConsumptionReceiptSha256,
                ),
            )
            assertFalse(
                reconstructed.realVpsSftpReadOnlyPreflightExecutionUsePort()
                    .consumeOnce(phase11_49Receipt.readOnlyPreflightConsumptionReceiptSha256),
            )
            assertTrue(
                runCatching {
                    application.siteProductionDeploymentObserveRealVpsSftpReadOnlyPreflightOnce(
                        receipt = phase11_49Receipt,
                        freshResolutionProof = freshResolution.proof,
                        freshCredentialLease = freshResolution.lease,
                        serverAccess = access,
                        executionAttemptId = "phase11_50_replay_$nonce",
                        executedAtEpochMillis = 50_038L,
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

    private suspend fun resolveFreshCredential(
        receipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
        access: ServerAccess,
        nonce: String,
        label: String,
        evaluatedAt: Long,
        consumedAt: Long,
        resolvedAt: Long,
        lifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val draft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = receipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_50_cred_${label}_$nonce",
            evaluatedAtEpochMillis = evaluatedAt,
            requestedAuthorizationLifetimeMillis = lifetimeMillis,
        )
        val authorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            draft = draft,
            approval = SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                approvalChallengeSha256 = draft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        val handoff = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
            authorization = authorization,
            consumedAtEpochMillis = consumedAt,
        )
        val result = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            receipt = handoff,
            serverAccess = access,
            resolvedAtEpochMillis = resolvedAt,
        ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(result.proof)
        return result
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
            .getString("phase11_50_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce)) {
            "phase11_50_run_nonce must be a fresh lowercase 32-hex value"
        }
        return nonce
    }

    private fun mark(step: String) {
        Log.i("Phase11_50Diag", step)
    }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_50_real_vps_sftp_read_only_preflight_execution_acceptance.properties"
    }
}

private class OneShotPhase11_50Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial {
        val bytes = password ?: error("Phase 11.50 password material is already closed")
        return SecretMaterial.fromBytes(bytes)
    }

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_50Config {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES) { "Phase 11.50 acceptance config size is invalid" }
                val text = bytes.toString(StandardCharsets.US_ASCII)
                val values = text.lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val separator = line.indexOf('=')
                        require(separator > 0) { "Phase 11.50 acceptance config line is malformed" }
                        line.substring(0, separator) to line.substring(separator + 1)
                    }
                require(values["version"] == "1") { "Phase 11.50 acceptance config version is unsupported" }
                require(values["auth"] == "password") { "Phase 11.50 acceptance is fixed to password Test Lab auth" }
                val host = decodeUtf8(values.requireValue("host_b64"), "host")
                val username = decodeUtf8(values.requireValue("username_b64"), "username")
                val hostKey = decodeUtf8(values.requireValue("hostkey_b64"), "host key")
                require(host.isNotBlank() && host == host.trim())
                require(username.isNotBlank() && username == username.trim())
                require(hostKey.startsWith("SHA256:") && hostKey.length > 7)
                val port = values.requireValue("port").toIntOrNull()
                    ?: throw IllegalArgumentException("Phase 11.50 SSH port is invalid")
                require(port in 1..65535)
                val password = decodeBytes(values.requireValue("password_b64"), "password")
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_50Config(
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
            throw IllegalArgumentException("Phase 11.50 $label Base64 is invalid", error)
        }

        private fun Map<String, String>.requireValue(key: String): String =
            this[key] ?: throw IllegalArgumentException("Phase 11.50 acceptance config missing $key")
    }
}
