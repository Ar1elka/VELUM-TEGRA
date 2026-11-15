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
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWriteBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitFailureInjection
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitOutcome
import com.velumtegra.xuimobile.sitedeployer.*
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Arrays
import java.util.Comparator
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_53RealDeviceRealVpsCommitRollbackAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactStagingCommitsThenInjectedReplacementFailureRollsBackByRenameOnly() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.53 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_53Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_53_acceptance_credential")
        val localBase = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_53-base-")
        val localReplacement = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_53-replacement-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_53_access_$nonce"),
                serverId = ServerId("phase11_53_server_$nonce"),
                endpoint = SshEndpoint(config.host, config.port),
                username = config.username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
            )
            val material = config.toSecretMaterial()
            try { assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material)) }
            finally { material.close(); config.closeSensitiveBytes() }
            mark("STEP_02_SECRET_CREATED")

            val targetRoot = "/tmp/velum-p1153-${nonce.take(16)}"
            val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()

            val basePreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11530L),
                    domain = "phase1153.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                ),
                localBase,
            )
            val baseStagingPlan = SiteDeployerStagingWriteBoundary.prepare(basePreparation)
            val baseStageCredential = resolveFreshCredential(access, nonce, 1)
            val baseStagingProof = application.siteProductionDeploymentStageRealVpsBundleOnce(
                preparation = basePreparation,
                stagingPlan = baseStagingPlan,
                freshResolutionProof = baseStageCredential.proof,
                freshCredentialLease = baseStageCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_53_base_stage_$nonce",
                executedAtEpochMillis = 71_030L,
            )
            SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.validateProof(baseStagingProof)
            mark("STEP_03_BASE_STAGING_VERIFIED")

            val baseCommitPlan = SiteDeployerCommitTransactionBoundary.prepare(basePreparation, baseStagingPlan)
            val baseCommitCredential = resolveFreshCredential(access, nonce, 2)
            val committed = application.siteProductionDeploymentCommitRealVpsStagingOnce(
                plan = baseCommitPlan,
                stagingExecutionProof = baseStagingProof,
                freshResolutionProof = baseCommitCredential.proof,
                freshCredentialLease = baseCommitCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_53_base_commit_$nonce",
                executedAtEpochMillis = 72_030L,
            )
            SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary.validateProof(committed)
            assertEquals(SiteRemoteSftpCommitOutcome.COMMITTED, committed.outcome)
            assertTrue(committed.stagingToTargetRenamePerformed)
            assertFalse(committed.rollbackPerformed)
            assertFalse(committed.targetToBackupRenamePerformed)
            assertFalse(committed.uploadPerformed || committed.mkdirPerformed || committed.deletePerformed)
            assertFalse(committed.chmodPerformed || committed.chownOrChgrpPerformed || committed.remoteCommandDispatched)
            mark("STEP_04_ABSENT_TARGET_COMMIT_VERIFIED")

            val replacementPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11531L),
                    domain = "phase1153.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ),
                localReplacement,
            )
            val replacementStagingPlan = SiteDeployerStagingWriteBoundary.prepare(replacementPreparation)
            assertFalse(baseStagingPlan.sourceTreeSha256 == replacementStagingPlan.sourceTreeSha256)
            val replacementStageCredential = resolveFreshCredential(access, nonce, 3)
            val replacementStagingProof = application.siteProductionDeploymentStageRealVpsBundleOnce(
                preparation = replacementPreparation,
                stagingPlan = replacementStagingPlan,
                freshResolutionProof = replacementStageCredential.proof,
                freshCredentialLease = replacementStageCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_53_replacement_stage_$nonce",
                executedAtEpochMillis = 73_030L,
            )
            SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.validateProof(replacementStagingProof)
            mark("STEP_05_REPLACEMENT_STAGING_VERIFIED")

            val previousTarget = SiteDeployerCommitTransactionBoundary.expectation(basePreparation)
            val replacementCommitPlan = SiteDeployerCommitTransactionBoundary.prepare(
                replacementPreparation,
                replacementStagingPlan,
                previousTarget,
            )
            val rollbackCredential = resolveFreshCredential(access, nonce, 4)
            val rolledBack = application.siteProductionDeploymentCommitRealVpsStagingOnce(
                plan = replacementCommitPlan,
                stagingExecutionProof = replacementStagingProof,
                freshResolutionProof = rollbackCredential.proof,
                freshCredentialLease = rollbackCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_53_replacement_commit_$nonce",
                executedAtEpochMillis = 74_030L,
                failureInjection = SiteRemoteSftpCommitFailureInjection.AFTER_STAGING_TO_TARGET,
            )
            SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary.validateProof(rolledBack)
            assertEquals(SiteRemoteSftpCommitOutcome.ROLLED_BACK, rolledBack.outcome)
            assertTrue(rolledBack.targetToBackupRenamePerformed)
            assertTrue(rolledBack.stagingToTargetRenamePerformed)
            assertTrue(rolledBack.targetToStagingRollbackRenamePerformed)
            assertTrue(rolledBack.backupToTargetRollbackRenamePerformed)
            assertTrue(rolledBack.rollbackPerformed)
            assertTrue(rolledBack.finalTargetVerified && rolledBack.finalStagingVerified && rolledBack.finalBackupVerified)
            assertFalse(rolledBack.uploadPerformed || rolledBack.mkdirPerformed || rolledBack.deletePerformed)
            assertFalse(rolledBack.chmodPerformed || rolledBack.chownOrChgrpPerformed || rolledBack.remoteCommandDispatched)
            assertFalse(rolledBack.coordinatorInvoked || rolledBack.exposesDeployUiAction)
            mark("STEP_06_INJECTED_FAILURE_ROLLBACK_VERIFIED")

            val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(beforeFence.realVpsStagingWriteExecutionReceiptMarkerCount + 2, afterFence.realVpsStagingWriteExecutionReceiptMarkerCount)
            assertEquals(beforeFence.realVpsCommitTransactionExecutionReceiptMarkerCount + 2, afterFence.realVpsCommitTransactionExecutionReceiptMarkerCount)
            listOf(baseCommitPlan, replacementCommitPlan).forEach { plan ->
                assertTrue(application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_COMMIT_TRANSACTION_EXECUTION_RECEIPT,
                    plan.commitTransactionPlanSha256,
                ))
                assertFalse(application.siteProductionDeploymentReplayFence.realVpsCommitTransactionExecutionUsePort()
                    .consumeOnce(plan.commitTransactionPlanSha256))
            }
            mark("STEP_07_REPLAY_REJECTED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localBase)
            deleteTree(localReplacement)
            runCatching { configFile.delete() }
            mark("STEP_08_LOCAL_CLEANUP_COMPLETE_REMOTE_NONCE_ROOT_INTENTIONALLY_RETAINED")
        }
    }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
        sequence: Int,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val base = 70_000L + sequence * 1_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_53_admission_${sequence}_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission,
            "phase11_53_preflight_${sequence}_$nonce",
            base + 10L,
            15_000L,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            preflightDraft,
            SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(preflightDraft.approvalChallengeSha256, true),
        )
        val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            preflightAuthorization,
            base + 11L,
        )
        val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = preflightReceipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_53_credential_${sequence}_$nonce",
            evaluatedAtEpochMillis = base + 20L,
            requestedAuthorizationLifetimeMillis = 15_000L,
        )
        val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            credentialDraft,
            SiteProductionDeploymentRealVpsCredentialResolutionApproval(credentialDraft.approvalChallengeSha256, true),
        )
        val credentialHandoff = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
            credentialAuthorization,
            base + 21L,
        )
        return (application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            credentialHandoff,
            access,
            base + 22L,
        ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved).also {
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(it.proof)
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_53_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_53Diag", step) }

    companion object { private const val CONFIG_FILE_NAME = "phase11_53_real_vps_commit_rollback_acceptance.properties" }
}

private class OneShotPhase11_53Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial = SecretMaterial.fromBytes(password ?: error("Phase 11.53 password material is closed"))
    fun closeSensitiveBytes() { password?.let { Arrays.fill(it, 0) }; password = null }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024
        fun readAndDelete(file: File): OneShotPhase11_53Config {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES)
                val values = bytes.toString(StandardCharsets.US_ASCII).lineSequence()
                    .map { it.trimEnd('\r') }.filter { it.isNotBlank() }.associate { line ->
                        val i = line.indexOf('='); require(i > 0); line.substring(0, i) to line.substring(i + 1)
                    }
                require(values["version"] == "1" && values["auth"] == "password")
                val host = decodeUtf8(values.getValue("host_b64"))
                val username = decodeUtf8(values.getValue("username_b64"))
                val hostKey = decodeUtf8(values.getValue("hostkey_b64"))
                val port = values.getValue("port").toInt()
                val password = Base64.decode(values.getValue("password_b64"), Base64.NO_WRAP)
                require(host.isNotBlank() && username.isNotBlank() && hostKey.startsWith("SHA256:") && port in 1..65535)
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_53Config(host, port, username, hostKey, password)
            } finally { Arrays.fill(bytes, 0); runCatching { file.delete() } }
        }

        private fun decodeUtf8(value: String): String {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            return try { bytes.toString(StandardCharsets.UTF_8) } finally { Arrays.fill(bytes, 0) }
        }
    }
}
