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
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupKind
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
class Phase11_54RealDeviceRealVpsPostTransactionCleanupAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactRetainedBackupAndRollbackStagingAreCleanedWithoutTouchingLiveTarget() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.54 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_54Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_54_acceptance_credential")
        val localBase = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_54-base-")
        val localReplacement = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_54-replacement-")
        val localRollbackCandidate = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_54-rollback-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_54_access_$nonce"),
                serverId = ServerId("phase11_54_server_$nonce"),
                endpoint = SshEndpoint(config.host, config.port),
                username = config.username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
            )
            val material = config.toSecretMaterial()
            try { assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material)) }
            finally { material.close(); config.closeSensitiveBytes() }
            mark("STEP_02_SECRET_CREATED")

            val targetRoot = "/tmp/velum-p1154-${nonce.take(16)}"
            val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()

            val basePreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11540L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = config.host, targetRoot = targetRoot, owner = "root", group = "root",
                ), localBase,
            )
            val baseStagingPlan = SiteDeployerStagingWriteBoundary.prepare(basePreparation)
            val c1 = resolveFreshCredential(access, nonce, 1)
            val baseStagingProof = application.siteProductionDeploymentStageRealVpsBundleOnce(
                basePreparation, baseStagingPlan, c1.proof, c1.lease, access,
                "phase11_54_base_stage_$nonce", c1.proof.resolvedAtEpochMillis + 10L,
            )
            val baseCommitPlan = SiteDeployerCommitTransactionBoundary.prepare(basePreparation, baseStagingPlan)
            val c2 = resolveFreshCredential(access, nonce, 2)
            val baseCommitted = application.siteProductionDeploymentCommitRealVpsStagingOnce(
                baseCommitPlan, baseStagingProof, c2.proof, c2.lease, access,
                "phase11_54_base_commit_$nonce", c2.proof.resolvedAtEpochMillis + 10L,
            )
            assertEquals(SiteRemoteSftpCommitOutcome.COMMITTED, baseCommitted.outcome)
            mark("STEP_03_BASE_TARGET_COMMITTED")

            val replacementPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11541L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = config.host, targetRoot = targetRoot, owner = "root", group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ), localReplacement,
            )
            val replacementStagingPlan = SiteDeployerStagingWriteBoundary.prepare(replacementPreparation)
            val c3 = resolveFreshCredential(access, nonce, 3)
            val replacementStagingProof = application.siteProductionDeploymentStageRealVpsBundleOnce(
                replacementPreparation, replacementStagingPlan, c3.proof, c3.lease, access,
                "phase11_54_replace_stage_$nonce", c3.proof.resolvedAtEpochMillis + 10L,
            )
            val replacementCommitPlan = SiteDeployerCommitTransactionBoundary.prepare(
                replacementPreparation,
                replacementStagingPlan,
                SiteDeployerCommitTransactionBoundary.expectation(basePreparation),
            )
            val c4 = resolveFreshCredential(access, nonce, 4)
            val replacementCommitted = application.siteProductionDeploymentCommitRealVpsStagingOnce(
                replacementCommitPlan, replacementStagingProof, c4.proof, c4.lease, access,
                "phase11_54_replace_commit_$nonce", c4.proof.resolvedAtEpochMillis + 10L,
            )
            assertEquals(SiteRemoteSftpCommitOutcome.COMMITTED, replacementCommitted.outcome)
            assertTrue(replacementCommitted.backupRetainedAfterCommit)
            mark("STEP_04_REPLACEMENT_COMMITTED_WITH_BACKUP")

            val backupCleanupPlan = SiteDeployerPostTransactionCleanupBoundary
                .prepareRetainedBackupAfterCommit(replacementCommitPlan)
            val c5 = resolveFreshCredential(access, nonce, 5)
            val backupCleanup = application.siteProductionDeploymentCleanupRealVpsTransactionResidualOnce(
                backupCleanupPlan, replacementCommitPlan, replacementCommitted,
                c5.proof, c5.lease, access, "phase11_54_backup_cleanup_$nonce",
                c5.proof.resolvedAtEpochMillis + 10L,
            )
            SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary.validateProof(backupCleanup)
            assertEquals(SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT, backupCleanup.cleanupKind)
            assertTrue(backupCleanup.cleanupRootAbsentAfterDelete && backupCleanup.preservedTargetVerifiedAfterDelete)
            assertTrue(backupCleanup.removedFileCount > 0 && backupCleanup.removedDirectoryCount > 0)
            assertFalse(backupCleanup.uploadPerformed || backupCleanup.mkdirPerformed || backupCleanup.renamePerformed)
            assertFalse(backupCleanup.chmodPerformed || backupCleanup.chownOrChgrpPerformed || backupCleanup.remoteCommandDispatched)
            assertFalse(backupCleanup.coordinatorInvoked || backupCleanup.exposesDeployUiAction)
            mark("STEP_05_RETAINED_BACKUP_CLEANED")

            val rollbackPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11542L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = config.host, targetRoot = targetRoot, owner = "root", group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ), localRollbackCandidate,
            )
            val rollbackStagingPlan = SiteDeployerStagingWriteBoundary.prepare(rollbackPreparation)
            val c6 = resolveFreshCredential(access, nonce, 6)
            val rollbackStagingProof = application.siteProductionDeploymentStageRealVpsBundleOnce(
                rollbackPreparation, rollbackStagingPlan, c6.proof, c6.lease, access,
                "phase11_54_rollback_stage_$nonce", c6.proof.resolvedAtEpochMillis + 10L,
            )
            val rollbackCommitPlan = SiteDeployerCommitTransactionBoundary.prepare(
                rollbackPreparation,
                rollbackStagingPlan,
                SiteDeployerCommitTransactionBoundary.expectation(replacementPreparation),
            )
            val c7 = resolveFreshCredential(access, nonce, 7)
            val rolledBack = application.siteProductionDeploymentCommitRealVpsStagingOnce(
                rollbackCommitPlan, rollbackStagingProof, c7.proof, c7.lease, access,
                "phase11_54_rollback_commit_$nonce", c7.proof.resolvedAtEpochMillis + 10L,
                SiteRemoteSftpCommitFailureInjection.AFTER_STAGING_TO_TARGET,
            )
            assertEquals(SiteRemoteSftpCommitOutcome.ROLLED_BACK, rolledBack.outcome)
            assertTrue(rolledBack.finalTargetVerified && rolledBack.finalStagingVerified && rolledBack.finalBackupVerified)
            mark("STEP_06_ROLLBACK_LEFT_EXACT_STAGING")

            val stagingCleanupPlan = SiteDeployerPostTransactionCleanupBoundary.prepareStagingAfterRollback(rollbackCommitPlan)
            val c8 = resolveFreshCredential(access, nonce, 8)
            val stagingCleanup = application.siteProductionDeploymentCleanupRealVpsTransactionResidualOnce(
                stagingCleanupPlan, rollbackCommitPlan, rolledBack,
                c8.proof, c8.lease, access, "phase11_54_staging_cleanup_$nonce",
                c8.proof.resolvedAtEpochMillis + 10L,
            )
            SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary.validateProof(stagingCleanup)
            assertEquals(SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK, stagingCleanup.cleanupKind)
            assertTrue(stagingCleanup.cleanupRootAbsentAfterDelete && stagingCleanup.preservedTargetVerifiedAfterDelete)
            assertTrue(stagingCleanup.siblingAbsentBeforeAndAfter)
            assertFalse(stagingCleanup.uploadPerformed || stagingCleanup.mkdirPerformed || stagingCleanup.renamePerformed)
            mark("STEP_07_ROLLBACK_STAGING_CLEANED")

            val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(beforeFence.realVpsStagingWriteExecutionReceiptMarkerCount + 3, afterFence.realVpsStagingWriteExecutionReceiptMarkerCount)
            assertEquals(beforeFence.realVpsCommitTransactionExecutionReceiptMarkerCount + 3, afterFence.realVpsCommitTransactionExecutionReceiptMarkerCount)
            assertEquals(beforeFence.realVpsPostTransactionCleanupExecutionReceiptMarkerCount + 2, afterFence.realVpsPostTransactionCleanupExecutionReceiptMarkerCount)
            listOf(backupCleanupPlan, stagingCleanupPlan).forEach { plan ->
                assertTrue(application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_POST_TRANSACTION_CLEANUP_EXECUTION_RECEIPT,
                    plan.postTransactionCleanupPlanSha256,
                ))
                assertFalse(application.siteProductionDeploymentReplayFence.realVpsPostTransactionCleanupExecutionUsePort()
                    .consumeOnce(plan.postTransactionCleanupPlanSha256))
            }
            mark("STEP_08_CLEANUP_REPLAY_REJECTED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            listOf(localBase, localReplacement, localRollbackCandidate).forEach(::deleteTree)
            runCatching { configFile.delete() }
            mark("STEP_09_LOCAL_CLEANUP_COMPLETE_REMOTE_LIVE_TARGET_INTENTIONALLY_RETAINED")
        }
    }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
        sequence: Int,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val base = 80_000L + sequence * 1_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_54_admission_${sequence}_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission, "phase11_54_preflight_${sequence}_$nonce", base + 10L, 15_000L,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            preflightDraft,
            SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(preflightDraft.approvalChallengeSha256, true),
        )
        val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            preflightAuthorization, base + 11L,
        )
        val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = preflightReceipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_54_credential_${sequence}_$nonce",
            evaluatedAtEpochMillis = base + 20L,
            requestedAuthorizationLifetimeMillis = 15_000L,
        )
        val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            credentialDraft,
            SiteProductionDeploymentRealVpsCredentialResolutionApproval(credentialDraft.approvalChallengeSha256, true),
        )
        val credentialHandoff = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
            credentialAuthorization, base + 21L,
        )
        return (application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            credentialHandoff, access, base + 22L,
        ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved).also {
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(it.proof)
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_54_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_54Diag", step) }

    companion object { private const val CONFIG_FILE_NAME = "phase11_54_real_vps_post_transaction_cleanup_acceptance.properties" }
}

private class OneShotPhase11_54Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial = SecretMaterial.fromBytes(password ?: error("Phase 11.54 password material is closed"))
    fun closeSensitiveBytes() { password?.let { Arrays.fill(it, 0) }; password = null }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024
        fun readAndDelete(file: File): OneShotPhase11_54Config {
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
                return OneShotPhase11_54Config(host, port, username, hostKey, password)
            } finally { Arrays.fill(bytes, 0); runCatching { file.delete() } }
        }

        private fun decodeUtf8(value: String): String {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            return try { bytes.toString(StandardCharsets.UTF_8) } finally { Arrays.fill(bytes, 0) }
        }
    }
}
