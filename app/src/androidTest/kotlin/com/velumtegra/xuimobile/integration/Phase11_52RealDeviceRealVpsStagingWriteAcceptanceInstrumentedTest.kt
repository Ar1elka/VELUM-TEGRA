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
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWriteBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
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
class Phase11_52RealDeviceRealVpsStagingWriteAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactPhase11_51BundleStagesAndVerifiesOnlyExactTreeWithoutCommitOrCleanup() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.52 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_52Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_52_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_52-local-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_52_access_$nonce"),
                serverId = ServerId("phase11_52_server_$nonce"),
                endpoint = SshEndpoint(config.host, config.port),
                username = config.username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
            )
            val material = config.toSecretMaterial()
            try { assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material)) }
            finally { material.close(); config.closeSensitiveBytes() }
            mark("STEP_02_SECRET_CREATED")

            // Non-network credential-resolution prerequisite reused only to produce one fresh lease.
            val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
                serverAccess = access,
                targetRoot = "/etc/skel",
                stagingRoot = "/etc/skel-stage",
                backupRoot = "/etc/skel-backup",
                expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
                admissionAttemptId = "phase11_52_admission_$nonce",
                evaluatedAtEpochMillis = 60_000L,
            )
            val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission, "phase11_52_preflight_$nonce", 60_010L, 15_000L,
            )
            val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                preflightDraft,
                SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(preflightDraft.approvalChallengeSha256, true),
            )
            val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
                preflightAuthorization, 60_011L,
            )
            val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_52_credential_$nonce",
                evaluatedAtEpochMillis = 60_020L,
                requestedAuthorizationLifetimeMillis = 15_000L,
            )
            val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                credentialDraft,
                SiteProductionDeploymentRealVpsCredentialResolutionApproval(credentialDraft.approvalChallengeSha256, true),
            )
            val credentialHandoff = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                credentialAuthorization, 60_021L,
            )
            val resolved = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
                credentialHandoff, access, 60_022L,
            ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(resolved.proof)
            mark("STEP_03_FRESH_CREDENTIAL_RESOLVED")

            val targetRoot = "/tmp/velum-p1152-${nonce.take(16)}"
            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1152L),
                    domain = "phase1152.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                ),
                localRoot,
            )
            val stagingPlan = SiteDeployerStagingWriteBoundary.prepare(preparation)
            assertTrue(stagingPlan.stagingRoot.startsWith("/tmp/.velum-p1152-"))
            val before = application.siteProductionDeploymentReplayFence.snapshot()
            mark("STEP_04_LOCAL_BUNDLE_AND_STAGING_PLAN_READY")

            val proof = application.siteProductionDeploymentStageRealVpsBundleOnce(
                preparation = preparation,
                stagingPlan = stagingPlan,
                freshResolutionProof = resolved.proof,
                freshCredentialLease = resolved.lease,
                serverAccess = access,
                executionAttemptId = "phase11_52_stage_$nonce",
                executedAtEpochMillis = 60_030L,
            )
            SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.validateProof(proof)
            mark("STEP_05_STAGING_WRITE_VERIFIED")

            assertEquals(stagingPlan.stagingRoot, proof.stagingRoot)
            assertEquals(stagingPlan.sourceTreeSha256, proof.sourceTreeSha256)
            assertEquals(stagingPlan.fileCount, proof.uploadedFileCount)
            assertEquals(stagingPlan.fileCount, proof.verifiedFileCount)
            assertEquals(stagingPlan.totalBytes, proof.totalBytes)
            assertTrue(proof.stagingRootCreated && proof.remoteTreeVerified && proof.sessionClosed)
            assertFalse(proof.targetRootMutationPerformed)
            assertFalse(proof.renamePerformed)
            assertFalse(proof.deletePerformed)
            assertFalse(proof.chmodPerformed)
            assertFalse(proof.chownOrChgrpPerformed)
            assertFalse(proof.remoteCommandDispatched)
            assertFalse(proof.commitPerformed)
            assertFalse(proof.rollbackPerformed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            assertTrue(proof.requiresSeparateCommitBoundary)

            val after = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                before.realVpsStagingWriteExecutionReceiptMarkerCount + 1,
                after.realVpsStagingWriteExecutionReceiptMarkerCount,
            )
            assertTrue(
                application.siteProductionDeploymentReplayFence.hasConsumed(
                    SiteProductionDeploymentReplayScope.REAL_VPS_STAGING_WRITE_EXECUTION_RECEIPT,
                    stagingPlan.stagingWritePlanSha256,
                ),
            )
            assertFalse(application.siteProductionDeploymentReplayFence.realVpsStagingWriteExecutionUsePort()
                .consumeOnce(stagingPlan.stagingWritePlanSha256))
            mark("STEP_06_REPLAY_REJECTED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localRoot)
            runCatching { configFile.delete() }
            mark("STEP_07_LOCAL_CLEANUP_COMPLETE_REMOTE_STAGING_INTENTIONALLY_LEFT_FOR_NEXT_BOUNDARY")
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_52_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_52Diag", step) }

    companion object { private const val CONFIG_FILE_NAME = "phase11_52_real_vps_staging_write_acceptance.properties" }
}

private class OneShotPhase11_52Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial = SecretMaterial.fromBytes(password ?: error("Phase 11.52 password material is closed"))
    fun closeSensitiveBytes() { password?.let { Arrays.fill(it, 0) }; password = null }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024
        fun readAndDelete(file: File): OneShotPhase11_52Config {
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
                return OneShotPhase11_52Config(host, port, username, hostKey, password)
            } finally { Arrays.fill(bytes, 0); runCatching { file.delete() } }
        }
        private fun decodeUtf8(value: String): String {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            return try { bytes.toString(StandardCharsets.UTF_8) } finally { Arrays.fill(bytes, 0) }
        }
    }
}
