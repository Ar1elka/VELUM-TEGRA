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
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupKind
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitFailureInjection
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_55RealDeviceRealVpsStaticFileTransactionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun oneBoundedTransactionCommitsCleansAndCounteractsProvenRollback() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.55 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_55Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_55_acceptance_credential")
        val localBase = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_55-base-")
        val localReplacement = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_55-replacement-")
        val localRollback = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_55-rollback-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_55_access_$nonce"),
                serverId = ServerId("phase11_55_server_$nonce"),
                endpoint = SshEndpoint(config.host, config.port),
                username = config.username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
            )
            val material = config.toSecretMaterial()
            try { assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material)) }
            finally { material.close(); config.closeSensitiveBytes() }
            mark("STEP_02_SECRET_CREATED")

            val targetRoot = "/tmp/velum-p1155-${nonce.take(16)}"
            val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()
            var credentialSequence = 0

            suspend fun execute(
                label: String,
                preparation: com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult,
                previous: com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation? = null,
                failureInjection: SiteRemoteSftpCommitFailureInjection = SiteRemoteSftpCommitFailureInjection.NONE,
            ): SiteProductionDeploymentRealVpsStaticFileTransactionResult =
                application.siteProductionDeploymentExecuteRealVpsStaticFileTransactionOnce(
                    request = SiteProductionDeploymentRealVpsStaticFileTransactionRequest(
                        preparation = preparation,
                        serverAccess = access,
                        previousTargetTree = previous,
                        failureInjection = failureInjection,
                    ),
                    credentialProvider = object : SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider {
                        override suspend fun acquire(
                            step: SiteProductionDeploymentRealVpsStaticFileTransactionStep,
                        ): SiteProductionDeploymentRealVpsExecutionCredential {
                            credentialSequence += 1
                            val resolved = resolveFreshCredential(access, nonce, credentialSequence)
                            return SiteProductionDeploymentRealVpsExecutionCredential(
                                proof = resolved.proof,
                                lease = resolved.lease,
                                executionAttemptId = "phase11_55_${label}_${step.name.lowercase()}_${nonce.take(16)}",
                                executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                            )
                        }
                    },
                ).also(SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary::validateResult)

            val basePreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11550L),
                    domain = "phase1155.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                ),
                localBase,
            )
            val base = execute("base", basePreparation)
            assertEquals(SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN, base.outcome)
            assertNull(base.cleanupPlan)
            assertNull(base.cleanupProof)
            assertTrue(base.remoteResidualStateClean)
            assertFalse(base.automaticRetryPerformed || base.coordinatorInvoked || base.exposesDeployUiAction)
            assertEquals(basePreparation.bundle.manifest.treeSha256, base.finalTargetTreeSha256)
            mark("STEP_03_BASE_TRANSACTION_COMMITTED_CLEAN")

            val replacementPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11551L),
                    domain = "phase1155.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ),
                localReplacement,
            )
            val replacement = execute(
                label = "replace",
                preparation = replacementPreparation,
                previous = SiteDeployerCommitTransactionBoundary.expectation(basePreparation),
            )
            assertEquals(SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN, replacement.outcome)
            assertEquals(SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT, replacement.cleanupPlan?.cleanupKind)
            assertTrue(replacement.cleanupProof?.cleanupRootAbsentAfterDelete == true)
            assertTrue(replacement.cleanupProof?.preservedTargetVerifiedAfterDelete == true)
            assertEquals(replacementPreparation.bundle.manifest.treeSha256, replacement.finalTargetTreeSha256)
            mark("STEP_04_REPLACEMENT_TRANSACTION_COMMITTED_AND_BACKUP_CLEANED")

            val rollbackPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11552L),
                    domain = "phase1155.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ),
                localRollback,
            )
            val rolledBack = execute(
                label = "rollback",
                preparation = rollbackPreparation,
                previous = SiteDeployerCommitTransactionBoundary.expectation(replacementPreparation),
                failureInjection = SiteRemoteSftpCommitFailureInjection.AFTER_STAGING_TO_TARGET,
            )
            assertEquals(SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.ROLLED_BACK_CLEAN, rolledBack.outcome)
            assertEquals(SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK, rolledBack.cleanupPlan?.cleanupKind)
            assertTrue(rolledBack.cleanupProof?.cleanupRootAbsentAfterDelete == true)
            assertTrue(rolledBack.cleanupProof?.preservedTargetVerifiedAfterDelete == true)
            assertEquals(replacementPreparation.bundle.manifest.treeSha256, rolledBack.finalTargetTreeSha256)
            assertFalse(rolledBack.automaticRetryPerformed)
            mark("STEP_05_ROLLBACK_COUNTERACTION_CLEAN")

            val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                beforeFence.realVpsStagingWriteExecutionReceiptMarkerCount + 3,
                afterFence.realVpsStagingWriteExecutionReceiptMarkerCount,
            )
            assertEquals(
                beforeFence.realVpsCommitTransactionExecutionReceiptMarkerCount + 3,
                afterFence.realVpsCommitTransactionExecutionReceiptMarkerCount,
            )
            assertEquals(
                beforeFence.realVpsPostTransactionCleanupExecutionReceiptMarkerCount + 2,
                afterFence.realVpsPostTransactionCleanupExecutionReceiptMarkerCount,
            )
            listOf(replacement.cleanupPlan, rolledBack.cleanupPlan).filterNotNull().forEach { plan ->
                assertTrue(
                    application.siteProductionDeploymentReplayFence.hasConsumed(
                        SiteProductionDeploymentReplayScope.REAL_VPS_POST_TRANSACTION_CLEANUP_EXECUTION_RECEIPT,
                        plan.postTransactionCleanupPlanSha256,
                    ),
                )
            }
            assertEquals(8, credentialSequence)
            mark("STEP_06_EXACT_STEP_COUNTS_AND_NO_RETRY_PROVED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            listOf(localBase, localReplacement, localRollback).forEach(::deleteTree)
            runCatching { configFile.delete() }
            mark("STEP_07_LOCAL_CLEANUP_COMPLETE_REMOTE_LIVE_TARGET_INTENTIONALLY_RETAINED")
        }
    }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
        sequence: Int,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val base = 90_000L + sequence * 1_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_55_admission_${sequence}_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission,
            "phase11_55_preflight_${sequence}_$nonce",
            base + 10L,
            15_000L,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            preflightDraft,
            SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                preflightDraft.approvalChallengeSha256,
                true,
            ),
        )
        val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            preflightAuthorization,
            base + 11L,
        )
        val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = preflightReceipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_55_credential_${sequence}_$nonce",
            evaluatedAtEpochMillis = base + 20L,
            requestedAuthorizationLifetimeMillis = 15_000L,
        )
        val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            credentialDraft,
            SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                credentialDraft.approvalChallengeSha256,
                true,
            ),
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
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_55_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_55Diag", step) }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_55_real_vps_static_file_transaction_acceptance.properties"
    }
}

private class OneShotPhase11_55Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.55 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_55Config {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES)
                val values = bytes.toString(StandardCharsets.US_ASCII).lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val i = line.indexOf('=')
                        require(i > 0)
                        line.substring(0, i) to line.substring(i + 1)
                    }
                require(values["version"] == "1" && values["auth"] == "password")
                val host = decodeUtf8(values.getValue("host_b64"))
                val username = decodeUtf8(values.getValue("username_b64"))
                val hostKey = decodeUtf8(values.getValue("hostkey_b64"))
                val port = values.getValue("port").toInt()
                val password = Base64.decode(values.getValue("password_b64"), Base64.NO_WRAP)
                require(host.isNotBlank() && username.isNotBlank() && hostKey.startsWith("SHA256:") && port in 1..65535)
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_55Config(host, port, username, hostKey, password)
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun decodeUtf8(value: String): String {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            return try { bytes.toString(StandardCharsets.UTF_8) } finally { Arrays.fill(bytes, 0) }
        }
    }
}
