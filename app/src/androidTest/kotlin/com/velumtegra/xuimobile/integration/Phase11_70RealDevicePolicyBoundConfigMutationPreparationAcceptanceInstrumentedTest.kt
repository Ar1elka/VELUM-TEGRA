package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.StrictMode
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
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
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
class Phase11_70RealDevicePolicyBoundConfigMutationPreparationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun policyBoundLivePreflightMustGateRollbackAwareMutationPreparationWithoutGrantingMutationAuthority() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.70 one-shot real-VPS acceptance config is missing" }
            val config = OneShotPhase11_70Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_70_acceptance_credential")
            val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_70-")
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_70_access_$nonce"),
                    serverId = ServerId("phase11_70_server_$nonce"),
                    endpoint = SshEndpoint(config.host, config.port),
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

                val preparation = prepare(
                    root = localRoot,
                    host = config.host,
                    port = 58481,
                    targetRoot = "/tmp/velum-p1170-${nonce.take(16)}",
                )
                val evidence = evidence(preparation)
                val selection =
                    SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                        preparation = preparation,
                        staticPublicationEvidence = evidence,
                    )
                val admission =
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                        .admit(selection)
                assertTrue(admission.readOnlyPreflightExecutionEligible)
                mark("STEP_03_EXACT_POLICY_SELECTION_AND_PREFLIGHT_ADMISSION_READY")

                val resolved = resolveFreshCredential(access, nonce)
                val execution =
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                        .observeOnce(
                            admission = admission,
                            selection = selection,
                            freshResolutionProof = resolved.proof,
                            freshCredentialLease = resolved.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_70_web_preflight_${nonce.take(16)}",
                            executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                        )
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .validateExecutionResult(execution)
                mark("STEP_04_POLICY_BOUND_REAL_VPS_READ_ONLY_PREFLIGHT_COMPLETE")

                val priorPolicy = StrictMode.getThreadPolicy()
                val result = try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                        .prepare(
                            selection = selection,
                            policyBoundPreflightExecution = execution,
                            mutationTransactionId = "phase11_70_tx_${nonce.take(16)}",
                        )
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                    .validateAgainst(result, selection, execution)
                mark("STEP_05_PHASE11_69_PROOF_CONSUMED_BY_ZERO_NETWORK_MUTATION_PREPARATION_GATE")

                assertEquals(selection.selectionSha256, result.servingPolicySelectionSha256)
                assertEquals(execution.admissionSha256, result.policyBoundPreflightAdmissionSha256)
                assertEquals(
                    execution.executionResultSha256,
                    result.policyBoundPreflightExecutionResultSha256,
                )
                assertEquals(execution.publicationPlanSha256, result.publicationPlanSha256)
                assertEquals(execution.selectedProtocol, result.selectedProtocol)
                assertEquals(
                    execution.preflightExecutionProof.preflightReport.preflightSha256,
                    result.readOnlyPreflightSha256,
                )
                assertTrue(result.exactPolicyPreflightBindingVerified)
                assertFalse(result.productionNetworkTouchedByPreparation)
                assertFalse(result.remoteMutationPerformed)
                assertFalse(result.configMutationAuthorized)
                assertFalse(result.webServerReloadAuthorized)
                assertFalse(result.certificateMutationAuthorized)
                assertFalse(result.dnsMutationAuthorized)
                assertFalse(result.firewallMutationAuthorized)
                assertFalse(result.packageInstallAuthorized)
                assertFalse(result.privateKeyContentReadAuthorized)
                assertFalse(result.automaticRetryAuthorized)
                assertFalse(result.coordinatorInvoked)
                assertFalse(result.exposesDeployUiAction)

                when (result.status) {
                    SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                        .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY -> {
                        val mutation = requireNotNull(result.mutationPreparation)
                        SiteWebServingConfigMutationPreparationBoundary.validate(mutation)
                        assertTrue(result.mutationPreparationCreated)
                        assertEquals(result.mutationTransactionId, mutation.mutationTransactionId)
                        assertEquals(result.publicationPlanSha256, mutation.publicationPlanSha256)
                        assertEquals(result.readOnlyPreflightSha256, mutation.readOnlyPreflightSha256)
                        assertTrue(mutation.stagingConfigPath.endsWith(".stage"))
                        assertFalse(mutation.stagingConfigPath.endsWith(".conf"))
                        assertFalse(mutation.configMutationAuthorized)
                        assertFalse(mutation.webServerReloadAuthorized)
                        println("PHASE11_70_PREPARATION_STATUS=${result.status.name}")
                        mark("STEP_06_READY_LIVE_PREFLIGHT_PRODUCED_ROLLBACK_AWARE_TRANSACTION_IDENTITY")
                    }

                    SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                        .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT -> {
                        assertFalse(result.mutationPreparationCreated)
                        assertNull(result.mutationPreparation)
                        println("PHASE11_70_PREPARATION_STATUS=${result.status.name}")
                        mark("STEP_06_BLOCKED_LIVE_PREFLIGHT_PRODUCED_NO_MUTATION_TRANSACTION")
                    }
                }
            } finally {
                val delete = secretStore.delete(secretId)
                assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
                config.closeSensitiveBytes()
                deleteTree(localRoot)
                runCatching { configFile.delete() }
                mark("STEP_07_LOCAL_CLEANUP_COMPLETE")
            }
        }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val base = 150_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_70_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft =
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_70_preflight_$nonce",
                evaluatedAtEpochMillis = base + 10L,
                requestedAuthorizationLifetimeMillis = 10_000L,
            )
        val preflightAuthorization =
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                preflightDraft,
                SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                    preflightDraft.approvalChallengeSha256,
                    true,
                ),
            )
        val preflightReceipt =
            application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
                preflightAuthorization,
                base + 11L,
            )
        val credentialDraft =
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_70_credential_$nonce",
                evaluatedAtEpochMillis = base + 20L,
                requestedAuthorizationLifetimeMillis = 10_000L,
            )
        val credentialAuthorization =
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                credentialDraft,
                SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    credentialDraft.approvalChallengeSha256,
                    true,
                ),
            )
        val credentialHandoff =
            application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                credentialAuthorization,
                base + 21L,
            )
        return (application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            credentialHandoff,
            access,
            base + 22L,
        ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved).also {
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
                .validateProof(it.proof)
        }
    }

    private fun prepare(
        root: Path,
        host: String,
        port: Int,
        targetRoot: String,
    ) = SiteDeployerLocalPreparationBoundary.prepare(
        SiteDeployerLocalPreparationRequest(
            rootSeed = DesignSeed(1170L),
            domain = "phase1170.example.com",
            servicePort = port,
            remoteHostIdentity = host,
            targetRoot = targetRoot,
            owner = "root",
            group = "root",
            reuseExisting3xUiCertificate = false,
        ),
        root,
    )

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) =
        SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce =
            InstrumentationRegistry.getArguments()
                .getString("phase11_70_run_nonce")
                ?.trim()
                .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_70Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_70_policy_bound_config_mutation_preparation_acceptance.properties"
    }
}

private class OneShotPhase11_70Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(
            password ?: error("Phase 11.70 password material is closed"),
        )

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_70Config {
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
                require(
                    host.isNotBlank() &&
                        username.isNotBlank() &&
                        hostKey.startsWith("SHA256:") &&
                        port in 1..65535,
                )
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_70Config(host, port, username, hostKey, password)
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun decodeUtf8(value: String): String {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            return try {
                bytes.toString(StandardCharsets.UTF_8)
            } finally {
                Arrays.fill(bytes, 0)
            }
        }
    }
}
