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
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
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
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_71RealDevicePolicyBoundStagingSyntaxAuthorityPreparationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun readyPhase1170MustBindExactTransactionBeforeBoundedStagingSyntaxAuthorityCanBePrepared() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.71 one-shot real-VPS acceptance config is missing" }
            val config = OneShotPhase11_71Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_71_acceptance_credential")
            val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_71-")
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_71_access_$nonce"),
                    serverId = ServerId("phase11_71_server_$nonce"),
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
                    port = 58482,
                    targetRoot = "/tmp/velum-p1171-${nonce.take(16)}",
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
                            executionAttemptId = "phase11_71_web_preflight_${nonce.take(16)}",
                            executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                        )
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .validateExecutionResult(execution)
                mark("STEP_04_POLICY_BOUND_REAL_VPS_READ_ONLY_PREFLIGHT_COMPLETE")

                val priorPolicy = StrictMode.getThreadPolicy()
                val phase1170: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult
                val result: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    phase1170 =
                        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                            .prepare(
                                selection = selection,
                                policyBoundPreflightExecution = execution,
                                mutationTransactionId = "phase11_71_tx_${nonce.take(16)}",
                            )
                    SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                        .validateAgainst(phase1170, selection, execution)
                    result =
                        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                            .prepare(
                                selection = selection,
                                policyBoundPreflightExecution = execution,
                                policyBoundConfigMutationPreparation = phase1170,
                            )
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .validateAgainst(result, selection, execution, phase1170)
                mark("STEP_05_PHASE11_70_IDENTITY_BOUND_TO_ZERO_NETWORK_STAGING_SYNTAX_AUTHORITY_PREPARATION")

                assertEquals(
                    SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                        .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY,
                    phase1170.status,
                )
                assertEquals(
                    SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                        .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                    result.status,
                )
                assertEquals(selection.selectionSha256, result.servingPolicySelectionSha256)
                assertEquals(
                    execution.executionResultSha256,
                    result.policyBoundPreflightExecutionResultSha256,
                )
                assertEquals(
                    phase1170.preparationResultSha256,
                    result.policyBoundConfigMutationPreparationResultSha256,
                )
                assertEquals(execution.publicationPlanSha256, result.publicationPlanSha256)
                assertEquals(execution.selectedProtocol, result.selectedProtocol)
                assertEquals(
                    execution.preflightExecutionProof.preflightReport.preflightSha256,
                    result.readOnlyPreflightSha256,
                )
                assertEquals(phase1170.mutationTransactionId, result.mutationTransactionId)
                assertEquals(
                    phase1170.mutationPreparation?.mutationPreparationSha256,
                    result.mutationPreparationSha256,
                )
                assertTrue(result.exactPolicyPreparationBindingVerified)
                assertTrue(result.stagingSyntaxExecutionPlanCreated)
                assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
                assertFalse(result.remoteMutationPerformed)
                assertTrue(result.stagingConfigWriteAuthorized)
                assertTrue(result.validationConfigWriteAuthorized)
                assertTrue(result.isolatedNginxSyntaxValidationAuthorized)
                assertFalse(result.exactConfigActivationAuthorized)
                assertFalse(result.webServerReloadAuthorized)
                assertFalse(result.certificateMutationAuthorized)
                assertFalse(result.dnsMutationAuthorized)
                assertFalse(result.firewallMutationAuthorized)
                assertFalse(result.packageInstallAuthorized)
                assertFalse(result.privateKeyContentReadAuthorized)
                assertFalse(result.automaticRetryAuthorized)
                assertFalse(result.coordinatorInvoked)
                assertFalse(result.exposesDeployUiAction)

                val plan = requireNotNull(result.stagingSyntaxExecutionPlan)
                val mutation = requireNotNull(phase1170.mutationPreparation)
                SiteWebServingConfigMutationPreparationBoundary.validate(mutation)
                SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
                    plan = plan,
                    preparation = mutation,
                    publicationPlan = requireNotNull(selection.publicationPlan),
                    readOnlyPreflight = execution.preflightExecutionProof.preflightReport,
                )
                assertEquals(result.mutationTransactionId, plan.mutationTransactionId)
                assertEquals(result.mutationPreparationSha256, plan.mutationPreparationSha256)
                assertTrue(plan.stagingConfigWriteAuthorized)
                assertTrue(plan.validationConfigWriteAuthorized)
                assertTrue(plan.isolatedNginxSyntaxValidationAuthorized)
                assertFalse(plan.exactConfigActivationAuthorized)
                assertFalse(plan.webServerReloadAuthorized)
                println("PHASE11_71_AUTHORITY_PREPARATION_STATUS=${result.status.name}")
                mark("STEP_06_READY_PHASE11_70_PRODUCED_EXACT_BOUNDED_PHASE11_59_EXECUTION_PLAN")
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
            admissionAttemptId = "phase11_71_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft =
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_71_preflight_$nonce",
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
                authorizationAttemptId = "phase11_71_credential_$nonce",
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
            rootSeed = DesignSeed(1171L),
            domain = "phase1171.example.com",
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
                .getString("phase11_71_run_nonce")
                ?.trim()
                .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_71Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_71_policy_bound_config_mutation_preparation_acceptance.properties"
    }
}

private class OneShotPhase11_71Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(
            password ?: error("Phase 11.71 password material is closed"),
        )

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_71Config {
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
                return OneShotPhase11_71Config(host, port, username, hostKey, password)
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
