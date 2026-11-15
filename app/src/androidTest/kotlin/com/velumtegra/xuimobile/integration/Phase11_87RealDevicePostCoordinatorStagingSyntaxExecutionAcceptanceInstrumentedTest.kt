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
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingHandoff
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingHandoffStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus
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
class Phase11_87RealDevicePostCoordinatorStagingSyntaxExecutionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun postCoordinatorPreparedAuthorityExecutesOneBoundedStagingSyntaxTransactionWithoutReplay() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.87 one-shot real-VPS acceptance config is missing" }
            val config = OneShotPhase11_87Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_87_acceptance_credential")
            val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_87-")
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_87_access_$nonce"),
                    serverId = ServerId("phase11_87_server_$nonce"),
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
                    targetRoot = "/tmp/velum-p1187-${nonce.take(16)}",
                )
                val handoff = readyHandoff(preparation)
                val phase1184Admission =
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                        .admit(handoff)
                val preflightCredential = resolveFreshCredential(access, nonce, "preflight", 170_000L)
                val phase1184Execution =
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                        .observeOnce(
                            admission = phase1184Admission,
                            handoff = handoff,
                            freshResolutionProof = preflightCredential.proof,
                            freshCredentialLease = preflightCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_87_web_preflight_${nonce.take(16)}",
                            executedAtEpochMillis = preflightCredential.proof.resolvedAtEpochMillis + 10L,
                        )
                SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                    .validateExecutionResult(phase1184Execution)
                assertTrue(phase1184Execution.productionNetworkTouched)
                assertFalse(phase1184Execution.remoteMutationPerformed)
                assertFalse(phase1184Execution.coordinatorReinvoked)
                assertFalse(phase1184Execution.staticPublicationReplayPerformed)
                mark("STEP_03_EXACT_PHASE1183_TO_PHASE1184_PREFLIGHT_PROOF_READY")

                val priorPolicy = StrictMode.getThreadPolicy()
                val phase1185: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult
                val phase1186: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult
                val phase1187Admission: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    phase1185 =
                        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                            .prepare(
                                handoff = handoff,
                                phase1184Execution = phase1184Execution,
                                mutationTransactionId = "phase11_87_tx_${nonce.take(16)}",
                            )
                    phase1186 =
                        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                            .prepare(
                                handoff = handoff,
                                phase1184Execution = phase1184Execution,
                                phase1185Preparation = phase1185,
                            )
                    phase1187Admission =
                        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                            .admit(phase1186)
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                        .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
                    phase1186.status,
                )
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                        .READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
                    phase1187Admission.status,
                )
                assertTrue(phase1187Admission.realVpsExecutionEligible)
                assertTrue(phase1187Admission.requiresFreshCredentialResolution)
                assertTrue(phase1187Admission.requiresLiveRemoteHostKeyVerification)
                assertFalse(phase1187Admission.exactConfigActivationAuthorized)
                assertFalse(phase1187Admission.webServerReloadAuthorized)
                assertFalse(phase1187Admission.coordinatorReinvocationAuthorized)
                assertFalse(phase1187Admission.staticPublicationReplayAuthorized)
                assertFalse(phase1187Admission.automaticRetryAuthorized)
                mark("STEP_04_PHASE1185_PHASE1186_PHASE1187_LOCAL_BINDING_COMPLETE")

                val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()
                val stageCredential = resolveFreshCredential(access, nonce, "stage", 180_000L)
                val execution =
                    SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                        .executeOnce(
                            admission = phase1187Admission,
                            handoff = handoff,
                            phase1184Execution = phase1184Execution,
                            phase1185Preparation = phase1185,
                            phase1186AuthorityPreparation = phase1186,
                            freshResolutionProof = stageCredential.proof,
                            freshCredentialLease = stageCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_87_stage_syntax_${nonce.take(16)}",
                            executedAtEpochMillis = stageCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort =
                                application.siteProductionDeploymentReplayFence
                                    .realVpsWebServingConfigStagingSyntaxExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                    .validateExecutionResultAgainst(
                        result = execution,
                        admission = phase1187Admission,
                        handoff = handoff,
                        phase1184Execution = phase1184Execution,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
                    .validateProof(execution.phase1172ExecutionResult.phase11_59ExecutionProof)
                val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount + 1,
                    afterFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount,
                )
                mark("STEP_05_ONE_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION_COMPLETE")

                assertEquals(
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus
                        .EXECUTED_AND_CLEANED_WITHOUT_CONFIG_ACTIVATION_OR_COORDINATOR_REPLAY,
                    execution.status,
                )
                assertEquals(phase1187Admission.admissionSha256, execution.phase1187AdmissionSha256)
                assertEquals(phase1186.authorityPreparationResultSha256, execution.phase1186AuthorityPreparationResultSha256)
                assertEquals(handoff.handoffSha256, execution.phase1183HandoffSha256)
                assertEquals(phase1184Execution.executionResultSha256, execution.phase1184ExecutionResultSha256)
                assertEquals(phase1185.preparationResultSha256, execution.phase1185PreparationResultSha256)
                assertEquals(SiteWebServingProtocol.HTTP, execution.selectedProtocol)
                assertTrue(execution.exactPostCoordinatorChainBindingVerified)
                assertTrue(execution.durableBaselineCheckpointRecorded)
                assertTrue(execution.credentialLeaseMaterialConsumed)
                assertTrue(execution.productionNetworkTouched)
                assertTrue(execution.liveHostKeyPinVerified)
                assertTrue(execution.operationOwnedStagingWritePerformed)
                assertTrue(execution.operationOwnedValidationWritePerformed)
                assertTrue(execution.nginxSyntaxValidationPassed)
                assertTrue(execution.operationOwnedCleanupVerified)
                assertFalse(execution.exactConfigActivationPerformed)
                assertFalse(execution.webServerReloadPerformed)
                assertFalse(execution.coordinatorReinvoked)
                assertFalse(execution.staticPublicationReplayPerformed)
                assertFalse(execution.automaticRetryPerformed)
                assertEquals(7, execution.phase1172ExecutionResult.phase11_59ExecutionProof.remoteCommandCount)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.exactConfigPathAbsentAfterValidation)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.listenerStillFreeAfterValidation)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.stagingConfigAbsentAfterCleanup)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.validationConfigAbsentAfterCleanup)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.validationPidAbsentAfterCleanup)
                println("PHASE11_87_EXECUTION_STATUS=${execution.status.name}")
                mark("STEP_06_EXACT_POST_COORDINATOR_CHAIN_DURABLE_FENCE_AND_CLEANUP_VERIFIED")
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
        suffix: String,
        base: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        require(Regex("^[a-z][a-z0-9_-]{2,15}$").matches(suffix))
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_87_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_87_${suffix}_preflight_$nonce",
            evaluatedAtEpochMillis = base + 10L,
            requestedAuthorizationLifetimeMillis = 10_000L,
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
            authorizationAttemptId = "phase11_87_${suffix}_credential_$nonce",
            evaluatedAtEpochMillis = base + 20L,
            requestedAuthorizationLifetimeMillis = 10_000L,
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

    private fun prepare(
        root: Path,
        host: String,
        targetRoot: String,
    ) = SiteDeployerLocalPreparationBoundary.prepare(
        SiteDeployerLocalPreparationRequest(
            rootSeed = DesignSeed(11870L),
            domain = "phase1187.example.com",
            servicePort = 58487,
            remoteHostIdentity = host,
            targetRoot = targetRoot,
            owner = "root",
            group = "root",
            reuseExisting3xUiCertificate = false,
        ),
        root,
    )

    private fun readyHandoff(
        preparation: SiteDeployerLocalPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorServingHandoff {
        val evidence = SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )
        val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
            preparation = preparation,
            staticPublicationEvidence = evidence,
        )
        val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
            contractVersion = 1,
            status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
            phase1180AdmissionSha256 = "a".repeat(64),
            phase1180ExecutionResultSha256 = "b".repeat(64),
            localPreparationSha256 = preparation.preparationSha256,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            staticPublicationEvidence = evidence,
            servingPolicySelection = selection,
            servingPolicySelectionSha256 = selection.selectionSha256,
            requiresFreshPolicyBoundWebServingPreflight = true,
            authorizesWebServingNetworkExecution = false,
            authorizesWebServingMutation = false,
            authorizesCoordinatorReinvocation = false,
            automaticRetryAuthorized = false,
            handoffSha256 = "",
        )
        return base.copy(
            handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                .handoffSha256ForTest(base),
        )
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
            .getString("phase11_87_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_87Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_87_post_coordinator_staging_syntax_execution_acceptance.properties"
    }
}

private class OneShotPhase11_87Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(
            password ?: error("Phase 11.87 password material is closed"),
        )

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_87Config {
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
                return OneShotPhase11_87Config(host, port, username, hostKey, password)
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
