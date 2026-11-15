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
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightCheckCode
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingHandoff
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingHandoffStatus
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
class Phase11_84RealDevicePostCoordinatorPolicyBoundPreflightAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun postCoordinatorHandoffConsumesFreshCredentialAndRunsPolicyBoundPreflightWithoutCoordinatorReplay() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.84 one-shot real-VPS acceptance config is missing" }
            val config = OneShotPhase11_84Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_84_acceptance_credential")
            val root = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_84-")
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_84_access_$nonce"),
                    serverId = ServerId("phase11_84_server_$nonce"),
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
                    root = root,
                    host = config.host,
                    targetRoot = "/tmp/velum-p1184-${nonce.take(16)}",
                )
                val handoff = readyHandoff(preparation)

                val priorPolicy = StrictMode.getThreadPolicy()
                val admission = try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(handoff)
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus
                        .READY_FOR_FRESH_POLICY_BOUND_READ_ONLY_PREFLIGHT,
                    admission.status,
                )
                assertEquals(handoff.handoffSha256, admission.phase1183HandoffSha256)
                assertEquals(SiteWebServingProtocol.HTTP, admission.selectedProtocol)
                assertTrue(admission.requiresFreshCredentialResolution)
                assertFalse(admission.authorizesCoordinatorReinvocation)
                assertFalse(admission.authorizesStaticPublicationReplay)
                assertFalse(admission.authorizesWebServingMutation)
                mark("STEP_03_PHASE1183_HANDOFF_BOUND_LOCALLY_TO_EXACT_PHASE1169_ADMISSION")

                val blocked = blockedRollbackHandoff(preparation)
                var blockedRejected = false
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(blocked)
                } catch (_: IllegalArgumentException) {
                    blockedRejected = true
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                assertTrue(blockedRejected)
                mark("STEP_04_BLOCKED_PHASE1183_HANDOFF_STOPPED_BEFORE_NETWORK")

                val resolved = resolveFreshCredential(access, nonce)
                mark("STEP_05_FRESH_CREDENTIAL_LEASE_RESOLVED")

                val execution =
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.observeOnce(
                        admission = admission,
                        handoff = handoff,
                        freshResolutionProof = resolved.proof,
                        freshCredentialLease = resolved.lease,
                        serverAccess = access,
                        executionAttemptId = "phase11_84_web_preflight_${nonce.take(16)}",
                        executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                    )
                SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                    .validateExecutionResult(execution)
                SiteWebServingReadOnlyPreflightBoundary.validateReport(
                    execution.phase1169ExecutionResult.preflightExecutionProof.preflightReport,
                )
                mark("STEP_06_FRESH_POLICY_BOUND_REAL_VPS_READ_ONLY_PREFLIGHT_COMPLETE")

                assertEquals(handoff.handoffSha256, execution.phase1183HandoffSha256)
                assertEquals(handoff.phase1180ExecutionResultSha256, execution.phase1180ExecutionResultSha256)
                assertEquals(admission.admissionSha256, execution.phase1184AdmissionSha256)
                assertEquals(admission.phase1169Admission.admissionSha256, execution.phase1169AdmissionSha256)
                assertEquals(admission.publicationPlanSha256, execution.publicationPlanSha256)
                assertEquals(SiteWebServingProtocol.HTTP, execution.selectedProtocol)
                assertTrue(execution.productionNetworkTouched)
                assertFalse(execution.remoteMutationPerformed)
                assertFalse(execution.coordinatorReinvoked)
                assertFalse(execution.staticPublicationReplayPerformed)
                assertFalse(execution.automaticRetryPerformed)

                val phase1169 = execution.phase1169ExecutionResult
                assertTrue(phase1169.liveHostKeyVerified)
                assertFalse(phase1169.remoteMutationPerformed)
                assertFalse(phase1169.coordinatorInvoked)
                assertFalse(phase1169.automaticRetryPerformed)
                val proof = phase1169.preflightExecutionProof
                assertTrue(proof.productionNetworkTouched)
                assertTrue(proof.sessionClosed)
                assertFalse(proof.mutationOperationPerformed)
                assertFalse(proof.privateKeyContentReadPerformed)
                assertFalse(proof.automaticRetryPerformed)
                val checks = proof.preflightReport.checks.associateBy { it.code }
                assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.REMOTE_HOST_IDENTITY).passed)
                assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.VERIFIED_HOST_KEY).passed)
                assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT).passed)
                assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE).passed)
                println("PHASE11_84_PREFLIGHT_STATUS=${execution.preflightStatus.name}")
                mark("STEP_07_EXACT_POST_COORDINATOR_CHAIN_PROVED_WITHOUT_REPLAY_OR_MUTATION")
            } finally {
                val delete = secretStore.delete(secretId)
                assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
                config.closeSensitiveBytes()
                deleteTree(root)
                runCatching { configFile.delete() }
                mark("STEP_08_LOCAL_CLEANUP_COMPLETE")
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
            admissionAttemptId = "phase11_84_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_84_preflight_$nonce",
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
            authorizationAttemptId = "phase11_84_credential_$nonce",
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
            rootSeed = DesignSeed(11840L),
            domain = "phase1184.example.com",
            servicePort = 58484,
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
        val evidence = evidence(preparation)
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

    private fun blockedRollbackHandoff(
        preparation: SiteDeployerLocalPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorServingHandoff {
        val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
            contractVersion = 1,
            status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .BLOCKED_COORDINATOR_ROLLED_BACK_CLEAN,
            phase1180AdmissionSha256 = "c".repeat(64),
            phase1180ExecutionResultSha256 = "d".repeat(64),
            localPreparationSha256 = preparation.preparationSha256,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            staticPublicationEvidence = null,
            servingPolicySelection = null,
            servingPolicySelectionSha256 = null,
            requiresFreshPolicyBoundWebServingPreflight = false,
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
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_84_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_84Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_84_post_coordinator_policy_bound_preflight_acceptance.properties"
    }
}

private class OneShotPhase11_84Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.84 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_84Config {
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
                return OneShotPhase11_84Config(host, port, username, hostKey, password)
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
