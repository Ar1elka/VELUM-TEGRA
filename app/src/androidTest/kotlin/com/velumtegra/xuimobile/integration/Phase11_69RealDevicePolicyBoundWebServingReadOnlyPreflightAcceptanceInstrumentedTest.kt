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
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityObservation
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityTrust
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightCheckCode
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCertificatePublicationCompositionGate
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
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
class Phase11_69RealDevicePolicyBoundWebServingReadOnlyPreflightAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun servingPolicySelectionMustBindExactPlanBeforeRealVpsReadOnlyPreflightAndBlockedReuseNeverTouchesNetwork() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.69 one-shot real-VPS acceptance config is missing" }
            val config = OneShotPhase11_69Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_69_acceptance_credential")
            val httpRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_69-http-")
            val reuseRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_69-reuse-")
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_69_access_$nonce"),
                    serverId = ServerId("phase11_69_server_$nonce"),
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

                val httpPreparation = prepare(
                    root = httpRoot,
                    reuse = false,
                    host = config.host,
                    port = 58479,
                    targetRoot = "/tmp/velum-p1169-${nonce.take(16)}",
                    seed = 11690L,
                )
                val httpEvidence = evidence(httpPreparation)
                val httpSelection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                    preparation = httpPreparation,
                    staticPublicationEvidence = httpEvidence,
                )
                val httpAdmission =
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(httpSelection)
                assertEquals(
                    SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                        .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
                    httpAdmission.status,
                )
                assertEquals(SiteWebServingProtocol.HTTP, httpAdmission.selectedProtocol)
                assertFalse(httpAdmission.productionNetworkTouchedByAdmission)
                mark("STEP_03_EXPLICIT_HTTP_POLICY_BOUND_TO_EXACT_PREFLIGHT_ADMISSION")

                val reusePreparation = prepare(
                    root = reuseRoot,
                    reuse = true,
                    host = config.host,
                    port = 58480,
                    targetRoot = "/tmp/velum-p1169-reuse-${nonce.take(12)}",
                    seed = 11691L,
                )
                val reuseEvidence = evidence(reusePreparation)
                val priorPolicy = StrictMode.getThreadPolicy()
                val blockedAdmission = try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    val blockedComposition =
                        SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                            preparation = reusePreparation,
                            staticPublicationEvidence = reuseEvidence,
                            eligibilityReport = noConfiguredCertificateReport(config.host),
                            observedRemoteHostIdentity = config.host,
                            realVpsExecutionProofSha256 = "c".repeat(64),
                        )
                    val blockedSelection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                        preparation = reusePreparation,
                        staticPublicationEvidence = reuseEvidence,
                        certificateComposition = blockedComposition,
                    )
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(blockedSelection)
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                assertEquals(
                    SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                        .BLOCKED_BY_EXPLICIT_SERVING_POLICY,
                    blockedAdmission.status,
                )
                assertFalse(blockedAdmission.readOnlyPreflightExecutionEligible)
                assertNull(blockedAdmission.publicationPlanSha256)
                assertNull(blockedAdmission.remoteHostIdentity)
                assertFalse(blockedAdmission.productionNetworkTouchedByAdmission)
                mark("STEP_04_BLOCKED_REUSE_STOPPED_LOCALLY_BEFORE_NETWORK")

                val resolved = resolveFreshCredential(access, nonce)
                val execution =
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.observeOnce(
                        admission = httpAdmission,
                        selection = httpSelection,
                        freshResolutionProof = resolved.proof,
                        freshCredentialLease = resolved.lease,
                        serverAccess = access,
                        executionAttemptId = "phase11_69_web_preflight_${nonce.take(16)}",
                        executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                    )
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .validateExecutionResult(execution)
                SiteWebServingReadOnlyPreflightBoundary.validateReport(
                    execution.preflightExecutionProof.preflightReport,
                )
                mark("STEP_05_POLICY_BOUND_REAL_VPS_READ_ONLY_PREFLIGHT_COMPLETE")

                assertEquals(httpSelection.selectionSha256, execution.servingPolicySelectionSha256)
                assertEquals(httpAdmission.admissionSha256, execution.admissionSha256)
                assertEquals(httpSelection.publicationPlan?.publicationPlanSha256, execution.publicationPlanSha256)
                assertEquals(SiteWebServingProtocol.HTTP, execution.selectedProtocol)
                assertTrue(execution.exactPolicyPlanBindingVerified)
                assertTrue(execution.freshCredentialProofRequired)
                assertTrue(execution.liveHostKeyVerified)
                assertFalse(execution.remoteMutationPerformed)
                assertFalse(execution.configMutationAuthorized)
                assertFalse(execution.webServerReloadAuthorized)
                assertFalse(execution.dnsMutationAuthorized)
                assertFalse(execution.firewallMutationAuthorized)
                assertFalse(execution.packageInstallAuthorized)
                assertFalse(execution.privateKeyContentReadPerformed)
                assertFalse(execution.automaticRetryPerformed)
                assertFalse(execution.coordinatorInvoked)
                assertFalse(execution.exposesDeployUiAction)

                val proof = execution.preflightExecutionProof
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
                println("PHASE11_69_PREFLIGHT_STATUS=${execution.preflightStatus.name}")
                mark("STEP_06_EXACT_PLAN_AND_LIVE_PROOF_BOUND_WITH_NO_MUTATION_AUTHORITY")
            } finally {
                val delete = secretStore.delete(secretId)
                assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
                config.closeSensitiveBytes()
                deleteTree(httpRoot)
                deleteTree(reuseRoot)
                runCatching { configFile.delete() }
                mark("STEP_07_LOCAL_CLEANUP_COMPLETE")
            }
        }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val base = 140_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_69_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_69_preflight_$nonce",
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
            authorizationAttemptId = "phase11_69_credential_$nonce",
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
        reuse: Boolean,
        host: String,
        port: Int,
        targetRoot: String,
        seed: Long,
    ) = SiteDeployerLocalPreparationBoundary.prepare(
        SiteDeployerLocalPreparationRequest(
            rootSeed = DesignSeed(seed),
            domain = "phase1169.example.com",
            servicePort = port,
            remoteHostIdentity = host,
            targetRoot = targetRoot,
            owner = "root",
            group = "root",
            reuseExisting3xUiCertificate = reuse,
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

    private fun noConfiguredCertificateReport(host: String) =
        SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
            plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(host),
            trust = SiteExisting3xUiCertificateReuseEligibilityTrust("7".repeat(64)),
            observation = SiteExisting3xUiCertificateReuseEligibilityObservation(
                remoteHostIdentity = host,
                verifiedHostKeySha256 = "7".repeat(64),
                databasePath = SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH,
                databasePathType = SiteWebServingObservedPathType.FILE,
                sqliteReadOnlyAvailable = true,
                certificatePath = null,
                privateKeyPath = null,
                certificatePathType = null,
                privateKeyPathType = null,
                certificateSha256 = null,
                certificateDnsNames = emptyList(),
                certificateNotBeforeEpochMillis = null,
                certificateNotAfterEpochMillis = null,
                remoteCommandCount = 1,
                mutationOperationPerformed = false,
                arbitraryCommandAccepted = false,
                privateKeyContentReadPerformed = false,
            ),
            observedAtEpochMillis = Instant.parse("2026-10-04T00:00:00Z").toEpochMilli(),
        )

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_69_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_69Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_69_policy_bound_web_serving_read_only_preflight_acceptance.properties"
    }
}

private class OneShotPhase11_69Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.69 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_69Config {
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
                return OneShotPhase11_69Config(host, port, username, hostKey, password)
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
