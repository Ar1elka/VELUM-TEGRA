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
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightCheckCode
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimePrerequisiteBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimePrerequisiteStatus
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingRuntimePrerequisiteExecutionBoundary
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
class Phase11_59ARealDeviceRealVpsWebServingRuntimePrerequisiteAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun missingNginxIsClassifiedAsSeparateSupportedAptProvisioningPrerequisiteWithoutMutation() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.59A one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_59AConfig.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_59a_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_59a-plan-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_59a_access_$nonce"),
                serverId = ServerId("phase11_59a_server_$nonce"),
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

            val localPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11591L),
                    domain = "phase1159a.example.com",
                    servicePort = 58474,
                    remoteHostIdentity = config.host,
                    targetRoot = "/tmp/velum-p1159a-${nonce.take(16)}",
                    owner = "root",
                    group = "root",
                    reuseExisting3xUiCertificate = false,
                ),
                localRoot,
            )
            val publicationPlan = SiteWebServingPublicationPlanBoundary.prepare(
                SiteWebServingPublicationPlanRequest(
                    preparation = localPreparation,
                    staticPublicationEvidence = SiteStaticPublicationEvidence(
                        preparationSha256 = localPreparation.preparationSha256,
                        remoteHostIdentity = localPreparation.remoteDeployPlan.remoteHostIdentity,
                        targetRoot = localPreparation.remoteDeployPlan.publish.targetRoot,
                        finalTargetTreeSha256 = localPreparation.remoteDeployPlan.sourceTreeSha256,
                        committedClean = true,
                        remoteResidualStateClean = true,
                    ),
                    strategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
                    certificateReference = null,
                ),
            )
            mark("STEP_03_EXACT_PUBLICATION_PLAN_READY")

            val baselineCredential = resolveFreshCredential(access, nonce, "baseline", 210_000L)
            val baseline = application.siteProductionDeploymentObserveRealVpsWebServingReadOnlyPreflightOnce(
                plan = publicationPlan,
                freshResolutionProof = baselineCredential.proof,
                freshCredentialLease = baselineCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_59a_baseline_${nonce.take(18)}",
                executedAtEpochMillis = baselineCredential.proof.resolvedAtEpochMillis + 10L,
            )
            SiteWebServingReadOnlyPreflightBoundary.validateReport(baseline.preflightReport)
            assertEquals(
                SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                baseline.preflightReport.status,
            )
            val failedChecks = baseline.preflightReport.checks.filterNot { it.passed }.map { it.code }.toSet()
            assertEquals(
                setOf(
                    SiteWebServingReadOnlyPreflightCheckCode.NGINX_EXECUTABLE,
                    SiteWebServingReadOnlyPreflightCheckCode.NGINX_CONF_D_DIRECTORY,
                ),
                failedChecks,
            )
            assertTrue(
                baseline.preflightReport.checks
                    .first { it.code == SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT }
                    .passed,
            )
            assertTrue(
                baseline.preflightReport.checks
                    .first { it.code == SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE }
                    .passed,
            )
            mark("STEP_04_EXACT_MISSING_NGINX_GAP_CONFIRMED")

            val prerequisiteCredential = resolveFreshCredential(access, nonce, "prereq", 230_000L)
            val proof = application.siteProductionDeploymentObserveRealVpsWebServingRuntimePrerequisiteOnce(
                plan = publicationPlan,
                sourcePreflight = baseline.preflightReport,
                freshResolutionProof = prerequisiteCredential.proof,
                freshCredentialLease = prerequisiteCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_59a_prereq_${nonce.take(18)}",
                executedAtEpochMillis = prerequisiteCredential.proof.resolvedAtEpochMillis + 10L,
            )
            SiteProductionDeploymentAndroidRealVpsWebServingRuntimePrerequisiteExecutionBoundary.validateProof(proof)
            SiteWebServingRuntimePrerequisiteBoundary.validateReport(proof.prerequisiteReport)
            mark("PREREQ_STATUS=${proof.prerequisiteReport.status.name}")
            mark("PREREQ_PROVISIONING_PREPARATION_ELIGIBLE=${proof.prerequisiteReport.provisioningPreparationEligible}")
            assertEquals(
                SiteWebServingRuntimePrerequisiteStatus.SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED,
                proof.prerequisiteReport.status,
            )
            assertTrue(proof.prerequisiteReport.provisioningPreparationEligible)
            assertFalse(proof.prerequisiteReport.packageInstallAuthorized)
            assertFalse(proof.prerequisiteReport.configMutationAuthorized)
            assertFalse(proof.prerequisiteReport.webServerReloadAuthorized)
            assertFalse(proof.prerequisiteReport.dnsMutationAuthorized)
            assertFalse(proof.prerequisiteReport.firewallMutationAuthorized)
            assertFalse(proof.prerequisiteReport.automaticRetryAuthorized)
            assertEquals(6, proof.remoteCommandCount)
            assertTrue(proof.credentialLeaseMaterialConsumed)
            assertTrue(proof.productionNetworkTouched)
            assertTrue(proof.hostKeyPinVerifiedAgainstRemote)
            assertTrue(proof.exactSessionRegistryUsed)
            assertFalse(proof.mutationOperationPerformed)
            assertFalse(proof.arbitraryCommandAccepted)
            assertFalse(proof.privateKeyContentReadPerformed)
            assertFalse(proof.configMutationPerformed)
            assertFalse(proof.webServerReloadPerformed)
            assertFalse(proof.dnsMutationPerformed)
            assertFalse(proof.firewallMutationPerformed)
            assertFalse(proof.packageInstallPerformed)
            assertFalse(proof.automaticRetryPerformed)
            assertTrue(proof.sessionClosed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            mark("STEP_05_SUPPORTED_APT_PROVISIONING_PREREQUISITE_CLASSIFIED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localRoot)
            runCatching { configFile.delete() }
            mark("STEP_06_LOCAL_CLEANUP_COMPLETE")
        }
    }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
        suffix: String,
        base: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_59a_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_59a_${suffix}_preflight_$nonce",
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
            authorizationAttemptId = "phase11_59a_${suffix}_credential_$nonce",
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

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_59a_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_59ADiag", step) }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_59a_real_vps_web_serving_runtime_prerequisite_acceptance.properties"
    }
}

private class OneShotPhase11_59AConfig private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.59A password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_59AConfig {
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
                return OneShotPhase11_59AConfig(host, port, username, hostKey, password)
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
