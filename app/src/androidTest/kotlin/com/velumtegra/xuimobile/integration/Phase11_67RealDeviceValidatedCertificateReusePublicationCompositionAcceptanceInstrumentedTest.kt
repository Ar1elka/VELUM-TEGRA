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
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCertificatePublicationCompositionGate
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCertificatePublicationCompositionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
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
class Phase11_67RealDeviceValidatedCertificateReusePublicationCompositionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun realVpsEligibilityProofMustPassExactDomainBindingBeforeHttpsPublicationPlanCanBeSelected() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.67 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_67Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_67_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_67-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_67_access_$nonce"),
                serverId = ServerId("phase11_67_server_$nonce"),
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

            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1167L),
                    domain = "site.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = config.host,
                    targetRoot = "/srv/www/velum-phase11-67",
                    owner = "www_data",
                    group = "www_data",
                    reuseExisting3xUiCertificate = true,
                ),
                localRoot,
            )
            val staticEvidence = SiteStaticPublicationEvidence(
                preparationSha256 = preparation.preparationSha256,
                remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
                targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                committedClean = true,
                remoteResidualStateClean = true,
            )
            val eligibilityPlan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(config.host)
            mark("STEP_03_LOCAL_COMPOSITION_INPUTS_READY")

            val resolved = resolveFreshCredential(access, nonce)
            val proof = application.siteProductionDeploymentObserveRealVpsExisting3xUiCertificateReuseEligibilityOnce(
                plan = eligibilityPlan,
                freshResolutionProof = resolved.proof,
                freshCredentialLease = resolved.lease,
                serverAccess = access,
                executionAttemptId = "phase11_67_cert_proof_${nonce.take(16)}",
                executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
            )
            mark("STEP_04_REAL_VPS_READ_ONLY_ELIGIBILITY_PROOF_COMPLETE")

            val priorPolicy = StrictMode.getThreadPolicy()
            val composition = try {
                StrictMode.setThreadPolicy(
                    StrictMode.ThreadPolicy.Builder(priorPolicy)
                        .detectNetwork()
                        .penaltyDeath()
                        .build(),
                )
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.compose(
                    preparation = preparation,
                    staticPublicationEvidence = staticEvidence,
                    eligibilityExecutionProof = proof,
                )
            } finally {
                StrictMode.setThreadPolicy(priorPolicy)
            }
            SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.validate(composition)
            mark("STEP_05_VALIDATED_PROOF_BOUND_BEFORE_PUBLICATION_PLAN_SELECTION")

            assertTrue(composition.realVpsExecutionProofValidated)
            assertFalse(composition.productionNetworkTouchedByComposition)
            assertFalse(composition.remoteMutationPerformed)
            assertFalse(composition.certificateMutationAuthorized)
            assertFalse(composition.tlsConfigurationAuthorized)
            assertFalse(composition.nginxMutationAuthorized)
            assertFalse(composition.dnsMutationAuthorized)
            assertFalse(composition.firewallMutationAuthorized)
            assertFalse(composition.packageInstallAuthorized)
            assertFalse(composition.privateKeyContentReadAuthorized)
            assertFalse(composition.automaticRetryAuthorized)
            assertFalse(composition.coordinatorInvoked)
            assertFalse(composition.exposesDeployUiAction)

            when (composition.status) {
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE -> {
                    val publicationPlan = requireNotNull(composition.publicationPlan)
                    assertTrue(composition.publicationPlanSelected)
                    assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, publicationPlan.protocol)
                    assertEquals("site.example.com", publicationPlan.domain)
                    assertEquals(config.host, publicationPlan.remoteHostIdentity)
                    println("PHASE11_67_COMPOSITION_STATUS=${composition.status.name}")
                    mark("STEP_06_HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_CERTIFICATE")
                }
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE -> {
                    assertNull(composition.publicationPlan)
                    assertFalse(composition.publicationPlanSelected)
                    println("PHASE11_67_COMPOSITION_STATUS=${composition.status.name}")
                    mark("STEP_06_NO_CONFIGURED_PANEL_CERTIFICATE_REMAINS_FAIL_CLOSED")
                }
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN -> {
                    assertNull(composition.publicationPlan)
                    assertFalse(composition.publicationPlanSelected)
                    println("PHASE11_67_COMPOSITION_STATUS=${composition.status.name}")
                    mark("STEP_06_WRONG_DOMAIN_CERTIFICATE_REMAINS_FAIL_CLOSED")
                }
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION -> {
                    error("Unexpected Phase 11.67 reconciliation block")
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
        val base = 130_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_67_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_67_preflight_$nonce",
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
            authorizationAttemptId = "phase11_67_credential_$nonce",
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
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_67_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_67Diag", step) }

    private fun deleteTree(root: java.nio.file.Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_67_validated_certificate_reuse_publication_composition_acceptance.properties"
    }
}

private class OneShotPhase11_67Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.67 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_67Config {
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
                return OneShotPhase11_67Config(host, port, username, hostKey, password)
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
