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
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityCheckCode
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_65RealDeviceExisting3xUiCertificateReuseEligibilityAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun existing3xUiCertificateIsDiscoveredAndProvenReusableWithoutPrivateKeyReadOrMutation() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.65 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_65Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_65_acceptance_credential")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_65_access_$nonce"),
                serverId = ServerId("phase11_65_server_$nonce"),
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

            val plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(config.host)
            assertEquals("/etc/x-ui/x-ui.db", plan.databasePath)
            assertTrue(plan.sqliteReadOnlyQueryAuthorized)
            assertTrue(plan.publicCertificateMetadataReadAuthorized)
            assertTrue(plan.privateKeyPresenceProbeAuthorized)
            assertFalse(plan.privateKeyContentReadAuthorized)
            assertFalse(plan.certificateMutationAuthorized)
            assertFalse(plan.tlsConfigurationAuthorized)
            mark("STEP_03_CERTIFICATE_REUSE_ELIGIBILITY_PLAN_READY")

            val resolved = resolveFreshCredential(access, nonce)
            val proof = application.siteProductionDeploymentObserveRealVpsExisting3xUiCertificateReuseEligibilityOnce(
                plan = plan,
                freshResolutionProof = resolved.proof,
                freshCredentialLease = resolved.lease,
                serverAccess = access,
                executionAttemptId = "phase11_65_cert_reuse_${nonce.take(16)}",
                executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
            )
            SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary.validateProof(proof)
            SiteExisting3xUiCertificateReuseEligibilityBoundary.validateReport(proof.eligibilityReport)
            mark("STEP_04_REAL_VPS_CERTIFICATE_READ_ONLY_OBSERVATION_COMPLETE")

            assertTrue(proof.remoteCommandCount in 1..3)
            assertTrue(proof.credentialLeaseMaterialConsumed)
            assertTrue(proof.productionNetworkTouched)
            assertTrue(proof.hostKeyPinVerifiedAgainstRemote)
            assertTrue(proof.exactSessionRegistryUsed)
            assertTrue(proof.sessionClosed)
            assertFalse(proof.mutationOperationPerformed)
            assertFalse(proof.arbitraryCommandAccepted)
            assertFalse(proof.privateKeyContentReadPerformed)
            assertFalse(proof.certificateMutationPerformed)
            assertFalse(proof.tlsConfigurationPerformed)
            assertFalse(proof.dnsMutationPerformed)
            assertFalse(proof.firewallMutationPerformed)
            assertFalse(proof.packageInstallPerformed)
            assertFalse(proof.automaticRetryPerformed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)

            val report = proof.eligibilityReport
            val checks = report.checks.associateBy { it.code }
            assertTrue(checks.getValue(SiteExisting3xUiCertificateReuseEligibilityCheckCode.REMOTE_HOST_IDENTITY).passed)
            assertTrue(checks.getValue(SiteExisting3xUiCertificateReuseEligibilityCheckCode.VERIFIED_HOST_KEY).passed)
            assertTrue(checks.getValue(SiteExisting3xUiCertificateReuseEligibilityCheckCode.XUI_DATABASE_REGULAR_FILE).passed)
            assertTrue(checks.getValue(SiteExisting3xUiCertificateReuseEligibilityCheckCode.SQLITE_READ_ONLY_AVAILABLE).passed)
            val failedChecks = report.checks.filterNot { it.passed }
            val failedCheckCodes = failedChecks.joinToString(",") { it.code.name }.ifBlank { "NONE" }
            Log.i("Phase11_65Diag", "FAILED_CHECK_CODES=$failedCheckCodes")
            when (report.status) {
                SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING -> {
                    assertTrue(report.checks.all { it.passed })
                    val reference = requireNotNull(report.certificateReference)
                    assertEquals(config.host, reference.remoteHostIdentity)
                    assertTrue(reference.certificateSha256.matches(Regex("^[0-9a-f]{64}$")))
                    assertTrue(reference.dnsNames.isNotEmpty())
                    assertEquals(reference.dnsNames, reference.dnsNames.distinct().sorted())
                    assertTrue(reference.certificatePath.startsWith('/'))
                    assertTrue(reference.privateKeyPath.startsWith('/'))
                    assertTrue(reference.certificatePath != reference.privateKeyPath)
                    assertTrue(reference.usableNow)
                    assertTrue(reference.privateKeyPresentOnServer)
                    println("PHASE11_65_CERTIFICATE_REUSE_STATUS=${report.status.name}")
                    println("PHASE11_65_CERTIFICATE_DNS_NAME_COUNT=${reference.dnsNames.size}")
                    mark("STEP_05_EXISTING_3X_UI_CERTIFICATE_ELIGIBLE_FOR_EXACT_DOMAIN_BINDING")
                }
                SiteExisting3xUiCertificateReuseEligibilityStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION -> {
                    val expectedNoConfiguredPanelCertificateChecks = setOf(
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REFERENCE_CANONICAL,
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REFERENCE_CANONICAL,
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REGULAR_FILE,
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REGULAR_FILE_SERVER_SIDE,
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_SHA256_OBSERVED,
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_DNS_NAMES_NORMALIZABLE,
                        SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_CURRENTLY_VALID,
                    )
                    assertEquals(
                        "Unexpected Phase 11.65 blocked-check combination: $failedCheckCodes",
                        expectedNoConfiguredPanelCertificateChecks,
                        failedChecks.map { it.code }.toSet(),
                    )
                    assertEquals(1, proof.remoteCommandCount)
                    assertEquals(null, report.certificateReference)
                    println("PHASE11_65_CERTIFICATE_REUSE_STATUS=${report.status.name}")
                    println("PHASE11_65_CERTIFICATE_RECONCILIATION=NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE")
                    mark("STEP_05_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE_FAIL_CLOSED")
                }
            }
            assertFalse(report.certificateMutationAuthorized)
            assertFalse(report.tlsConfigurationAuthorized)
            assertFalse(report.privateKeyContentReadAuthorized)
            assertFalse(report.automaticRetryAuthorized)
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            runCatching { configFile.delete() }
            mark("STEP_06_LOCAL_CLEANUP_COMPLETE")
        }
    }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val base = 120_000L
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_65_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_65_preflight_$nonce",
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
            authorizationAttemptId = "phase11_65_credential_$nonce",
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
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_65_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_65Diag", step) }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_65_real_vps_existing_3x_ui_certificate_reuse_eligibility_acceptance.properties"
    }
}

private class OneShotPhase11_65Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.65 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_65Config {
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
                return OneShotPhase11_65Config(host, port, username, hostKey, password)
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
