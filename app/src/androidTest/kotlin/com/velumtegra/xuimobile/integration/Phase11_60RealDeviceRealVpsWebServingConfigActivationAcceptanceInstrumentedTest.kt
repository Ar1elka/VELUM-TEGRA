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
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightCheckCode
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentEphemeralCredentialLease
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Arrays
import java.util.Comparator
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_60RealDeviceRealVpsWebServingConfigActivationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactConfigIsAtomicallyActivatedAndVerifiedWithoutReloadThenAcceptanceCleanupReturnsAbsent() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.60 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_60Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_60_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_60-plan-")
        var publicationConfigPath: String? = null
        var publicationConfigSha: String? = null
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_60_access_$nonce"),
                serverId = ServerId("phase11_60_server_$nonce"),
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
                    rootSeed = DesignSeed(1160L),
                    domain = "phase1160.example.com",
                    servicePort = 58475,
                    remoteHostIdentity = config.host,
                    targetRoot = "/tmp/velum-p1160-${nonce.take(16)}",
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
            publicationConfigPath = publicationPlan.configPath
            publicationConfigSha = publicationPlan.desiredConfigSha256
            assertEquals(58475, publicationPlan.port)
            assertTrue(publicationPlan.configPath.endsWith(".conf"))
            mark("STEP_03_EXACT_PUBLICATION_PLAN_READY")

            val readCredential = resolveFreshCredential(access, nonce, "read", 210_000L)
            val readProof = application.siteProductionDeploymentObserveRealVpsWebServingReadOnlyPreflightOnce(
                plan = publicationPlan,
                freshResolutionProof = readCredential.proof,
                freshCredentialLease = readCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_60_read_preflight_${nonce.take(16)}",
                executedAtEpochMillis = readCredential.proof.resolvedAtEpochMillis + 10L,
            )
            SiteWebServingReadOnlyPreflightBoundary.validateReport(readProof.preflightReport)
            assertEquals(
                SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY,
                readProof.preflightReport.status,
            )
            val checks = readProof.preflightReport.checks.associateBy { it.code }
            assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.NGINX_EXECUTABLE).passed)
            assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.NGINX_CONF_D_DIRECTORY).passed)
            assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT).passed)
            assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE).passed)
            mark("STEP_04_FRESH_READ_ONLY_BASELINE_READY")

            val mutationPreparation = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(
                    publicationPlan = publicationPlan,
                    readOnlyPreflight = readProof.preflightReport,
                    mutationTransactionId = "phase11_60_tx_${nonce.take(20)}",
                ),
            )
            val stagingSyntaxPlan = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(
                mutationPreparation,
                publicationPlan,
                readProof.preflightReport,
            )
            val stagingCredential = resolveFreshCredential(access, nonce, "stage", 230_000L)
            val stagingProof = application.siteProductionDeploymentExecuteRealVpsWebServingConfigStagingSyntaxOnce(
                publicationPlan = publicationPlan,
                readOnlyPreflight = readProof.preflightReport,
                mutationPreparation = mutationPreparation,
                executionPlan = stagingSyntaxPlan,
                freshResolutionProof = stagingCredential.proof,
                freshCredentialLease = stagingCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_60_stage_syntax_${nonce.take(16)}",
                executedAtEpochMillis = stagingCredential.proof.resolvedAtEpochMillis + 10L,
            )
            assertTrue(stagingProof.nginxSyntaxValidationPassed)
            assertTrue(stagingProof.exactConfigPathAbsentAfterValidation)
            assertTrue(stagingProof.stagingConfigAbsentAfterCleanup)
            mark("STEP_05_PHASE1159_PREREQUISITE_PROOF_READY")

            val activationPlan = SiteWebServingConfigActivationExecutionBoundary.prepare(
                mutationPreparation,
                stagingSyntaxPlan,
                publicationPlan,
                readProof.preflightReport,
            )
            assertTrue(activationPlan.exactConfigActivationAuthorized)
            assertFalse(activationPlan.webServerReloadAuthorized)
            mark("STEP_06_ATOMIC_ACTIVATION_AUTHORITY_PREPARED")

            val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()
            val activationCredential = resolveFreshCredential(access, nonce, "activate", 250_000L)
            val proof = application.siteProductionDeploymentExecuteRealVpsWebServingConfigActivationOnce(
                publicationPlan = publicationPlan,
                readOnlyPreflight = readProof.preflightReport,
                mutationPreparation = mutationPreparation,
                stagingSyntaxPlan = stagingSyntaxPlan,
                stagingSyntaxProof = stagingProof,
                activationPlan = activationPlan,
                freshResolutionProof = activationCredential.proof,
                freshCredentialLease = activationCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_60_activate_${nonce.take(16)}",
                executedAtEpochMillis = activationCredential.proof.resolvedAtEpochMillis + 10L,
            )
            SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary.validateProof(proof)
            val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                beforeFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount + 1,
                afterFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount,
            )
            mark("STEP_07_REAL_VPS_ATOMIC_ACTIVATION_COMPLETE")

            assertEquals(7, proof.remoteCommandCount)
            assertTrue(proof.successfulStagingSyntaxProofValidated)
            assertTrue(proof.durablePreactivationCheckpointRecorded)
            assertTrue(proof.stagingConfigWritePerformed)
            assertTrue(proof.stagingConfigSha256Verified)
            assertTrue(proof.exactConfigActivationPerformed)
            assertTrue(proof.exactConfigSha256Verified)
            assertTrue(proof.nginxSyntaxValidationPassed)
            assertTrue(proof.exactConfigPathPresentAfterActivation)
            assertTrue(proof.stagingConfigAbsentAfterActivation)
            assertTrue(proof.listenerStillFreeAfterActivation)
            assertFalse(proof.rollbackToAbsentPerformed)
            assertFalse(proof.webServerReloadPerformed)
            assertFalse(proof.dnsMutationPerformed)
            assertFalse(proof.firewallMutationPerformed)
            assertFalse(proof.packageInstallPerformed)
            assertFalse(proof.automaticRetryPerformed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            mark("STEP_08_EXACT_CONFIG_PRESENT_LISTENER_STILL_FREE_NO_RELOAD")

            val cleanupCredential = resolveFreshCredential(access, nonce, "cleanup", 270_000L)
            cleanupExactConfigForAcceptance(
                access = access,
                resolved = cleanupCredential,
                configPath = publicationPlan.configPath,
                desiredSha256 = publicationPlan.desiredConfigSha256,
                port = publicationPlan.port,
                nonce = nonce,
            )
            publicationConfigPath = null
            publicationConfigSha = null
            mark("STEP_09_ACCEPTANCE_ONLY_EXACT_CONFIG_CLEANUP_TO_ABSENT")
        } finally {
            if (publicationConfigPath != null && publicationConfigSha != null) {
                Log.e("Phase11_60Diag", "REMOTE_EXACT_CONFIG_MAY_REQUIRE_RECONCILIATION=$publicationConfigPath")
            }
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localRoot)
            runCatching { configFile.delete() }
            mark("STEP_10_LOCAL_CLEANUP_COMPLETE")
        }
    }

    private suspend fun cleanupExactConfigForAcceptance(
        access: ServerAccess,
        resolved: SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved,
        configPath: String,
        desiredSha256: String,
        port: Int,
        nonce: String,
    ) {
        val owner = SessionOwner.Operation(OperationId("phase11_60_cleanup_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_60_cleanup_session_${nonce.take(16)}")
        val leaseStore = OneShotAcceptanceCleanupLeaseSecretStore(access.auth.secretId, resolved.lease)
        val factory = JschSshConnectionFactory(secretStore = leaseStore, sessionIdFactory = { sessionId })
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connectResult = factory.connect(
                access = access,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.60 acceptance cleanup SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("Phase 11.60 acceptance cleanup lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)
            val qPath = shellQuote(configPath)
            val qSha = shellQuote(desiredSha256)
            val qFilter = shellQuote("sport = :$port")
            val raw = "test -f $qPath; test ! -L $qPath; " +
                "test \"\$(sha256sum -- $qPath | cut -d' ' -f1)\" = $qSha; rm -- $qPath; " +
                "test ! -e $qPath; test ! -L $qPath; nginx -t >/dev/null 2>&1; " +
                "out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; printf 'ABSENT\\n'"
            val result = verified.execute(
                RemoteCommand.create(raw, "phase11-60-acceptance-only-cleanup-to-absent"),
                SshTransportConfig(
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            )
            require(result.dispatchState == CommandDispatchState.DISPATCHED)
            require(result.completion == CommandCompletion.ConfirmedSuccess)
            require(!result.stdout.truncated && !result.stderr.truncated)
            require(result.stdout.copyBytes().toString(StandardCharsets.UTF_8).trim() == "ABSENT")
        } finally {
            runCatching { connectedHandle?.close() }
            resolved.lease.close()
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
            admissionAttemptId = "phase11_60_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_60_${suffix}_preflight_$nonce",
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
            authorizationAttemptId = "phase11_60_${suffix}_credential_$nonce",
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
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_60_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun shellQuote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_60Diag", step) }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_60_real_vps_web_serving_config_activation_acceptance.properties"
    }
}

private class OneShotAcceptanceCleanupLeaseSecretStore(
    private val expectedSecretId: SecretId,
    private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
) : SecretStore {
    private val readStarted = AtomicBoolean(false)
    override suspend fun read(secretId: SecretId): SecretReadResult {
        if (secretId != expectedSecretId) return SecretReadResult.NotFound
        if (!readStarted.compareAndSet(false, true)) {
            return SecretReadResult.Unavailable("Phase 11.60 cleanup credential lease is single-use")
        }
        val copy = credentialLease.useMaterialOnce { material -> material.useBytes { SecretMaterial.fromBytes(it) } }
        return SecretReadResult.Found(copy)
    }
    override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
        SecretCreateResult.StorageFailure("Phase 11.60 cleanup lease adapter is read-only")
    override suspend fun delete(secretId: SecretId): SecretDeleteResult =
        SecretDeleteResult.StorageFailure("Phase 11.60 cleanup lease adapter is read-only")
    override suspend fun listIds(): SecretListResult =
        SecretListResult.StorageFailure("Phase 11.60 cleanup lease adapter does not enumerate secrets")
}

private class OneShotPhase11_60Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.60 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_60Config {
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
                return OneShotPhase11_60Config(host, port, username, hostKey, password)
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
