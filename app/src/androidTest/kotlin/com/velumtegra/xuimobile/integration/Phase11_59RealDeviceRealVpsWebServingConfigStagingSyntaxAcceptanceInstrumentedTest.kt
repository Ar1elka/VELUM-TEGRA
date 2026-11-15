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
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentEphemeralCredentialLease
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
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
class Phase11_59RealDeviceRealVpsWebServingConfigStagingSyntaxAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactConfigIsStagedSyntaxValidatedAndCleanedWithoutActivationOrReload() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.59 one-shot real-VPS acceptance config is missing" }
        val config = OneShotPhase11_59Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_59_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_59-plan-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_59_access_$nonce"),
                serverId = ServerId("phase11_59_server_$nonce"),
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
                    rootSeed = DesignSeed(1159L),
                    domain = "phase1159.example.com",
                    servicePort = 58474,
                    remoteHostIdentity = config.host,
                    targetRoot = "/tmp/velum-p1159-${nonce.take(16)}",
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
            assertEquals(58474, publicationPlan.port)
            assertTrue(publicationPlan.configPath.endsWith(".conf"))
            mark("STEP_03_EXACT_PUBLICATION_PLAN_READY")

            val readCredential = resolveFreshCredential(access, nonce, "read", 140_000L)
            val readProof = application.siteProductionDeploymentObserveRealVpsWebServingReadOnlyPreflightOnce(
                plan = publicationPlan,
                freshResolutionProof = readCredential.proof,
                freshCredentialLease = readCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_59_read_preflight_${nonce.take(16)}",
                executedAtEpochMillis = readCredential.proof.resolvedAtEpochMillis + 10L,
            )
            SiteWebServingReadOnlyPreflightBoundary.validateReport(readProof.preflightReport)
            readProof.preflightReport.checks.forEach { check ->
                Log.i(
                    "Phase11_59Diag",
                    "PREFLIGHT_${check.code.name}=${check.passed}",
                )
            }
            Log.i(
                "Phase11_59Diag",
                "PREFLIGHT_STATUS=${readProof.preflightReport.status.name}",
            )
            val failedPreflightChecks = readProof.preflightReport.checks
                .filterNot { it.passed }
                .map { it.code.name }
            if (failedPreflightChecks.isNotEmpty()) {
                val discoveryCredential = resolveFreshCredential(access, nonce, "discover", 150_000L)
                val discovery = discoverWebServingEnvironment(
                    access = access,
                    resolved = discoveryCredential,
                    nonce = nonce,
                )
                discovery.forEach { line -> mark("DISCOVERY_$line") }
                mark("STEP_04A_READ_ONLY_ENVIRONMENT_DISCOVERY_COMPLETE")
            }
            assertEquals(
                "Blocked read-only preflight checks: ${failedPreflightChecks.joinToString(separator = ",")}",
                SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY,
                readProof.preflightReport.status,
            )
            val checks = readProof.preflightReport.checks.associateBy { it.code }
            assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT).passed)
            assertTrue(checks.getValue(SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE).passed)
            mark("STEP_04_FRESH_READ_ONLY_BASELINE_READY")

            val mutationPreparation = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(
                    publicationPlan = publicationPlan,
                    readOnlyPreflight = readProof.preflightReport,
                    mutationTransactionId = "phase11_59_tx_${nonce.take(20)}",
                ),
            )
            val executionPlan = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(
                mutationPreparation,
                publicationPlan,
                readProof.preflightReport,
            )
            assertTrue(executionPlan.stagingConfigWriteAuthorized)
            assertTrue(executionPlan.isolatedNginxSyntaxValidationAuthorized)
            assertFalse(executionPlan.exactConfigActivationAuthorized)
            assertFalse(executionPlan.webServerReloadAuthorized)
            mark("STEP_05_BOUNDED_WRITE_AUTHORITY_PREPARED")

            val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()
            val writeCredential = resolveFreshCredential(access, nonce, "write", 160_000L)
            val proof = application.siteProductionDeploymentExecuteRealVpsWebServingConfigStagingSyntaxOnce(
                publicationPlan = publicationPlan,
                readOnlyPreflight = readProof.preflightReport,
                mutationPreparation = mutationPreparation,
                executionPlan = executionPlan,
                freshResolutionProof = writeCredential.proof,
                freshCredentialLease = writeCredential.lease,
                serverAccess = access,
                executionAttemptId = "phase11_59_stage_syntax_${nonce.take(16)}",
                executedAtEpochMillis = writeCredential.proof.resolvedAtEpochMillis + 10L,
            )
            SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary.validateProof(proof)
            val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                beforeFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount + 1,
                afterFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount,
            )
            mark("STEP_06_REAL_VPS_STAGE_SYNTAX_EXECUTION_COMPLETE")

            assertEquals(7, proof.remoteCommandCount)
            assertTrue(proof.durableBaselineCheckpointRecorded)
            assertTrue(proof.credentialLeaseMaterialConsumed)
            assertTrue(proof.productionNetworkTouched)
            assertTrue(proof.hostKeyPinVerifiedAgainstRemote)
            assertTrue(proof.exactSessionRegistryUsed)
            assertTrue(proof.mutationOperationPerformed)
            assertTrue(proof.stagingConfigWritePerformed)
            assertTrue(proof.stagingConfigSha256Verified)
            assertTrue(proof.validationConfigWritePerformed)
            assertTrue(proof.validationConfigSha256Verified)
            assertTrue(proof.nginxSyntaxValidationPassed)
            assertFalse(proof.exactConfigActivationPerformed)
            assertTrue(proof.exactConfigPathAbsentAfterValidation)
            assertTrue(proof.listenerStillFreeAfterValidation)
            assertTrue(proof.stagingConfigAbsentAfterCleanup)
            assertTrue(proof.validationConfigAbsentAfterCleanup)
            assertTrue(proof.validationPidAbsentAfterCleanup)
            assertFalse(proof.arbitraryCommandAccepted)
            assertFalse(proof.privateKeyContentReadPerformed)
            assertFalse(proof.webServerReloadPerformed)
            assertFalse(proof.dnsMutationPerformed)
            assertFalse(proof.firewallMutationPerformed)
            assertFalse(proof.packageInstallPerformed)
            assertFalse(proof.automaticRetryPerformed)
            assertTrue(proof.sessionClosed)
            assertFalse(proof.coordinatorInvoked)
            assertFalse(proof.exposesDeployUiAction)
            mark("STEP_07_EXACT_CONFIG_AND_LISTENER_REMAIN_UNCHANGED")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localRoot)
            runCatching { configFile.delete() }
            mark("STEP_08_LOCAL_CLEANUP_COMPLETE")
        }
    }

    private suspend fun discoverWebServingEnvironment(
        access: ServerAccess,
        resolved: SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved,
        nonce: String,
    ): List<String> {
        val owner = SessionOwner.Operation(OperationId("phase11_59_env_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_59_env_session_${nonce.take(16)}")
        val leaseStore = OneShotDiscoveryLeaseSecretStore(access.auth.secretId, resolved.lease)
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
                    stdoutCaptureLimitBytes = 32 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.59 read-only environment discovery SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("Phase 11.59 read-only environment discovery lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)

            val result = verified.execute(
                RemoteCommand.create(
                    WEB_SERVING_ENVIRONMENT_DISCOVERY_COMMAND,
                    "phase11-59-web-serving-environment-discovery",
                ),
                SshTransportConfig(
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 32 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
                ),
            )
            require(result.dispatchState == CommandDispatchState.DISPATCHED) {
                "Phase 11.59 read-only environment discovery was not dispatched"
            }
            require(result.completion == CommandCompletion.ConfirmedSuccess) {
                "Phase 11.59 read-only environment discovery command failed"
            }
            require(!result.stdout.truncated && !result.stderr.truncated) {
                "Phase 11.59 read-only environment discovery output was truncated"
            }
            val lines = result.stdout.copyBytes().toString(StandardCharsets.UTF_8)
                .lineSequence()
                .map(String::trim)
                .filter(String::isNotEmpty)
                .toList()
            require(lines.isNotEmpty() && lines.size <= 80) {
                "Phase 11.59 read-only environment discovery returned an invalid line count"
            }
            val allowedPrefixes = listOf(
                "TOOL_",
                "EXEC=",
                "EXEC_ABSENT=",
                "DIR=",
                "DIR_ABSENT=",
                "PATH_NONDIR=",
                "FIND_EXEC=",
                "FIND_DIR=",
                "FIND_UNAVAILABLE=",
            )
            require(lines.all { line ->
                line.length <= 512 && '\r' !in line && '\u0000' !in line && allowedPrefixes.any(line::startsWith)
            }) { "Phase 11.59 read-only environment discovery returned malformed output" }
            mark("DISCOVERY_REMOTE_COMMAND_COUNT=1")
            return lines
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
            admissionAttemptId = "phase11_59_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_59_${suffix}_preflight_$nonce",
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
            authorizationAttemptId = "phase11_59_${suffix}_credential_$nonce",
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
        val nonce = InstrumentationRegistry.getArguments().getString("phase11_59_run_nonce")?.trim().orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun mark(step: String) { Log.i("Phase11_59Diag", step) }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_59_real_vps_web_serving_config_staging_syntax_acceptance.properties"
        private const val WEB_SERVING_ENVIRONMENT_DISCOVERY_COMMAND =
            "for t in nginx openresty caddy apache2 httpd; do " +
                "if p=\$(command -v \"\$t\" 2>/dev/null); then printf 'TOOL_%s=%s\\n' \"\$t\" \"\$p\"; " +
                "else printf 'TOOL_%s=ABSENT\\n' \"\$t\"; fi; done; " +
                "for p in /usr/sbin/nginx /usr/local/sbin/nginx /usr/bin/nginx /usr/local/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx /opt/nginx/sbin/nginx /www/server/nginx/sbin/nginx; do " +
                "if [ -x \"\$p\" ]; then printf 'EXEC=%s\\n' \"\$p\"; else printf 'EXEC_ABSENT=%s\\n' \"\$p\"; fi; done; " +
                "for d in /etc/nginx /etc/nginx/conf.d /etc/nginx/sites-available /etc/nginx/sites-enabled /usr/local/nginx/conf /usr/local/openresty/nginx/conf /www/server/nginx/conf /etc/openresty /etc/caddy /etc/apache2 /etc/httpd; do " +
                "if [ -d \"\$d\" ]; then printf 'DIR=%s\\n' \"\$d\"; elif [ -e \"\$d\" ]; then printf 'PATH_NONDIR=%s\\n' \"\$d\"; else printf 'DIR_ABSENT=%s\\n' \"\$d\"; fi; done; " +
                "if command -v find >/dev/null 2>&1 && command -v sed >/dev/null 2>&1 && command -v head >/dev/null 2>&1; then " +
                "find /usr/local /opt /www -maxdepth 5 -type f -name nginx -perm -111 -print 2>/dev/null | sed 's#^#FIND_EXEC=#' | head -n 16; " +
                "find /etc /usr/local /opt /www -maxdepth 5 -type d \\( -name nginx -o -name conf.d \\) -print 2>/dev/null | sed 's#^#FIND_DIR=#' | head -n 32; " +
                "else printf 'FIND_UNAVAILABLE=true\\n'; fi"
    }
}

private class OneShotDiscoveryLeaseSecretStore(
    private val expectedSecretId: SecretId,
    private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
) : SecretStore {
    private val readStarted = AtomicBoolean(false)

    override suspend fun read(secretId: SecretId): SecretReadResult {
        if (secretId != expectedSecretId) return SecretReadResult.NotFound
        if (!readStarted.compareAndSet(false, true)) {
            return SecretReadResult.Unavailable("Phase 11.59 discovery credential lease is single-use")
        }
        val copy = credentialLease.useMaterialOnce { material ->
            material.useBytes { SecretMaterial.fromBytes(it) }
        }
        return SecretReadResult.Found(copy)
    }

    override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
        SecretCreateResult.StorageFailure("Phase 11.59 discovery lease adapter is read-only")

    override suspend fun delete(secretId: SecretId): SecretDeleteResult =
        SecretDeleteResult.StorageFailure("Phase 11.59 discovery lease adapter is read-only")

    override suspend fun listIds(): SecretListResult =
        SecretListResult.StorageFailure("Phase 11.59 discovery lease adapter does not enumerate secrets")
}

private class OneShotPhase11_59Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.59 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_59Config {
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
                return OneShotPhase11_59Config(host, port, username, hostKey, password)
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
