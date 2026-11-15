package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import android.util.Log
import android.view.inputmethod.InputMethodManager
import androidx.compose.ui.test.click
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.secrets.ProcessCredentialMutationCoordinator
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewViewModel
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiExecutionStatus
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_100RealDeviceReleaseBootstrapProductionContextHttpUiAcceptanceInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun storedExactTargetBootstrapsThroughNormalUiAndPublishesVerifiedHttpOnce() {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            "Phase 11.100 real production bootstrap acceptance requires Android API 26+"
        }
        val nonce = requiredRunNonce()
        val shortNonce = nonce.take(16)
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()

        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.100 one-shot acceptance config is missing" }
        val config = OneShotPhase11_100Config.readAndDelete(configFile)
        val database = VelumDatabaseFactory.open(context)
        val serverRepository = RoomServerRepository(database)
        val serverAccessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val webPanelRepository = RoomWebPanelAccessRepository(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val credentials = CredentialTransactionService(
            secretStore = secretStore,
            serverAccessRepository = serverAccessRepository,
            webPanelAccessRepository = webPanelRepository,
            credentialReferenceWriter = credentialWriter,
            coordinator = ProcessCredentialMutationCoordinator(),
        )

        val server = Server(
            id = ServerId("phase11_100_server_$shortNonce"),
            displayName = "Phase 11.100 Test Lab $shortNonce",
            createdAt = Instant.now(),
        )
        val secretId = SecretId("phase11_100_secret_$shortNonce")
        val access = ServerAccess(
            id = ServerAccessId("phase11_100_access_$shortNonce"),
            serverId = server.id,
            endpoint = SshEndpoint(config.host, config.port),
            username = config.username,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
        )
        val targetRoot = "/tmp/velum-p11100-$shortNonce"
        val domain = "${config.host.replace('.', '-')}.nip.io"
        val servicePort = ACCEPTANCE_SERVICE_PORT
        var remoteServingCommitted = false
        var remoteCleanupCompleted = false

        try {
            runBlocking {
                secretStore.delete(secretId)
                requireRepositorySuccess(serverRepository.create(server), "create Phase 11.100 Server")
                val material = config.toSecretMaterial()
                try {
                    requireCredentialSuccess(
                        credentials.createServerAccess(access, material),
                        "create Phase 11.100 ServerAccess + credential",
                    )
                } finally {
                    material.close()
                    config.closeSensitiveBytes()
                }
            }
            mark("STEP_02_EXACT_STORED_SERVER_AND_ACCESS_CREATED")

            compose.onNodeWithTag("home_site_deployer_review").performClick()
            compose.onNodeWithTag("site_deployer_review_root").fetchSemanticsNode()
            val viewModel = ViewModelProvider(compose.activity)[SiteDeployerReviewViewModel::class.java]

            compose.onNodeWithTag("site_deployer_site_name")
                .performScrollTo()
                .performTextReplacement("Phase 11.100 acceptance")
            compose.onNodeWithTag("site_deployer_domain")
                .performScrollTo()
                .performTextReplacement(domain)
            compose.onNodeWithTag("site_deployer_port")
                .performScrollTo()
                .performTextReplacement(servicePort.toString())
            compose.onNodeWithTag("site_deployer_target_root")
                .performScrollTo()
                .performTextReplacement(targetRoot)
            dismissSoftwareKeyboard()
            compose.waitForIdle()

            assertNull(viewModel.uiState.value.selectedReleaseServerId)
            assertNull(viewModel.uiState.value.selectedReleaseServerAccessId)
            assertNull(viewModel.uiState.value.productionAdmission)
            compose.onNodeWithTag("site_deployer_production_deploy")
                .performScrollTo()
                .assertIsNotEnabled()
            mark("STEP_03_NORMAL_UI_HAS_NO_IMPLICIT_PRODUCTION_TARGET_OR_ADMISSION")

            compose.onNodeWithTag("site_deployer_load_release_targets")
                .performScrollTo()
                .performClick()
            compose.waitUntil(timeoutMillis = 15_000L) {
                val state = viewModel.uiState.value
                !state.releaseTargetsLoading && state.releaseTargets.any {
                    it.serverId == server.id.value && it.serverAccessId == access.id.value
                }
            }
            assertNull(viewModel.uiState.value.selectedReleaseServerId)
            assertNull(viewModel.uiState.value.selectedReleaseServerAccessId)
            mark("STEP_04_STORED_TARGET_LISTED_WITHOUT_AUTO_SELECTION")

            compose.onNodeWithTag("site_deployer_release_target_${access.id.value}")
                .performScrollTo()
                .performClick()
            compose.waitForIdle()
            assertEquals(server.id.value, viewModel.uiState.value.selectedReleaseServerId)
            assertEquals(access.id.value, viewModel.uiState.value.selectedReleaseServerAccessId)
            assertNull(viewModel.uiState.value.productionAdmission)
            mark("STEP_05_EXACT_SERVER_AND_ACCESS_SELECTED")

            compose.onNodeWithTag("site_deployer_prepare_production_context")
                .performScrollTo()
                .assertIsEnabled()
                .performClick()
            compose.waitUntil(timeoutMillis = 45_000L) {
                val state = viewModel.uiState.value
                !state.releaseBootstrapInProgress &&
                    (state.productionAdmission != null || state.releaseBootstrapError != null)
            }
            val bootstrapState = viewModel.uiState.value
            require(bootstrapState.releaseBootstrapError == null) {
                "Phase 11.100 production bootstrap failed closed: ${bootstrapState.releaseBootstrapError}"
            }
            val admission = requireNotNull(bootstrapState.productionAdmission)
            assertNotNull(bootstrapState.releaseBootstrapAdmissionSha256)
            assertEquals(config.host, admission.remoteHostIdentity)
            assertEquals(targetRoot, admission.targetRoot)
            assertEquals(domain, admission.serviceDomain)
            assertEquals(servicePort, admission.servicePort)
            assertFalse(admission.automaticRetryAuthorized)
            compose.onNodeWithTag("site_deployer_release_bootstrap_ready").performScrollTo()
            compose.onNodeWithTag("site_deployer_production_deploy").assertIsNotEnabled()
            mark("STEP_06_FRESH_READ_ONLY_BOOTSTRAP_PUBLISHED_REVIEWED_CONTEXT")

            compose.onNodeWithTag("site_deployer_confirm_exact_target").performScrollTo().performClick()
            compose.onNodeWithTag("site_deployer_confirm_real_mutation").performScrollTo().performClick()
            compose.onNodeWithTag("site_deployer_confirm_no_retry").performScrollTo().performClick()
            dismissSoftwareKeyboard()
            compose.waitForIdle()
            val deploy = compose.onNodeWithTag("site_deployer_production_deploy")
                .performScrollTo()
                .assertIsDisplayed()
                .assertIsEnabled()
            val deployNode = deploy.fetchSemanticsNode()
            Log.i(
                "Phase11_100Diag",
                "STEP_07_PHYSICAL_UI_DEPLOY_READY bounds=${deployNode.boundsInRoot}; deployEnabled=${viewModel.uiState.value.productionDeployEnabled}",
            )
            deploy.performTouchInput { click() }
            try {
                compose.waitUntil(timeoutMillis = 10_000L) {
                    viewModel.uiState.value.productionAttemptConsumed
                }
            } catch (error: Throwable) {
                val dispatchState = viewModel.uiState.value
                Log.e(
                    "Phase11_100Diag",
                    "STEP_07_DISPATCH_NOT_OBSERVED=${error::class.java.name}; " +
                        "deployEnabled=${dispatchState.productionDeployEnabled}; " +
                        "inProgress=${dispatchState.productionExecutionInProgress}; " +
                        "attemptConsumed=${dispatchState.productionAttemptConsumed}; " +
                        "receipt=${dispatchState.productionExecutionReceipt?.status}; " +
                        "error=${dispatchState.productionExecutionError ?: "NONE"}",
                )
                throw error
            }
            mark("STEP_07_THREE_CONFIRMATIONS_AND_ONE_PRODUCTION_ATTEMPT_DISPATCHED")

            try {
                compose.waitUntil(timeoutMillis = 420_000L) {
                    val state = viewModel.uiState.value
                    !state.productionExecutionInProgress &&
                        (state.productionExecutionReceipt != null || state.productionExecutionError != null)
                }
            } catch (error: Throwable) {
                val timedOutState = viewModel.uiState.value
                Log.e(
                    "Phase11_100Diag",
                    "STEP_07_TERMINAL_WAIT_EXCEPTION=${error::class.java.name}; " +
                        "inProgress=${timedOutState.productionExecutionInProgress}; " +
                        "attemptConsumed=${timedOutState.productionAttemptConsumed}; " +
                        "receipt=${timedOutState.productionExecutionReceipt?.status}; " +
                        "error=${timedOutState.productionExecutionError ?: "NONE"}",
                )
                throw error
            }
            val finalState = viewModel.uiState.value
            require(finalState.productionExecutionError == null) {
                "Phase 11.100 real UI production execution failed without retry: ${finalState.productionExecutionError}"
            }
            val receipt = requireNotNull(finalState.productionExecutionReceipt)
            assertEquals(
                SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED,
                receipt.status,
            )
            assertTrue(receipt.completeHttpServingPathVerified)
            assertFalse(receipt.completeHttpsTlsServingPathVerified)
            assertNotNull(receipt.phase1192ExecutionResultSha256)
            assertTrue(finalState.productionAttemptConsumed)
            assertFalse(finalState.productionDeployEnabled)
            remoteServingCommitted = true
            mark("STEP_08_NORMAL_UI_HTTP_RELEASE_VERIFIED_END_TO_END")

            runBlocking {
                cleanupSuccessfulAcceptanceRemoteState(
                    access = access,
                    secretStore = secretStore,
                    targetRoot = targetRoot,
                    domain = domain,
                    port = servicePort,
                    nonce = nonce,
                )
            }
            remoteCleanupCompleted = true
            remoteServingCommitted = false
            mark("STEP_09_ACCEPTANCE_ONLY_EXACT_REMOTE_CLEANUP_COMPLETE")

            // The production receipt above is already the authoritative end-to-end serving proof.
            // After exact remote cleanup, verify the retained ViewModel state instead of requiring a
            // lazy/scrollable Compose result node to remain currently composed. Presentation
            // virtualization must never turn an already verified-and-cleaned production attempt into
            // a failed acceptance result.
            val postCleanupState = viewModel.uiState.value
            assertEquals(receipt.status, postCleanupState.productionExecutionReceipt?.status)
            assertTrue(postCleanupState.productionAttemptConsumed)
            assertFalse(postCleanupState.productionDeployEnabled)
            mark("STEP_09_PRODUCTION_RECEIPT_RETAINED_AFTER_REMOTE_CLEANUP")
        } finally {
            if (remoteServingCommitted && !remoteCleanupCompleted) {
                val configPath = runCatching {
                    SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
                        remoteHostIdentity = config.host,
                        targetRoot = targetRoot,
                        domain = domain,
                        port = servicePort,
                    )
                }.getOrNull()
                Log.e("Phase11_100Diag", "REMOTE_RECONCILIATION_REQUIRED_TARGET=$targetRoot")
                Log.e("Phase11_100Diag", "REMOTE_RECONCILIATION_REQUIRED_CONFIG=${configPath ?: "UNKNOWN"}")
                Log.e("Phase11_100Diag", "REMOTE_RECONCILIATION_REQUIRED_PORT=$servicePort")
            }
            application.clearSiteDeployerProductionExecutionContext()
            runBlocking {
                val accessDelete = credentials.deleteServerAccess(access.id)
                if (accessDelete !is CredentialTransactionResult.NotFound) {
                    requireCredentialSuccess(accessDelete, "delete Phase 11.100 ServerAccess metadata")
                }
                when (val current = serverRepository.get(server.id)) {
                    is RepositoryResult.Success ->
                        requireRepositorySuccess(
                            serverRepository.delete(server.id, current.value.revision),
                            "delete Phase 11.100 Server",
                        )
                    RepositoryResult.NotFound -> Unit
                    else -> error("Unable to read Phase 11.100 Server during cleanup: $current")
                }
                val secretDelete = secretStore.delete(secretId)
                require(
                    secretDelete == SecretDeleteResult.Deleted ||
                        secretDelete == SecretDeleteResult.AlreadyAbsent,
                ) { "Phase 11.100 acceptance secret cleanup failed: $secretDelete" }
            }
            database.close()
            config.closeSensitiveBytes()
            runCatching { configFile.delete() }
            mark("STEP_10_LOCAL_ACCEPTANCE_CLEANUP_COMPLETE")
        }
    }

    private suspend fun cleanupSuccessfulAcceptanceRemoteState(
        access: ServerAccess,
        secretStore: AndroidKeystoreSecretStore,
        targetRoot: String,
        domain: String,
        port: Int,
        nonce: String,
    ) {
        require(Regex("^/tmp/velum-p11100-[0-9a-f]{16}$").matches(targetRoot))
        require(domain == "192-0-2-169.nip.io")
        require(port == ACCEPTANCE_SERVICE_PORT)
        val configPath = SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
            remoteHostIdentity = access.endpoint.host,
            targetRoot = targetRoot,
            domain = domain,
            port = port,
        )
        require(Regex("^/etc/nginx/conf\\.d/velum-tegra-[0-9a-f]{16}\\.conf$").matches(configPath))
        val owner = SessionOwner.Operation(OperationId("phase11_100_cleanup_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_100_cleanup_session_${nonce.take(16)}")
        val factory = JschSshConnectionFactory(secretStore = secretStore, sessionIdFactory = { sessionId })
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connected = factory.connect(
                access = access,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(15),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            ) as? SshConnectResult.Connected
                ?: error("Phase 11.100 acceptance cleanup SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("Phase 11.100 acceptance cleanup lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)

            val qConfig = shellQuote(configPath)
            val qTarget = shellQuote(targetRoot)
            val qIndex = shellQuote("$targetRoot/index.html")
            val qListenMarker = shellQuote("listen $port;")
            val qServerMarker = shellQuote("server_name $domain;")
            val qRootMarker = shellQuote("root $targetRoot;")
            val qFilter = shellQuote("sport = :$port")
            val raw = "test -f $qConfig; test ! -L $qConfig; " +
                "test -d $qTarget; test ! -L $qTarget; test -f $qIndex; test ! -L $qIndex; " +
                "grep -Fq -- $qListenMarker $qConfig; grep -Fq -- $qServerMarker $qConfig; " +
                "grep -Fq -- $qRootMarker $qConfig; " +
                "out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; test \$code -eq 0; test -n \"\$out\"; " +
                "nginx -t >/dev/null 2>&1; printf 'PRECONDITION=EXACT_MATCH\\n'; " +
                "rm -- $qConfig; test ! -e $qConfig; test ! -L $qConfig; " +
                "nginx -t >/dev/null 2>&1; nginx -s reload; " +
                "i=0; while [ \$i -lt 60 ]; do out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; " +
                "if [ \$code -eq 0 ] && [ -z \"\$out\" ]; then break; fi; " +
                "i=\$((i+1)); sleep 0.1; done; test \$i -lt 60; " +
                "rm -rf -- $qTarget; " +
                "test ! -e $qTarget; test ! -L $qTarget; test ! -e $qIndex; test ! -L $qIndex; " +
                "out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; " +
                "printf 'CONFIG=ABSENT\\nTARGET=ABSENT\\nINDEX=ABSENT\\nPORT=FREE\\nCLEANUP=SUCCESS\\n'"
            val result = verified.execute(
                RemoteCommand.create(raw, "phase11-100-acceptance-only-cleanup"),
                SshTransportConfig(
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(15),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            )
            require(result.dispatchState == CommandDispatchState.DISPATCHED)
            require(result.completion == CommandCompletion.ConfirmedSuccess)
            require(!result.stdout.truncated && !result.stderr.truncated)
            val stdout = result.stdout.copyBytes().toString(StandardCharsets.UTF_8).trim()
            val values = stdout.lineSequence()
                .filter { it.isNotBlank() }
                .associate { line ->
                    val i = line.indexOf('=')
                    require(i > 0) { "Malformed acceptance cleanup output" }
                    line.substring(0, i) to line.substring(i + 1)
                }
            require(values.getValue("PRECONDITION") == "EXACT_MATCH")
            require(values.getValue("CONFIG") == "ABSENT")
            require(values.getValue("TARGET") == "ABSENT")
            require(values.getValue("INDEX") == "ABSENT")
            require(values.getValue("PORT") == "FREE")
            require(values.getValue("CLEANUP") == "SUCCESS")
            mark("STEP_09_ACCEPTANCE_REMOTE_CLEANUP_POSTCONDITIONS_VERIFIED")
        } finally {
            runCatching { connectedHandle?.close() }
        }
    }

    private fun shellQuote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }


    private fun dismissSoftwareKeyboard() {
        compose.activity.runOnUiThread {
            val focused = compose.activity.currentFocus ?: return@runOnUiThread
            val imm = compose.activity.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
            imm.hideSoftInputFromWindow(focused.windowToken, 0)
            focused.clearFocus()
        }
        compose.waitForIdle()
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
            .getString("phase11_100_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun <T> requireRepositorySuccess(result: RepositoryResult<T>, action: String): T =
        when (result) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> error("$action failed: NotFound")
            is RepositoryResult.ConstraintConflict -> error("$action failed: ${result.reason}")
            is RepositoryResult.StaleRevision -> error("$action failed: stale revision")
            is RepositoryResult.Corruption -> error("$action failed: ${result.reason}")
            is RepositoryResult.StorageFailure -> error("$action failed: ${result.reason}")
        }

    private fun <T> requireCredentialSuccess(result: CredentialTransactionResult<T>, action: String): T =
        when (result) {
            is CredentialTransactionResult.Success -> result.value
            CredentialTransactionResult.NotFound -> error("$action failed: NotFound")
            CredentialTransactionResult.SecretAlreadyExists -> error("$action failed: secret already exists")
            is CredentialTransactionResult.SecretUnavailable -> error("$action failed: ${result.reason}")
            is CredentialTransactionResult.ConstraintConflict -> error("$action failed: ${result.reason}")
            is CredentialTransactionResult.StaleRevision -> error("$action failed: stale revision")
            is CredentialTransactionResult.Corruption -> error("$action failed: ${result.reason}")
            is CredentialTransactionResult.StorageFailure -> error("$action failed: ${result.reason}")
        }

    private fun mark(step: String) { Log.i("Phase11_100Diag", step) }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_100_release_bootstrap_production_context_http_ui_acceptance.properties"
        private const val ACCEPTANCE_SERVICE_PORT = 58492
    }
}

private class OneShotPhase11_100Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(
            password ?: error("Phase 11.100 password material is closed"),
        )

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_100Config {
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
                    host == "192.0.2.169" &&
                        username == "root" &&
                        hostKey == "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" &&
                        port == 22,
                )
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_100Config(host, port, username, hostKey, password)
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
