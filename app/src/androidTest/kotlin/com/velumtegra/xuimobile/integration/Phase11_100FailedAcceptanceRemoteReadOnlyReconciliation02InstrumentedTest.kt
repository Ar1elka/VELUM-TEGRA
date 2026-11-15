package com.velumtegra.xuimobile.integration

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
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
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_100FailedAcceptanceRemoteReadOnlyReconciliation02InstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun exactFailedRunRemoteStateIsObservedWithoutMutation() = runBlocking {
        val failedRunNonce = requiredFailedRunNonce()
        require(failedRunNonce == EXPECTED_FAILED_RUN_NONCE) {
            "Phase 11.100 reconciliation is scoped to the exact failed acceptance run only"
        }
        val shortNonce = failedRunNonce.take(16)
        val targetRoot = "/tmp/velum-p11100-$shortNonce"
        val domain = EXPECTED_DOMAIN
        val servicePort = EXPECTED_SERVICE_PORT
        val configPath = SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
            remoteHostIdentity = EXPECTED_HOST,
            targetRoot = targetRoot,
            domain = domain,
            port = servicePort,
        )
        assertEquals(EXPECTED_TARGET_ROOT, targetRoot)
        assertEquals(EXPECTED_CONFIG_PATH, configPath)
        mark("STEP_01_EXACT_FAILED_RUN_SCOPE_VERIFIED")

        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.100 reconciliation one-shot config is missing" }
        val config = OneShotPhase11_100Recon02ciliationConfig.readAndDelete(configFile)
        require(config.host == EXPECTED_HOST)
        require(config.port == 22)
        require(config.username == "root")
        require(config.hostKeySha256 == EXPECTED_HOST_KEY)

        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_100_recon02_${shortNonce}")
        val access = ServerAccess(
            id = ServerAccessId("phase11_100_recon02_access_$shortNonce"),
            serverId = ServerId("phase11_100_recon02_server_$shortNonce"),
            endpoint = SshEndpoint(config.host, config.port),
            username = config.username,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
        )
        val owner = SessionOwner.Operation(OperationId("phase11_100_recon02_${failedRunNonce.take(20)}"))
        val sessionId = SessionId("phase11_100_recon02_session_$shortNonce")
        val factory = JschSshConnectionFactory(secretStore = secretStore, sessionIdFactory = { sessionId })
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null

        try {
            secretStore.delete(secretId)
            val material = config.toSecretMaterial()
            try {
                assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
            } finally {
                material.close()
                config.closeSensitiveBytes()
            }
            mark("STEP_02_EPHEMERAL_RECONCILIATION_CREDENTIAL_READY")

            val connected = factory.connect(
                access = access,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
                ),
            ) as? SshConnectResult.Connected
                ?: error("Phase 11.100 read-only reconciliation SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("Phase 11.100 reconciliation lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)

            val qConfig = shellQuote(configPath)
            val qTarget = shellQuote(targetRoot)
            val qIndex = shellQuote("$targetRoot/index.html")
            val qListenMarker = shellQuote("listen $servicePort;")
            val qServerMarker = shellQuote("server_name $domain;")
            val qRootMarker = shellQuote("root $targetRoot;")
            val qFilter = shellQuote("sport = :$servicePort")
            val raw = "if [ -L $qConfig ]; then c=SYMLINK; " +
                "elif [ -f $qConfig ]; then c=REGULAR; elif [ -e $qConfig ]; then c=OTHER; else c=ABSENT; fi; " +
                "if [ -L $qTarget ]; then t=SYMLINK; " +
                "elif [ -d $qTarget ]; then t=DIRECTORY; elif [ -e $qTarget ]; then t=OTHER; else t=ABSENT; fi; " +
                "if [ -L $qIndex ]; then i=SYMLINK; " +
                "elif [ -f $qIndex ]; then i=REGULAR; elif [ -e $qIndex ]; then i=OTHER; else i=ABSENT; fi; " +
                "out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; " +
                "if [ \$code -ne 0 ]; then l=QUERY_FAILED; elif [ -z \"\$out\" ]; then l=FREE; else l=LISTENING; fi; " +
                "m=NOT_APPLICABLE; if [ \"\$c\" = REGULAR ]; then a=0; b=0; d=0; " +
                "grep -Fq -- $qListenMarker $qConfig && a=1; grep -Fq -- $qServerMarker $qConfig && b=1; " +
                "grep -Fq -- $qRootMarker $qConfig && d=1; " +
                "if [ \$a -eq 1 ] && [ \$b -eq 1 ] && [ \$d -eq 1 ]; then m=MATCH; else m=MISMATCH; fi; fi; " +
                "printf 'CONFIG=%s\\nTARGET=%s\\nINDEX=%s\\nPORT=%s\\nMARKERS=%s\\n' \"\$c\" \"\$t\" \"\$i\" \"\$l\" \"\$m\""
            val result = verified.execute(
                RemoteCommand.create(raw, "phase11-100-failed-acceptance-read-only-reconciliation"),
                SshTransportConfig(
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
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
                    require(i > 0) { "Malformed reconciliation output" }
                    line.substring(0, i) to line.substring(i + 1)
                }
            require(values.keys == setOf("CONFIG", "TARGET", "INDEX", "PORT", "MARKERS"))
            require(values.getValue("CONFIG") in setOf("ABSENT", "REGULAR", "SYMLINK", "OTHER"))
            require(values.getValue("TARGET") in setOf("ABSENT", "DIRECTORY", "SYMLINK", "OTHER"))
            require(values.getValue("INDEX") in setOf("ABSENT", "REGULAR", "SYMLINK", "OTHER"))
            require(values.getValue("PORT") in setOf("FREE", "LISTENING", "QUERY_FAILED"))
            require(values.getValue("MARKERS") in setOf("MATCH", "MISMATCH", "NOT_APPLICABLE"))

            mark("RECON_EXACT_CONFIG_PATH=$configPath")
            mark("RECON_EXACT_TARGET_ROOT=$targetRoot")
            mark("RECON_CONFIG=${values.getValue("CONFIG")}")
            mark("RECON_TARGET=${values.getValue("TARGET")}")
            mark("RECON_INDEX=${values.getValue("INDEX")}")
            mark("RECON_PORT=${values.getValue("PORT")}")
            mark("RECON_MARKERS=${values.getValue("MARKERS")}")
            mark("STEP_03_READ_ONLY_REMOTE_RECONCILIATION_COMPLETE")
        } finally {
            runCatching { connectedHandle?.close() }
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            runCatching { configFile.delete() }
            mark("STEP_04_LOCAL_RECONCILIATION_CLEANUP_COMPLETE")
        }
    }

    private fun requiredFailedRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_100_failed_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun shellQuote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    private fun mark(value: String) {
        Log.i("Phase11_100Recon02", value)
    }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_100_failed_acceptance_remote_reconciliation_02.properties"
        private const val EXPECTED_FAILED_RUN_NONCE = "a60664d7878c4503a425f65b4051c18d"
        private const val EXPECTED_HOST = "192.0.2.169"
        private const val EXPECTED_HOST_KEY = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        private const val EXPECTED_DOMAIN = "192-0-2-169.nip.io"
        private const val EXPECTED_SERVICE_PORT = 58492
        private const val EXPECTED_TARGET_ROOT = "/tmp/velum-p11100-a60664d7878c4503"
        private const val EXPECTED_CONFIG_PATH = "/etc/nginx/conf.d/velum-tegra-950ab3d0197e0d05.conf"
    }
}

private class OneShotPhase11_100Recon02ciliationConfig private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.100 reconciliation password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_100Recon02ciliationConfig {
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
                val password = Base64.decode(values.getValue("password_b64"), Base64.DEFAULT)
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_100Recon02ciliationConfig(host, port, username, hostKey, password)
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun decodeUtf8(value: String): String =
            Base64.decode(value, Base64.DEFAULT).toString(StandardCharsets.UTF_8)
    }
}
