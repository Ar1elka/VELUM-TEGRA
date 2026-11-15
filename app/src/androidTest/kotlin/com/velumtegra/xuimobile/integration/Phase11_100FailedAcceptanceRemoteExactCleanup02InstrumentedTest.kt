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
class Phase11_100FailedAcceptanceRemoteExactCleanup02InstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun exactFailedRunRemoteResidueIsRemovedAfterExactPreconditionVerification() = runBlocking {
        val shortNonce = requiredFailedRunShortNonce()
        require(shortNonce == EXPECTED_FAILED_RUN_SHORT_NONCE) {
            "Phase 11.100 cleanup is scoped to the exact reconciled failed acceptance residue only"
        }
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
        require(configFile.isFile) { "Phase 11.100 cleanup one-shot config is missing" }
        val config = OneShotPhase11_100Cleanup02Config.readAndDelete(configFile)
        require(config.host == EXPECTED_HOST)
        require(config.port == 22)
        require(config.username == "root")
        require(config.hostKeySha256 == EXPECTED_HOST_KEY)

        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_100_cleanup02_${shortNonce}")
        val access = ServerAccess(
            id = ServerAccessId("phase11_100_cleanup02_access_$shortNonce"),
            serverId = ServerId("phase11_100_cleanup02_server_$shortNonce"),
            endpoint = SshEndpoint(config.host, config.port),
            username = config.username,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
        )
        val owner = SessionOwner.Operation(OperationId("phase11_100_cleanup02_$shortNonce"))
        val sessionId = SessionId("phase11_100_cleanup02_session_$shortNonce")
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
            mark("STEP_02_EPHEMERAL_CLEANUP_CREDENTIAL_READY")

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
                ?: error("Phase 11.100 exact cleanup SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("Phase 11.100 exact cleanup lacks verified host-key evidence")
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
            val raw = "test -f $qConfig; test ! -L $qConfig; " +
                "test -d $qTarget; test ! -L $qTarget; test -f $qIndex; test ! -L $qIndex; " +
                "grep -Fq -- $qListenMarker $qConfig; grep -Fq -- $qServerMarker $qConfig; " +
                "grep -Fq -- $qRootMarker $qConfig; " +
                "out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; test \$code -eq 0; test -n \"\$out\"; " +
                "nginx -t >/dev/null 2>&1; " +
                "printf 'PRECONDITION=EXACT_MATCH\\n'; " +
                "rm -- $qConfig; test ! -e $qConfig; test ! -L $qConfig; " +
                "nginx -t >/dev/null 2>&1; nginx -s reload; " +
                "i=0; while [ \$i -lt 60 ]; do out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; " +
                "if [ \$code -eq 0 ] && [ -z \"\$out\" ]; then break; fi; i=\$((i+1)); sleep 0.1; done; " +
                "test \$i -lt 60; " +
                "rm -rf -- $qTarget; test ! -e $qTarget; test ! -L $qTarget; test ! -e $qIndex; test ! -L $qIndex; " +
                "out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; " +
                "printf 'CONFIG=ABSENT\\nTARGET=ABSENT\\nINDEX=ABSENT\\nPORT=FREE\\nCLEANUP=SUCCESS\\n'"
            val result = verified.execute(
                RemoteCommand.create(raw, "phase11-100-failed-acceptance-exact-cleanup"),
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
                    require(i > 0) { "Malformed cleanup output" }
                    line.substring(0, i) to line.substring(i + 1)
                }
            require(values.getValue("PRECONDITION") == "EXACT_MATCH")
            require(values.getValue("CONFIG") == "ABSENT")
            require(values.getValue("TARGET") == "ABSENT")
            require(values.getValue("INDEX") == "ABSENT")
            require(values.getValue("PORT") == "FREE")
            require(values.getValue("CLEANUP") == "SUCCESS")

            mark("CLEANUP_EXACT_CONFIG_PATH=$configPath")
            mark("CLEANUP_EXACT_TARGET_ROOT=$targetRoot")
            mark("CLEANUP_PRECONDITION=EXACT_MATCH")
            mark("CLEANUP_CONFIG=ABSENT")
            mark("CLEANUP_TARGET=ABSENT")
            mark("CLEANUP_INDEX=ABSENT")
            mark("CLEANUP_PORT=FREE")
            mark("STEP_03_EXACT_REMOTE_CLEANUP_AND_POSTCONDITION_VERIFICATION_COMPLETE")
        } finally {
            runCatching { connectedHandle?.close() }
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            runCatching { configFile.delete() }
            mark("STEP_04_LOCAL_CLEANUP_CREDENTIAL_REMOVAL_COMPLETE")
        }
    }

    private fun requiredFailedRunShortNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_100_failed_run_short_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{16}$").matches(nonce))
        return nonce
    }

    private fun shellQuote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    private fun mark(value: String) {
        Log.i("Phase11_100Cleanup02", value)
    }

    companion object {
        private const val CONFIG_FILE_NAME = "phase11_100_failed_acceptance_remote_cleanup_02.properties"
        private const val EXPECTED_FAILED_RUN_SHORT_NONCE = "7aef28a4190f47a5"
        private const val EXPECTED_HOST = "192.0.2.169"
        private const val EXPECTED_HOST_KEY = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        private const val EXPECTED_DOMAIN = "192-0-2-169.nip.io"
        private const val EXPECTED_SERVICE_PORT = 58492
        private const val EXPECTED_TARGET_ROOT = "/tmp/velum-p11100-7aef28a4190f47a5"
        private const val EXPECTED_CONFIG_PATH = "/etc/nginx/conf.d/velum-tegra-4fa4e791b364648b.conf"
    }
}

private class OneShotPhase11_100Cleanup02Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.100 cleanup password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_100Cleanup02Config {
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
                return OneShotPhase11_100Cleanup02Config(host, port, username, hostKey, password)
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun decodeUtf8(value: String): String =
            Base64.decode(value, Base64.DEFAULT).toString(StandardCharsets.UTF_8)
    }
}
