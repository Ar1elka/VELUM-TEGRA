package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshPrivateKeyCredentialMaterial
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 3.2D real-device / real-SSH acceptance gate.
 *
 * This test is deliberately opt-in. It runs only when the one-shot configuration file is injected into the target
 * app's noBackupFilesDir by RUN_PHASE3_2D_VPS_ACCEPTANCE.ps1. The file is deleted immediately after parsing.
 *
 * Remote behavior is read-only: one exact SSH connection, one `printf VELUM_PHASE3_DEVICE_OK` exec, then close.
 * There is no retry, no fallback target, no TOFU and no mutation command.
 */
@RunWith(AndroidJUnit4::class)
class Phase3SshVpsAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun exactPinnedAccessConnectsAndExecutesOneReadOnlyProbe() = runBlocking {
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        assumeTrue(
            "Phase 3.2D acceptance config was not injected; real VPS gate is opt-in",
            configFile.isFile,
        )

        assertInternetPermissionDeclared()

        val parsed = OneShotAcceptanceConfig.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId(ACCEPTANCE_SECRET_ID)
        try {
            // A prior interrupted acceptance run may have left only encrypted device-local test material.
            // Delete it before create because SecretStore is create-only and never overwrites by design.
            secretStore.delete(secretId)

            val accessId = ServerAccessId("phase3-2d-vps-access")
            val auth = when (parsed.authMethod) {
                AcceptanceAuthMethod.PASSWORD -> SshAuthRef.Password(secretId)
                AcceptanceAuthMethod.PRIVATE_KEY -> SshAuthRef.PrivateKey(secretId)
            }
            val access = ServerAccess(
                id = accessId,
                serverId = ServerId("phase3-2d-vps-server"),
                endpoint = SshEndpoint(parsed.host, parsed.port),
                username = parsed.username,
                auth = auth,
                pinnedHostKey = HostKeyFingerprint(parsed.hostKeySha256),
            )
            val owner = SessionOwner.Management(
                installationId = XuiInstallationId("phase3-2d-vps-installation"),
                serverAccessId = accessId,
            )

            val credentialMaterial = parsed.toSecretMaterial()
            try {
                assertEquals(
                    SecretCreateResult.Created,
                    secretStore.create(secretId, credentialMaterial),
                )
            } finally {
                credentialMaterial.close()
                parsed.closeSensitiveBytes()
            }

            val connect = JschSshConnectionFactory(secretStore).connect(access, owner)
            val connected = connect as? SshConnectResult.Connected
                ?: throw AssertionError("Real SSH acceptance connect failed: ${safeConnectFailureName(connect)}")

            val handle = connected.handle
            try {
                assertTrue(handle.isOpen)
                assertEquals(accessId, handle.binding.serverAccessId)
                assertEquals(owner, handle.binding.owner)

                val result = handle.execute(
                    RemoteCommand.create(
                        raw = "printf VELUM_PHASE3_DEVICE_OK",
                        redactedLabel = "phase3-device-read-only-probe",
                    ),
                )
                assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
                assertEquals(CommandCompletion.ConfirmedSuccess, result.completion)
                assertFalse(result.stdout.truncated)
                assertFalse(result.stderr.truncated)
                assertArrayEquals(PROBE_OUTPUT, result.stdout.copyBytes())
                assertEquals(0, result.stderr.sizeBytes)
            } finally {
                handle.close()
                assertFalse(handle.isOpen)
            }
        } finally {
            parsed.closeSensitiveBytes()
            secretStore.delete(secretId)
            // Idempotent cleanup if parsing/connection failed before the parser's immediate delete path completed.
            runCatching { configFile.delete() }
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(
            "Target debug app must declare android.permission.INTERNET before real SSH acceptance",
            info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true,
        )
    }

    private fun safeConnectFailureName(result: SshConnectResult): String = when (result) {
        is SshConnectResult.Connected -> "Connected"
        is SshConnectResult.Failed -> result.failure::class.java.simpleName.ifBlank { "SshConnectFailure" }
    }

    companion object {
        private const val CONFIG_FILE_NAME = "phase3_2d_vps_acceptance.properties"
        private const val ACCEPTANCE_SECRET_ID = "phase3-2d-vps-acceptance-credential"
        private val PROBE_OUTPUT = "VELUM_PHASE3_DEVICE_OK".toByteArray(StandardCharsets.UTF_8)
    }
}

private enum class AcceptanceAuthMethod {
    PASSWORD,
    PRIVATE_KEY,
}

/** Sensitive fields are byte arrays so they can be wiped. Non-secret routing fields remain ordinary strings. */
private class OneShotAcceptanceConfig private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    val authMethod: AcceptanceAuthMethod,
    private var password: ByteArray?,
    private var privateKey: ByteArray?,
    private var passphrase: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial = when (authMethod) {
        AcceptanceAuthMethod.PASSWORD -> {
            val bytes = password ?: error("Password acceptance material is already closed")
            SecretMaterial.fromBytes(bytes)
        }
        AcceptanceAuthMethod.PRIVATE_KEY -> {
            val key = privateKey ?: error("Private-key acceptance material is already closed")
            SshPrivateKeyCredentialMaterial.create(key, passphrase)
        }
    }

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        privateKey?.let { Arrays.fill(it, 0) }
        passphrase?.let { Arrays.fill(it, 0) }
        password = null
        privateKey = null
        passphrase = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 2 * 1024 * 1024

        fun readAndDelete(file: File): OneShotAcceptanceConfig {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES) { "Acceptance config size is invalid" }
                val text = bytes.toString(StandardCharsets.US_ASCII)
                val values = text.lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val separator = line.indexOf('=')
                        require(separator > 0) { "Acceptance config line is malformed" }
                        line.substring(0, separator) to line.substring(separator + 1)
                    }

                require(values["version"] == "1") { "Acceptance config version is unsupported" }
                val host = decodeUtf8(values.require("host_b64"), "host")
                val username = decodeUtf8(values.require("username_b64"), "username")
                val hostKey = decodeUtf8(values.require("hostkey_b64"), "host key fingerprint")
                require(hostKey.startsWith("SHA256:") && hostKey.length > "SHA256:".length) {
                    "Acceptance host-key fingerprint must use canonical SHA256: form"
                }
                val port = values.require("port").toIntOrNull()
                    ?: throw IllegalArgumentException("Acceptance SSH port is invalid")
                require(port in 1..65535) { "Acceptance SSH port is invalid" }

                return when (values.require("auth")) {
                    "password" -> OneShotAcceptanceConfig(
                        host = host,
                        port = port,
                        username = username,
                        hostKeySha256 = hostKey,
                        authMethod = AcceptanceAuthMethod.PASSWORD,
                        password = decodeBytes(values.require("password_b64"), "password").also {
                            require(it.isNotEmpty()) { "Acceptance password must not be empty" }
                        },
                        privateKey = null,
                        passphrase = null,
                    )
                    "privatekey" -> {
                        val hasPassphrase = when (values.require("passphrase_present")) {
                            "0" -> false
                            "1" -> true
                            else -> throw IllegalArgumentException("Acceptance passphrase_present is invalid")
                        }
                        OneShotAcceptanceConfig(
                            host = host,
                            port = port,
                            username = username,
                            hostKeySha256 = hostKey,
                            authMethod = AcceptanceAuthMethod.PRIVATE_KEY,
                            password = null,
                            privateKey = decodeBytes(values.require("private_key_b64"), "private key").also {
                                require(it.isNotEmpty()) { "Acceptance private key must not be empty" }
                            },
                            passphrase = if (hasPassphrase) {
                                decodeBytes(values.require("passphrase_b64"), "passphrase")
                            } else {
                                null
                            },
                        )
                    }
                    else -> throw IllegalArgumentException("Acceptance SSH auth method is unsupported")
                }
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun Map<String, String>.require(key: String): String =
            get(key) ?: throw IllegalArgumentException("Acceptance config is missing $key")

        private fun decodeUtf8(value: String, field: String): String {
            val bytes = decodeBytes(value, field)
            return try {
                bytes.toString(StandardCharsets.UTF_8).also {
                    require(it.isNotBlank()) { "Acceptance $field must not be blank" }
                }
            } finally {
                Arrays.fill(bytes, 0)
            }
        }

        private fun decodeBytes(value: String, field: String): ByteArray = try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Acceptance $field is not valid base64")
        }
    }
}
