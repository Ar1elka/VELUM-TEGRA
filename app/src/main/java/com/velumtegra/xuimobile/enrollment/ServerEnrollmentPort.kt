package com.velumtegra.xuimobile.enrollment

import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.SshPrivateKeyCredentialMaterial
import java.time.Instant
import java.util.Arrays
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** UI has no direct Room, Keystore, SSH or arbitrary-target write capability. */
interface ServerEnrollmentPort {
    suspend fun addServer(displayName: String): EnrollmentResult

    /** Takes ownership of passwordBytes and wipes the supplied mutable buffer in all exit paths. */
    suspend fun addPasswordAccess(
        serverId: String,
        host: String,
        port: String,
        username: String,
        hostFingerprint: String,
        independentlyVerified: Boolean,
        passwordBytes: ByteArray,
    ): EnrollmentResult

    /** Takes ownership of BOTH buffers, including rejected input, and zeroes them in finally. */
    suspend fun addPrivateKeyAccess(
        serverId: String,
        host: String,
        port: String,
        username: String,
        hostFingerprint: String,
        independentlyVerified: Boolean,
        privateKeyBytes: ByteArray,
        passphraseBytes: ByteArray?,
    ): EnrollmentResult
}

sealed interface EnrollmentResult {
    data class Saved(val recordId: String) : EnrollmentResult
    data class Rejected(val message: String) : EnrollmentResult
}

/** Pure, fail-closed preflight: fingerprint is an externally verified pin, never TOFU. */
object EnrollmentInputPolicy {
    fun validateHostAndPort(host: String, port: String): String? {
        // No URI, embedded credentials, whitespace, slash or shell metacharacters.
        if (host.length !in 1..253 || !host.matches(Regex("[A-Za-z0-9.\\-:\\[\\]]+"))) {
            return "Адрес: только IP или домен, без схемы, пути и пробелов."
        }
        val numericPort = port.toIntOrNull()
        if (numericPort == null || numericPort !in 1..65535) return "SSH-порт должен быть от 1 до 65535."
        return null
    }

    fun validateName(displayName: String): String? = when {
        displayName.trim().isEmpty() -> "Укажите название сервера."
        displayName.trim().length > 80 || displayName.any { it.isISOControl() } -> "Название: не более 80 символов, без управляющих знаков."
        else -> null
    }

    fun validateAccess(
        serverId: String,
        host: String,
        port: String,
        username: String,
        fingerprint: String,
        verified: Boolean,
        secretLength: Int,
    ): String? {
        if (serverId.isBlank()) return "Не выбран точный сервер."
        validateHostAndPort(host, port)?.let { return it }
        if (!username.matches(Regex("[A-Za-z0-9_.@-]{1,64}"))) return "Недопустимое имя SSH-пользователя."
        if (fingerprint.isBlank() ||
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) !is HostKeyFingerprintParseResult.Valid
        ) {
            return "Укажите точный SSH host key в формате SHA256: (43 символа Base64)."
        }
        if (!verified) return "Сначала подтвердите независимую проверку отпечатка SSH-ключа."
        if (secretLength !in 1..4096) return "Пароль должен содержать от 1 до 4096 байт."
        return null
    }

    /** Never converts the complete private key into an immutable String. Syntax is only a preflight,
     * not proof the key can authenticate against any server. */
    fun validatePrivateKeyDocument(bytes: ByteArray): String? {
        if (bytes.size !in 1..BoundedPrivateKeyDocumentReader.MAX_KEY_BYTES) {
            return "Файл SSH-ключа должен иметь размер от 1 байта до 1 МиБ."
        }
        val formats = listOf(
            "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
            "DSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
        )
        val pair = formats.firstOrNull { kind ->
            val header = "-----BEGIN $kind-----".toByteArray(Charsets.US_ASCII)
            val footer = "-----END $kind-----".toByteArray(Charsets.US_ASCII)
            bytes.size > header.size + footer.size &&
                bytes.copyOfRange(0, header.size).contentEquals(header) &&
                bytes.copyOfRange(bytes.size - minOf(footer.size + 3, bytes.size), bytes.size)
                    .let { tail ->
                        val footerIndex = tail.indexOfSubArray(footer)
                        footerIndex >= 0 && tail.drop(footerIndex + footer.size).all {
                            it == 10.toByte() || it == 13.toByte()
                        }
                    }
        }
        if (pair == null) {
            return "Ожидается текстовый приватный PEM/OpenSSH-ключ с корректным BEGIN/END; публичные ключи не подходят."
        }
        // Known-unsupported types (Ed25519, DSA, hardware tokens) get an explicit message now rather than
        // an opaque "server rejected SSH authentication" after connecting.
        return UnsupportedPrivateKeyDetector.explain(bytes)
    }

    private fun ByteArray.indexOfSubArray(pattern: ByteArray): Int {
        if (pattern.size > size) return -1
        for (offset in 0..(size - pattern.size)) {
            if (pattern.indices.all { this[offset + it] == pattern[it] }) return offset
        }
        return -1
    }

    fun validatePrivateKeyAccess(
        serverId: String, host: String, port: String, username: String,
        fingerprint: String, verified: Boolean, privateKey: ByteArray,
        passphraseLength: Int,
    ): String? {
        validateAccess(serverId, host, port, username, fingerprint, verified, 1)?.let { return it }
        validatePrivateKeyDocument(privateKey)?.let { return it }
        if (passphraseLength !in 0..16_384) return "Парольная фраза SSH-ключа слишком длинная."
        return null
    }
}

/** Local-only storage adapter. No network I/O or SSH session creation. */
class LocalServerEnrollmentPort(
    private val servers: ServerRepository,
    private val credentials: CredentialTransactionService,
) : ServerEnrollmentPort {
    override suspend fun addServer(displayName: String): EnrollmentResult = withContext(Dispatchers.IO) {
        EnrollmentInputPolicy.validateName(displayName)?.let { return@withContext EnrollmentResult.Rejected(it) }
        val server = Server(ServerId(UUID.randomUUID().toString()), displayName.trim(), Instant.now())
        try {
            when (servers.create(server)) {
                is RepositoryResult.Success -> EnrollmentResult.Saved(server.id.value)
                else -> EnrollmentResult.Rejected("Не удалось создать сервер в локальной базе.")
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            EnrollmentResult.Rejected("Локальное хранилище недоступно. Запись не подтверждена.")
        }
    }

    override suspend fun addPasswordAccess(
        serverId: String,
        host: String,
        port: String,
        username: String,
        hostFingerprint: String,
        independentlyVerified: Boolean,
        passwordBytes: ByteArray,
    ): EnrollmentResult = try {
        withContext(Dispatchers.IO) {
            EnrollmentInputPolicy.validateAccess(
                serverId, host, port, username, hostFingerprint, independentlyVerified, passwordBytes.size,
            )?.let { return@withContext EnrollmentResult.Rejected(it) }
            val exactServerId = ServerId(serverId)
            if (servers.get(exactServerId) !is RepositoryResult.Success) {
                return@withContext EnrollmentResult.Rejected("Выбранный сервер не найден. Обновите список.")
            }
            val secretId = SecretId(UUID.randomUUID().toString())
            val accessId = ServerAccessId(UUID.randomUUID().toString())
            val access = ServerAccess(
                id = accessId,
                serverId = exactServerId,
                endpoint = SshEndpoint(host.trim(), requireNotNull(port.toIntOrNull())),
                username = username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(hostFingerprint),
            )
            // Secret created and verified in Keystore BEFORE Room publishes its SecretId reference.
            SecretMaterial.fromBytes(passwordBytes).use { material ->
                when (credentials.createServerAccess(access, material)) {
                    is CredentialTransactionResult.Success -> EnrollmentResult.Saved(accessId.value)
                    CredentialTransactionResult.SecretAlreadyExists -> EnrollmentResult.Rejected("Конфликт идентификатора секрета. Повторите попытку.")
                    else -> EnrollmentResult.Rejected("SSH-доступ не сохранён: защищённое хранилище или база отклонили запись.")
                }
            }
        }
    } catch (cancel: CancellationException) {
        throw cancel
    } catch (_: Exception) {
        EnrollmentResult.Rejected("SSH-доступ не подтверждён. Проверьте локальное хранилище.")
    } finally {
        Arrays.fill(passwordBytes, 0)
    }

    override suspend fun addPrivateKeyAccess(
        serverId: String,
        host: String,
        port: String,
        username: String,
        hostFingerprint: String,
        independentlyVerified: Boolean,
        privateKeyBytes: ByteArray,
        passphraseBytes: ByteArray?,
    ): EnrollmentResult = try {
        withContext(Dispatchers.IO) {
            EnrollmentInputPolicy.validatePrivateKeyAccess(
                serverId, host, port, username, hostFingerprint,
                independentlyVerified, privateKeyBytes, passphraseBytes?.size ?: 0,
            )?.let { return@withContext EnrollmentResult.Rejected(it) }
            val exactServerId = ServerId(serverId)
            if (servers.get(exactServerId) !is RepositoryResult.Success) {
                return@withContext EnrollmentResult.Rejected("Выбранный сервер не найден. Обновите список.")
            }
            val secretId = SecretId(UUID.randomUUID().toString())
            val accessId = ServerAccessId(UUID.randomUUID().toString())
            val access = ServerAccess(
                id = accessId,
                serverId = exactServerId,
                endpoint = SshEndpoint(host.trim(), requireNotNull(port.toIntOrNull())),
                username = username,
                auth = SshAuthRef.PrivateKey(secretId),
                pinnedHostKey = HostKeyFingerprint(hostFingerprint),
            )
            // Existing canonical SSH secret envelope: key + optional passphrase; outer
            // SecretStore uses Android Keystore; read-back precedes Room reference publication.
            SshPrivateKeyCredentialMaterial.create(privateKeyBytes, passphraseBytes).use { material ->
                when (credentials.createServerAccess(access, material)) {
                    is CredentialTransactionResult.Success -> EnrollmentResult.Saved(accessId.value)
                    CredentialTransactionResult.SecretAlreadyExists -> EnrollmentResult.Rejected("Конфликт идентификатора секрета. Повторите попытку.")
                    else -> EnrollmentResult.Rejected("SSH-ключ не сохранён: защищённое хранилище или база отклонили запись.")
                }
            }
        }
    } catch (cancel: CancellationException) {
        throw cancel
    } catch (_: Exception) {
        EnrollmentResult.Rejected("SSH-ключ не подтверждён. Проверьте локальное хранилище.")
    } finally {
        Arrays.fill(privateKeyBytes, 0)
        passphraseBytes?.let { Arrays.fill(it, 0) }
    }

}
