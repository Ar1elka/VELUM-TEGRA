package com.velumtegra.xuimobile.readiness

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Read-only metadata. No SecretStore, password/key bytes, transport or mutable database capability. */
data class LocalSshAccessSummary(
    val accessId: String,
    val host: String,
    val port: Int,
    val username: String,
    val authLabel: String,
    val savedFingerprint: String,
    /** SHA-256 over NON-SECRET reference identity; never display the SecretId or read its contents. */
    val credentialRefDigest: String = "",
)

sealed interface LocalSshAccessList {
    data class Available(val items: List<LocalSshAccessSummary>) : LocalSshAccessList
    data class Unavailable(val reason: String) : LocalSshAccessList
}

sealed interface LocalSshReadinessResult {
    data class MetadataPresent(val summary: LocalSshAccessSummary) : LocalSshReadinessResult
    data class Blocked(val reason: String) : LocalSshReadinessResult
}

interface SshReadinessPort {
    suspend fun listForExactServer(serverId: String): LocalSshAccessList
    suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult
}

/** Pure fail-closed policy. This does NOT verify remote identity or secret decryption. */
object LocalSshReadinessPolicy {
    /** Stable offline metadata revision. The SHA input is a local reference ID, NOT a password/key. */
    fun credentialRefDigest(ref: SshAuthRef): String? {
        val id = ref.secretId.value
        if (id.isBlank()) return null
        val kind = when (ref) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest("$kind:$id".toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    fun inspect(serverId: String, accessId: String, access: ServerAccess?): LocalSshReadinessResult {
        if (serverId.isBlank() || accessId.isBlank() || access == null) {
            return LocalSshReadinessResult.Blocked("Нужно выбрать существующие Server ID и SSH Access ID.")
        }
        if (access.serverId.value != serverId || access.id.value != accessId) {
            return LocalSshReadinessResult.Blocked("SSH-доступ не принадлежит выбранному серверу: проверка запрещена.")
        }
        if (access.endpoint.host.length !in 1..253 ||
            !access.endpoint.host.matches(Regex("[A-Za-z0-9.\\-:\\[\\]]+")) ||
            access.endpoint.port !in 1..65535 ||
            !access.username.matches(Regex("[A-Za-z0-9_.@-]{1,64}"))) {
            return LocalSshReadinessResult.Blocked("У выбранного доступа неполные SSH-метаданные.")
        }
        if (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) !is HostKeyFingerprintParseResult.Valid) {
            return LocalSshReadinessResult.Blocked("Сохранённый SSH host key имеет некорректный SHA-256 отпечаток.")
        }
        val authLabel = when (access.auth) {
            is SshAuthRef.Password -> "Пароль (ссылка на секрет)"
            is SshAuthRef.PrivateKey -> "Приватный ключ (ссылка на секрет)"
        }
        val credentialRefDigest = credentialRefDigest(access.auth)
            ?: return LocalSshReadinessResult.Blocked("Не указан SecretId для выбранного SSH-доступа.")
        return LocalSshReadinessResult.MetadataPresent(
            LocalSshAccessSummary(
                accessId = access.id.value,
                host = access.endpoint.host,
                port = access.endpoint.port,
                username = access.username,
                authLabel = authLabel,
                savedFingerprint = access.pinnedHostKey.value,
                credentialRefDigest = credentialRefDigest,
            ),
        )
    }
}

/** Deliberately only calls local repository get/list methods. Not a connection probe. */
class RepositorySshReadinessPort(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
) : SshReadinessPort {
    override suspend fun listForExactServer(serverId: String): LocalSshAccessList = withContext(Dispatchers.IO) {
        try {
            if (serverId.isBlank() || servers.get(ServerId(serverId)) !is RepositoryResult.Success) {
                return@withContext LocalSshAccessList.Unavailable("Выбранный сервер не найден в локальной базе.")
            }
            when (val result = accesses.listForServer(ServerId(serverId))) {
                is RepositoryResult.Success -> LocalSshAccessList.Available(result.value.map { access ->
                    // Do not send secret material, SecretId or internal crypto metadata into Compose.
                    val type = when (access.auth) {
                        is SshAuthRef.Password -> "Пароль"
                        is SshAuthRef.PrivateKey -> "Приватный ключ"
                    }
                    LocalSshAccessSummary(
                        access.id.value, access.endpoint.host, access.endpoint.port,
                        access.username, type, access.pinnedHostKey.value,
                        LocalSshReadinessPolicy.credentialRefDigest(access.auth).orEmpty(),
                    )
                }.sortedBy { it.accessId })
                else -> LocalSshAccessList.Unavailable("Не удалось прочитать локальный список SSH-доступов.")
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            LocalSshAccessList.Unavailable("Ошибка чтения локального хранилища. Никаких проверок по сети не выполнялось.")
        }
    }

    override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult = withContext(Dispatchers.IO) {
        try {
            if (serverId.isBlank() || accessId.isBlank()) {
                return@withContext LocalSshReadinessResult.Blocked("Сервер и SSH-доступ должны быть выбраны явно.")
            }
            if (servers.get(ServerId(serverId)) !is RepositoryResult.Success) {
                return@withContext LocalSshReadinessResult.Blocked("Выбранный сервер больше не существует.")
            }
            val exact = when (val read = accesses.get(ServerAccessId(accessId))) {
                is RepositoryResult.Success -> read.value
                else -> return@withContext LocalSshReadinessResult.Blocked("SSH-доступ не найден в локальной базе.")
            }
            LocalSshReadinessPolicy.inspect(serverId, accessId, exact)
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            LocalSshReadinessResult.Blocked("Не удалось выполнить локальную проверку метаданных.")
        }
    }
}
