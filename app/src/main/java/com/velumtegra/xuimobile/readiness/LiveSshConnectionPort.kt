package com.velumtegra.xuimobile.readiness

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** The sole opt-in real SSH capability for the UI; only authenticates and closes, never executes a command. */
interface LiveSshConnectionPort {
    suspend fun connectExact(
        serverId: String,
        accessId: String,
        reviewed: LocalSshAccessSummary,
        typedTarget: String,
        consent: Boolean,
    ): LiveSshConnectionResult
}

sealed interface LiveSshConnectionResult {
    data class Verified(
        val target: String,
        val fingerprint: String,
        /** Read-only server profile collected in the same verified session; null if it could not be read. */
        val profile: com.velumtegra.xuimobile.core.ssh.ServerProfile? = null,
    ) : LiveSshConnectionResult
    data class Blocked(val message: String) : LiveSshConnectionResult
}

/**
 * Pure policy: any changed endpoint, pin, username or credential reference revokes the UI review.
 * Backend independently re-reads the actual records immediately before the network attempt.
 */
object LiveSshConnectionPolicy {
    fun exactTarget(summary: LocalSshAccessSummary): String =
        "${summary.username}@${summary.host}:${summary.port}"

    fun preflight(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        fresh: LocalSshReadinessResult, typedTarget: String, consent: Boolean,
    ): String? {
        if (!consent) return "Сначала подтвердите разрешение на реальное SSH-подключение."
        if (serverId.isBlank() || accessId.isBlank() || reviewed.accessId != accessId) {
            return "Выбранный SSH-доступ недействителен."
        }
        val current = (fresh as? LocalSshReadinessResult.MetadataPresent)?.summary
            ?: return "SSH-доступ недоступен: повторите проверку."
        if (current != reviewed || current.credentialRefDigest.isBlank()) {
            return "Параметры SSH-доступа изменились. Выберите его заново."
        }
        if (typedTarget != exactTarget(current)) {
            return "Повторите точную SSH-цель без изменений."
        }
        return null
    }
}

class RepositoryLiveSshConnectionPort(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
    private val connectionFactory: SshConnectionFactory,
) : LiveSshConnectionPort {
    override suspend fun connectExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        typedTarget: String, consent: Boolean,
    ): LiveSshConnectionResult = withContext(Dispatchers.IO) {
        fun block(message: String): LiveSshConnectionResult = LiveSshConnectionResult.Blocked(message)
        try {
            // Never obtain a secret or establish a socket for missing/invalid user consent.
            if (!consent || serverId.isBlank() || accessId.isBlank() || reviewed.accessId != accessId ||
                typedTarget != LiveSshConnectionPolicy.exactTarget(reviewed)) {
                return@withContext block("Выберите доступ и подтвердите точную цель подключения.")
            }
            val server = when (val read = servers.get(ServerId(serverId))) {
                is RepositoryResult.Success -> read.value.value
                else -> return@withContext block("Выбранный сервер больше не существует.")
            }
            if (server.id.value != serverId) return@withContext block("Несоответствие выбранного Server ID.")
            val access = when (val read = accesses.get(ServerAccessId(accessId))) {
                is RepositoryResult.Success -> read.value
                else -> return@withContext block("SSH-доступ отсутствует. Обновите список.")
            }
            val fresh = LocalSshReadinessPolicy.inspect(serverId, accessId, access)
            LiveSshConnectionPolicy.preflight(serverId, accessId, reviewed, fresh, typedTarget, consent)
                ?.let { return@withContext block(it) }
            val parsed = CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)
                as? HostKeyFingerprintParseResult.Valid
                ?: return@withContext block("Сохранённый SSH-отпечаток некорректен.")
            // Explicit per-click owner; no remote command, tunnel, retry, fallback or VPS mutation.
            when (val outcome = connectionFactory.connect(
                access, SessionOwner.Operation(OperationId(UUID.randomUUID().toString())),
            )) {
                is SshConnectResult.Failed -> block(safeFailure(outcome.failure))
                is SshConnectResult.Connected -> {
                    val handle = outcome.handle
                    try {
                        val verified = handle as? VerifiedHostKeySshSessionHandle
                        if (handle.binding.serverAccessId != access.id || !handle.isOpen ||
                            verified?.verifiedHostKeySha256 != parsed.fingerprint.asHexSha256()) {
                            block("SSH-сессия не подтвердила точный сохранённый ключ сервера.")
                        } else {
                            // One read-only command: OS, rights, package manager, cloud, firewall, resources.
                            val profile = try {
                                com.velumtegra.xuimobile.core.ssh.ServerProfileProbe.read(handle)
                            } catch (cancel: CancellationException) {
                                throw cancel
                            } catch (_: Exception) {
                                null
                            }
                            LiveSshConnectionResult.Verified(typedTarget, parsed.fingerprint.asString(), profile)
                        }
                    } finally {
                        handle.close()
                    }
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            block("SSH-подключение не удалось. Данные доступа и VPS не изменены.")
        }
    }

    private fun safeFailure(failure: SshConnectFailure): String = when (failure) {
        is SshConnectFailure.HostIdentityMismatch -> "SSH-ключ сервера не совпадает с сохранённым. Соединение отклонено."
        SshConnectFailure.AuthenticationRejected -> "Сервер отклонил SSH-аутентификацию."
        is SshConnectFailure.Timeout -> "Превышено время ожидания SSH-подключения."
        is SshConnectFailure.Unreachable -> "SSH-сервер недоступен."
        is SshConnectFailure.NegotiationFailure -> "Сервер не согласовал поддерживаемые SSH-алгоритмы."
        is SshConnectFailure.SecretUnavailable, is SshConnectFailure.SecretCorrupt,
        is SshConnectFailure.SecretStorageFailure -> "Секрет SSH недоступен в защищённом хранилище."
        is SshConnectFailure.InvalidConfiguration -> "Сохранённые SSH-настройки некорректны."
        SshConnectFailure.Cancelled -> "SSH-подключение отменено."
        is SshConnectFailure.Unexpected -> "Ошибка установки SSH-сессии."
    }
}
