package com.velumtegra.xuimobile.sshport

import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessPolicy
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import java.security.SecureRandom
import java.time.Duration
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal const val STANDARD_SSH_PORT = 22

internal object SshPortPolicy {
    private val random = SecureRandom()

    fun parse(value: String): Int? =
        value.trim().takeIf { it.length in 1..5 && it.all { digit -> digit in '0'..'9' } }
            ?.toIntOrNull()?.takeIf { it in 1..65535 && it != STANDARD_SSH_PORT }

    fun randomPort(): Int = 49_152 + random.nextInt(16_384)
}

internal data class SshPortProfile(
    val serverId: ServerId,
    val serverName: String,
    val access: LocalSshAccessSummary,
) {
    val hostLabel: String
        get() = access.host.let { if (':' in it && !it.startsWith('[')) "[$it]" else it }

    val target: String get() = "${access.username}@$hostLabel:${access.port}"
}

internal sealed interface SshPortResult {
    data class Switched(val profile: SshPortProfile) : SshPortResult
    data object Closed : SshPortResult
    data class Blocked(val reason: String) : SshPortResult
}

internal class SshPortMigration(
    private val servers: ServerRepository,
    private val accesses: RoomServerAccessRepository,
    private val connections: SshConnectionFactory,
    private val journal: OperationJournal,
    private val runtime: OperationRuntimeCoordinator,
    private val script: () -> String,
) {
    suspend fun profiles(): List<SshPortProfile>? = withContext(Dispatchers.IO) {
        val stored = (servers.list() as? RepositoryResult.Success)?.value ?: return@withContext null
        buildList {
            for (record in stored) {
                val server = record.value
                val profiles = (accesses.listForServer(server.id) as? RepositoryResult.Success)?.value
                    ?: return@withContext null
                for (access in profiles) {
                    summary(server.id, server.displayName, access)?.let { add(it) }
                }
            }
        }
    }

    suspend fun switch(profile: SshPortProfile, port: Int): SshPortResult {
        if (profile.access.port != STANDARD_SSH_PORT || SshPortPolicy.parse(port.toString()) != port) {
            return SshPortResult.Blocked("Выберите сохранённый SSH-профиль на 22 и другой порт от 1 до 65535.")
        }
        return withReviewedAccess(profile) { old, owner, token ->
            val candidate = old.copy(id = ServerAccessId(UUID.randomUUID().toString()), endpoint = old.endpoint.copy(port = port))
            connected(old, owner) { remote(it, Action.PREPARE, port, token, "READY") }
            try {
                connected(candidate, owner) { session ->
                    if (readExact(profile) != old) abort("Исходный SSH-профиль изменился. Старый порт сохранён.")
                    remote(session, Action.PERSIST, port, token, "SAVED")
                }
            } catch (failure: MigrationFailure) {
                abort(failure.message.orEmpty() + " Вход на 22 сохранён. Если новый порт блокируется, разрешите TCP $port в файрволе VPS и у провайдера.")
            }
            val published = (accesses.publishVerifiedSshPort(old, candidate) as? RepositoryResult.Success)?.value
                ?: abort("Новый порт проверен и включён, но сохранить профиль на телефоне не удалось. Повторите переход с порта 22.")
            val newProfile = summary(profile.serverId, profile.serverName, published)
                ?: abort("Новый профиль сохранён. Обновите список SSH-профилей.")
            SshPortResult.Switched(newProfile)
        }
    }

    suspend fun closeStandardPort(profile: SshPortProfile): SshPortResult {
        val port = profile.access.port
        if (SshPortPolicy.parse(port.toString()) != port) {
            return SshPortResult.Blocked("Сначала перенесите SSH-вход на новый порт.")
        }
        return withReviewedAccess(profile) { active, owner, token ->
            if (port22StillLinked(profile.serverId)) {
                abort("На порте 22 остаются привязанные профили X-UI или веб-панели. Перенесите их перед закрытием.")
            }
            connected(active, owner) { remote(it, Action.CLOSE, port, token, "CLOSED_PENDING") }
            try {
                connected(active, owner) { session ->
                    if (readExact(profile) != active || port22StillLinked(profile.serverId)) {
                        abort("Профиль или его связи изменились во время проверки.")
                    }
                    remote(session, Action.FINISH, port, token, "CLOSED")
                }
            } catch (failure: MigrationFailure) {
                abort(failure.message.orEmpty() + " Если закрытие не подтвердилось, сервер попытается восстановить порт 22 через две минуты.")
            }
            SshPortResult.Closed
        }
    }

    private suspend fun port22StillLinked(server: ServerId): Boolean =
        (accesses.hasSshPortLinks(server, STANDARD_SSH_PORT) as? RepositoryResult.Success)?.value
            ?: abort("Не удалось проверить сохранённые связи порта 22.")

    private suspend fun withReviewedAccess(
        profile: SshPortProfile,
        action: suspend (ServerAccess, SessionOwner, String) -> SshPortResult,
    ): SshPortResult = withContext(Dispatchers.IO) {
        try {
            val id = UUID.randomUUID().toString()
            val operation = OperationId(id)
            runtime.withExclusiveServerMaintenanceLease(profile.serverId, operation) {
                val unfinished = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: abort("Не удалось проверить журнал операций VPS.")
                if (unfinished.any { it.snapshot.target.serverId == profile.serverId }) {
                    abort("На VPS есть незавершённая операция. Завершите её перед сменой SSH-порта.")
                }
                val access = readExact(profile) ?: abort("SSH-профиль изменился. Выберите его заново.")
                action(access, SessionOwner.Operation(operation), id.replace("-", ""))
            } ?: SshPortResult.Blocked("Дождитесь завершения текущей операции с VPS.")
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (failure: MigrationFailure) {
            android.util.Log.w("VelumSshPort", "blocked: ${failure.message}")
            SshPortResult.Blocked(failure.message.orEmpty())
        } catch (failure: Exception) {
            android.util.Log.w("VelumSshPort", "failed: ${failure.javaClass.simpleName}")
            SshPortResult.Blocked("Связь с VPS или хранилищем прервалась. Проверьте доступ перед повтором.")
        }
    }

    private suspend fun readExact(profile: SshPortProfile): ServerAccess? {
        val server = (servers.get(profile.serverId) as? RepositoryResult.Success)?.value?.value ?: return null
        val access = (accesses.get(ServerAccessId(profile.access.accessId)) as? RepositoryResult.Success)?.value
            ?: return null
        return access.takeIf { summary(server.id, server.displayName, it) == profile }
    }

    private fun summary(id: ServerId, name: String, access: ServerAccess): SshPortProfile? =
        (LocalSshReadinessPolicy.inspect(id.value, access.id.value, access) as? LocalSshReadinessResult.MetadataPresent)
            ?.let { SshPortProfile(id, name, it.summary) }

    private suspend fun connected(
        access: ServerAccess,
        owner: SessionOwner,
        action: suspend (SshSessionHandle) -> Unit,
    ) {
        val expected = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) as? HostKeyFingerprintParseResult.Valid)
            ?.fingerprint?.asHexSha256() ?: abort("У профиля нет действительного сохранённого SSH-ключа сервера.")
        // Mobile/VPN links drop single TCP handshakes. Retrying before authentication changes nothing on the VPS,
        // and every migration step has a server-side restore timer (120-180 s) covering these few retries.
        var connected = connections.connect(access, owner)
        for (attempt in 2..CONNECT_ATTEMPTS) {
            val failure = (connected as? SshConnectResult.Failed)?.failure ?: break
            if (failure !is SshConnectFailure.Timeout && failure !is SshConnectFailure.Unreachable) break
            android.util.Log.w("VelumSshPort", "connect ${access.endpoint.port}: $failure, retry $attempt")
            kotlinx.coroutines.delay(CONNECT_RETRY_DELAY_MS)
            connected = connections.connect(access, owner)
        }
        when (connected) {
            is SshConnectResult.Failed -> abort(when (connected.failure.also {
                android.util.Log.w("VelumSshPort", "connect ${access.endpoint.port}: $it")
            }) {
                is SshConnectFailure.HostIdentityMismatch -> "Ключ сервера на порту ${access.endpoint.port} отличается от сохранённого."
                SshConnectFailure.AuthenticationRejected -> "Сервер отклонил вход на порт ${access.endpoint.port}."
                else -> "Не удалось подключиться к порту ${access.endpoint.port}."
            })
            is SshConnectResult.Connected -> connected.handle.use { session ->
                val actual = (session as? VerifiedHostKeySshSessionHandle)?.verifiedHostKeySha256
                if (session.binding.owner != owner || session.binding.serverAccessId != access.id ||
                    !session.isOpen || actual != expected
                ) abort("SSH-сессия не подтвердила ожидаемый ключ сервера.")
                action(session)
            }
        }
    }

    private suspend fun remote(session: SshSessionHandle, action: Action, port: Int, token: String, success: String) {
        val command = RemoteCommand.create(
            "/bin/sh -s -- ${action.argument} $port $token <<'VELUM_SSH_PORT_SCRIPT'\n" +
                script() + "\nVELUM_SSH_PORT_SCRIPT\n",
            "ssh-port-${action.argument}",
        )
        val result = session.execute(command, SshTransportConfig(
            commandExecutionTimeout = Duration.ofSeconds(50),
            stdoutCaptureLimitBytes = 4_096, stderrCaptureLimitBytes = 4_096,
        ))
        val code = result.stdout.copyBytes().toString(Charsets.UTF_8).lineSequence()
            .map { it.trim() }.filter { it.startsWith("VELUM_SSH_PORT:") }.singleOrNull()
            ?.removePrefix("VELUM_SSH_PORT:")
        // Diagnostic only: action, server reply code and completion; no host, credentials or output.
        android.util.Log.i("VelumSshPort", "${action.argument}: code=$code completion=${result.completion} " +
            "dispatch=${result.dispatchState} truncated=${result.stdout.truncated}")
        if (code == success && !result.stdout.truncated && result.completion == CommandCompletion.ConfirmedSuccess) return
        if (code == "BUSY" && action == Action.CLOSE) {
            abort("Предыдущее закрытие порта 22 ещё не подтверждено. Подождите две минуты: сервер вернёт порт 22, затем повторите.")
        }
        abort(when (code) {
            "ROOT_REQUIRED" -> "Для смены порта нужен сохранённый вход root."
            "UNSUPPORTED", "CUSTOM_CONFIG" -> "Автосмена поддерживает стандартный OpenSSH Debian и Ubuntu с systemd. Настройки этого VPS требуют ручной смены."
            "CONFIG_CHECK" -> "Проверка конфигурации OpenSSH не прошла."
            "PORT_BUSY" -> "TCP-порт $port уже занят на VPS. Выберите другой."
            "OTHER_MIGRATION", "BUSY" -> "У VPS уже есть подготовленный порт или выполняется другой переход."
            "TIMER_FAILED" -> "Сервер не смог запустить таймер восстановления."
            "CONFIG_WRITE", "START_FAILED" -> "Сервер не смог запустить или сохранить новый слушатель OpenSSH."
            "STAGE_EXPIRED" -> "Время подтверждения истекло. Проверьте оба порта."
            "NEW_NOT_VERIFIED" -> "Выбранный порт не принадлежит проверенному слушателю, созданному приложением."
            "WRONG_PORT" -> "SSH-сервер принял соединение на другом внутреннем порту."
            "OLD_NOT_FOUND" -> "Активный стандартный SSH-вход на 22 не найден."
            "CLOSE_PENDING" -> "Закрытие порта 22 не подтверждено. На сервере действует таймер восстановления."
            else -> "Сервер не подтвердил результат операции. Проверьте доступ перед повтором."
        })
    }

    private enum class Action(val argument: String) {
        PREPARE("prepare"), PERSIST("persist"), CLOSE("close"), FINISH("finish"),
    }

    private companion object {
        const val CONNECT_ATTEMPTS = 3
        const val CONNECT_RETRY_DELAY_MS = 2_000L
    }

    private class MigrationFailure(message: String) : Exception(message)
    private fun abort(message: String): Nothing = throw MigrationFailure(message)
}
