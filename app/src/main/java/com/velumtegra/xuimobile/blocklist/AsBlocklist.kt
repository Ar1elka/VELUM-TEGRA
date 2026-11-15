package com.velumtegra.xuimobile.blocklist

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
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
import com.velumtegra.xuimobile.sshport.SshPortProfile
import java.time.Duration
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** What the server reported about the AS_Network_List protection. Parsed from marker lines only. */
internal data class AsBlocklistStatus(
    val os: String,
    val installed: Boolean,
    /** "nft", "ipset" or "none" when neither is present yet and a package has to be installed. */
    val backend: String,
    val active: Boolean,
    val blockVk: Boolean,
    val gov4: Int,
    val gov6: Int,
    val vk4: Int,
    val vk6: Int,
    val updatedEpochSeconds: Long?,
    val dropped: Long,
    /** "timer", "cron", "stopped" or "none". */
    val autoUpdate: String,
    val otherFirewalls: List<String>,
    val packageManager: String,
) {
    val backendLabel: String
        get() = when (backend) {
            "nft" -> "nftables"
            "ipset" -> "ipset + iptables"
            else -> when (packageManager) {
                "none", "" -> "не найден"
                else -> "nftables (будет установлен через $packageManager)"
            }
        }

    val osLabel: String get() = os.ifBlank { "Linux (название не определено)" }

    companion object {
        private const val INFO = "VELUM_BL_INFO:"
        private const val CODE = "VELUM_BL:"

        /** The single reply code, or null when the output is missing, duplicated or foreign. */
        fun replyCode(stdout: String): String? =
            stdout.lineSequence().map { it.trim() }.filter { it.startsWith(CODE) }.toList()
                .singleOrNull()?.removePrefix(CODE)?.takeIf { code -> code.isNotEmpty() && code.all { it in 'A'..'Z' || it == '_' } }

        fun parse(stdout: String): AsBlocklistStatus? {
            val values = stdout.lineSequence().map { it.trim() }.filter { it.startsWith(INFO) }
                .map { it.removePrefix(INFO) }.filter { '=' in it }
                .associate { it.substringBefore('=') to it.substringAfter('=').trim() }
            if ("installed" !in values || "backend" !in values) return null
            fun number(key: String) = values[key]?.toLongOrNull()?.coerceAtLeast(0) ?: 0
            return AsBlocklistStatus(
                os = values["os"].orEmpty().take(60),
                installed = values["installed"] == "1",
                backend = values["backend"].orEmpty().takeIf { it == "nft" || it == "ipset" } ?: "none",
                active = values["active"] == "1",
                blockVk = values["vk"] == "1",
                gov4 = number("gov4").toInt(),
                gov6 = number("gov6").toInt(),
                vk4 = number("vk4").toInt(),
                vk6 = number("vk6").toInt(),
                updatedEpochSeconds = values["updated"]?.toLongOrNull()?.takeIf { it > 0 },
                dropped = number("dropped"),
                autoUpdate = values["auto"].orEmpty().ifBlank { "none" },
                otherFirewalls = values["firewalls"].orEmpty().split(' ').filter { it.isNotBlank() },
                packageManager = values["package_manager"].orEmpty().ifBlank { "none" },
            )
        }

        fun failureText(code: String?): String = when (code) {
            "ROOT_REQUIRED" -> "Нужен вход root или sudo без пароля. Выберите SSH-профиль с такими правами."
            "NO_FIREWALL" -> "На сервере нет nftables и ipset, и установить их не получилось. " +
                "Так бывает на VPS с виртуализацией OpenVZ/LXC: там файрвол настраивается у провайдера."
            "NO_DOWNLOADER" -> "На сервере нет curl и wget, и установить curl не получилось."
            "DOWNLOAD" -> "Сервер не смог скачать списки с GitHub. Проверьте, что с VPS открыт raw.githubusercontent.com, и повторите."
            "BAD_LIST" -> "Скачанный список оказался пустым или повреждённым. Правила на сервере не менялись."
            "YOUR_IP_LISTED" -> "Ваш текущий IP-адрес входит в блокируемые сети. Защита не включена, чтобы вы не потеряли доступ к серверу. " +
                "Подключитесь через другую сеть или VPN и повторите."
            "APPLY" -> "Файрвол сервера не принял правила. Прежнее состояние сохранено."
            "BUSY" -> "На сервере уже выполняется обновление списков. Повторите через минуту."
            "NOT_INSTALLED" -> "Защита на этом сервере не установлена."
            "STATE", "TEMP" -> "Сервер не смог сохранить файлы защиты. Проверьте свободное место на диске."
            else -> "Сервер не подтвердил результат. Нажмите «Проверить сервер», чтобы увидеть текущее состояние."
        }
    }
}

internal sealed interface AsBlocklistResult {
    data class Ready(val status: AsBlocklistStatus, val code: String) : AsBlocklistResult
    data class Blocked(val reason: String) : AsBlocklistResult
}

internal enum class AsBlocklistAction(val argument: String, val timeoutSeconds: Long) {
    STATUS("status", 45), INSTALL("install", 240), REMOVE("remove", 90),
}

/**
 * Installs, refreshes and removes the C24Be/AS_Network_List firewall rules on a VPS through a saved,
 * host-key-pinned SSH profile. The server-side script picks the firewall that fits the system itself.
 */
internal class AsBlocklistManager(
    private val accesses: ServerAccessRepository,
    private val connections: SshConnectionFactory,
    private val runtime: OperationRuntimeCoordinator,
    private val listProfiles: suspend () -> List<SshPortProfile>?,
    private val script: () -> String,
) {
    suspend fun profiles(): List<SshPortProfile>? = listProfiles()

    suspend fun run(profile: SshPortProfile, action: AsBlocklistAction, blockVk: Boolean): AsBlocklistResult =
        withContext(Dispatchers.IO) {
            try {
                val id = UUID.randomUUID().toString()
                val operation = OperationId(id)
                runtime.withExclusiveServerMaintenanceLease(profile.serverId, operation) {
                    val access = (accesses.get(ServerAccessId(profile.access.accessId)) as? RepositoryResult.Success)?.value
                        ?.takeIf {
                            it.serverId == profile.serverId && it.endpoint.host == profile.access.host &&
                                it.endpoint.port == profile.access.port && it.username == profile.access.username
                        } ?: abort("SSH-профиль изменился. Выберите его заново.")
                    connected(access, SessionOwner.Operation(operation)) { remote(it, action, blockVk) }
                } ?: AsBlocklistResult.Blocked("Дождитесь завершения текущей операции с этим VPS.")
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (failure: BlocklistFailure) {
                AsBlocklistResult.Blocked(failure.message.orEmpty())
            } catch (failure: Exception) {
                android.util.Log.w(TAG, "failed: ${failure.javaClass.simpleName}")
                AsBlocklistResult.Blocked("Связь с VPS прервалась. Нажмите «Проверить сервер», чтобы увидеть текущее состояние.")
            }
        }

    private suspend fun connected(
        access: ServerAccess,
        owner: SessionOwner,
        action: suspend (SshSessionHandle) -> AsBlocklistResult,
    ): AsBlocklistResult {
        val expected = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) as? HostKeyFingerprintParseResult.Valid)
            ?.fingerprint?.asHexSha256() ?: abort("У профиля нет действительного сохранённого SSH-ключа сервера.")
        // Mobile links drop single TCP handshakes; retrying before authentication changes nothing on the VPS.
        var connected = connections.connect(access, owner)
        for (attempt in 2..CONNECT_ATTEMPTS) {
            val failure = (connected as? SshConnectResult.Failed)?.failure ?: break
            if (failure !is SshConnectFailure.Timeout && failure !is SshConnectFailure.Unreachable) break
            delay(CONNECT_RETRY_DELAY_MS)
            connected = connections.connect(access, owner)
        }
        return when (connected) {
            is SshConnectResult.Failed -> abort(when (connected.failure) {
                is SshConnectFailure.HostIdentityMismatch -> "Ключ сервера отличается от сохранённого. Подключение отменено."
                SshConnectFailure.AuthenticationRejected -> "Сервер отклонил вход по этому SSH-профилю."
                else -> "Не удалось подключиться к ${access.endpoint.host}:${access.endpoint.port}. Проверьте сеть и SSH-порт."
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

    private suspend fun remote(session: SshSessionHandle, action: AsBlocklistAction, blockVk: Boolean): AsBlocklistResult {
        val arguments = if (action == AsBlocklistAction.INSTALL) "install ${if (blockVk) 1 else 0}" else action.argument
        // The script has to exist as a file: on install it copies itself to the server for the daily timer.
        val command = RemoteCommand.create(
            "velum_bl=\$(mktemp) || exit 1\n" +
                "cat > \"\$velum_bl\" <<'VELUM_AS_BLOCKLIST_SCRIPT'\n" + script().trimEnd() + "\nVELUM_AS_BLOCKLIST_SCRIPT\n" +
                "sh \"\$velum_bl\" $arguments; velum_rc=\$?; rm -f \"\$velum_bl\"; exit \$velum_rc\n",
            "as-blocklist-${action.argument}",
        )
        val result = session.execute(command, SshTransportConfig(
            commandExecutionTimeout = Duration.ofSeconds(action.timeoutSeconds),
            stdoutCaptureLimitBytes = 8_192, stderrCaptureLimitBytes = 4_096,
        ))
        val stdout = result.stdout.copyBytes().toString(Charsets.UTF_8)
        val code = AsBlocklistStatus.replyCode(stdout)
        // Diagnostic only: action, reply code and completion; no host, credentials or output.
        android.util.Log.i(TAG, "${action.argument}: code=$code completion=${result.completion} truncated=${result.stdout.truncated}")
        val status = AsBlocklistStatus.parse(stdout)
        if (code in SUCCESS_CODES && code != null && status != null && !result.stdout.truncated) {
            return AsBlocklistResult.Ready(status, code)
        }
        abort(AsBlocklistStatus.failureText(code))
    }

    private class BlocklistFailure(message: String) : Exception(message)
    private fun abort(message: String): Nothing = throw BlocklistFailure(message)

    private companion object {
        const val TAG = "VelumAsBlocklist"
        const val CONNECT_ATTEMPTS = 3
        const val CONNECT_RETRY_DELAY_MS = 2_000L
        val SUCCESS_CODES = setOf("OK", "INSTALLED", "REMOVED")
    }
}
