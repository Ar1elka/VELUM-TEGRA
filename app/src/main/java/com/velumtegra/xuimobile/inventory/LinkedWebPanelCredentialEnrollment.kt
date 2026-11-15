package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.util.Arrays
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Local credential onboarding only. Never performs Web Panel login, SSH, or a VPS operation. */
internal interface LinkedWebPanelCredentialPort {
    /** Takes ownership of caller's password buffer and wipes it even on rejection/cancellation. */
    suspend fun save(
        serverId: String, installationId: String, httpsHost: String,
        username: String, passwordBytes: ByteArray, confirmed: Boolean,
    ): LinkedPanelCredentialResult
    /** Manual SSH Web Panel: no claim that a 3x-ui installation has been discovered. */
    suspend fun saveStandaloneViaSsh(
        serverAccessId: String, username: String, passwordBytes: ByteArray, confirmed: Boolean,
    ): LinkedPanelCredentialResult = LinkedPanelCredentialResult.Rejected(
        "Ручная запись закрытой панели недоступна."
    )
    /** Exact existing SSH profile; never silently falls back to direct HTTPS. */
    suspend fun saveViaSsh(
        serverId: String, installationId: String, serverAccessId: String,
        username: String, passwordBytes: ByteArray, confirmed: Boolean,
    ): LinkedPanelCredentialResult = LinkedPanelCredentialResult.Rejected(
        "Сохранение закрытой панели через SSH недоступно в этой конфигурации."
    )
}

internal sealed interface LinkedPanelCredentialResult {
    data class Saved(val accessId: String) : LinkedPanelCredentialResult
    data class Rejected(val reason: String) : LinkedPanelCredentialResult
}

/** Pure, fail-closed input policy. Host and panel URL cannot override saved port or path. */
internal object LinkedPanelCredentialPolicy {
    fun preflight(
        serverId: String, installationId: String, host: String,
        username: String, passwordLength: Int, confirmed: Boolean,
        port: Int, savedPath: String,
    ): String? = when {
        !confirmed -> "Подтвердите сохранение реквизитов именно выбранной установки."
        serverId.isBlank() || installationId.isBlank() -> "Установка или сервер не выбраны."
        username.isEmpty() || username != username.trim() || username.length > 128 ||
            username.any { Character.isISOControl(it) } -> "Логин должен содержать 1–128 символов без управляющих знаков и пробелов по краям."
        passwordLength !in 1..4096 -> "Пароль должен содержать 1–4096 байт."
        linkedInstallationHttpsUrl(host, port, savedPath) == null ->
            "Некорректный HTTPS-хост, сохранённый порт или веб-путь установки."
        else -> null
    }
}

/** Local-only SSH panel onboarding: identity must match both saved server and verified installation. */
internal object LinkedPanelSshCredentialPolicy {
    fun preflight(serverId: String, installationId: String, serverAccessId: String,
                  username: String, passwordLength: Int, confirmed: Boolean, port: Int, path: String): String? = when {
        !confirmed -> "Подтвердите сохранение Web Panel доступа."
        serverId.isBlank() || installationId.isBlank() || serverAccessId.isBlank() ->
            "Сервер, установка и точный SSH-профиль обязательны."
        username.isEmpty() || username != username.trim() || username.length > 128 ||
            username.any { Character.isISOControl(it) } -> "Некорректный логин панели."
        passwordLength !in 1..4096 -> "Некорректный пароль панели."
        port !in 1..65535 -> "Некорректный сохранённый порт панели."
        !path.startsWith('/') || path.contains("..") || path.any { Character.isISOControl(it) } ->
            "Некорректный сохранённый путь панели."
        else -> null
    }
}

/** Atomic, verified SecretStore -> Room onboarding via the existing credential transaction. */
internal class RepositoryLinkedWebPanelCredentialPort(
    private val servers: ServerRepository,
    private val installations: XuiInstallationRepository,
    private val panels: WebPanelAccessRepository,
    private val credentials: CredentialTransactionService,
    private val sshAccesses: ServerAccessRepository? = null,
) : LinkedWebPanelCredentialPort {
    override suspend fun save(
        serverId: String, installationId: String, httpsHost: String,
        username: String, passwordBytes: ByteArray, confirmed: Boolean,
    ): LinkedPanelCredentialResult = saveChecked(
        serverId, installationId, username, passwordBytes, confirmed,
        directHost = httpsHost, sshAccessId = null,
    )

    override suspend fun saveViaSsh(
        serverId: String, installationId: String, serverAccessId: String,
        username: String, passwordBytes: ByteArray, confirmed: Boolean,
    ): LinkedPanelCredentialResult = saveChecked(
        serverId, installationId, username, passwordBytes, confirmed,
        directHost = null, sshAccessId = serverAccessId,
    )

    override suspend fun saveStandaloneViaSsh(
        serverAccessId: String, username: String, passwordBytes: ByteArray, confirmed: Boolean,
    ): LinkedPanelCredentialResult = try {
        withContext(Dispatchers.IO) {
            fun reject(message: String) = LinkedPanelCredentialResult.Rejected(message)
            StandalonePrivatePanelPolicy.credentialError(
                serverAccessId, username, passwordBytes.size, confirmed,
            )?.let { return@withContext reject(it) }
            val ssh = when (val read = sshAccesses?.get(ServerAccessId(serverAccessId))) {
                is RepositoryResult.Success -> read.value
                else -> return@withContext reject("Сохранённый SSH-профиль не найден.")
            }
            if (ssh.id.value != serverAccessId) return@withContext reject("SSH-профиль изменился.")
            val server = when (val read = servers.get(ssh.serverId)) {
                is RepositoryResult.Success -> read.value.value
                else -> return@withContext reject("Сервер выбранного SSH-профиля не найден.")
            }
            if (server.id != ssh.serverId) return@withContext reject("SSH-профиль не принадлежит серверу.")
            val route = WebPanelRoute.SshTunnel(ssh.id)
            val existing = when (val read = panels.list()) {
                is RepositoryResult.Success -> read.value
                else -> return@withContext reject("Невозможно проверить существующие Web Panel доступы.")
            }
            if (existing.any { it.value.installationLink == WebPanelInstallationLink.Standalone &&
                    it.value.route == route && it.value.username == username }) {
                return@withContext reject("Такая самостоятельная панель уже сохранена для этого SSH-профиля.")
            }
            val access = WebPanelAccess(
                id = WebPanelAccessId(UUID.randomUUID().toString()),
                installationLink = WebPanelInstallationLink.Standalone,
                username = username,
                passwordSecretId = SecretId(UUID.randomUUID().toString()),
                route = route,
            )
            SecretMaterial.fromBytes(passwordBytes).use { secret ->
                when (credentials.createWebPanelAccess(access, secret)) {
                    is CredentialTransactionResult.Success -> LinkedPanelCredentialResult.Saved(access.id.value)
                    else -> reject("Не удалось сохранить защищённый Web Panel доступ.")
                }
            }
        }
    } catch (cancel: CancellationException) {
        throw cancel
    } catch (_: Exception) {
        LinkedPanelCredentialResult.Rejected("Локальное хранилище недоступно.")
    } finally {
        Arrays.fill(passwordBytes, 0)
    }

    private suspend fun saveChecked(
        serverId: String, installationId: String, username: String,
        passwordBytes: ByteArray, confirmed: Boolean, directHost: String?, sshAccessId: String?,
    ): LinkedPanelCredentialResult = try {
        withContext(Dispatchers.IO) {
            fun reject(message: String) = LinkedPanelCredentialResult.Rejected(message)
            if (!confirmed || serverId.isBlank() || installationId.isBlank() ||
                passwordBytes.size !in 1..4096) {
                return@withContext reject("Выберите установку, подтвердите действие и введите пароль.")
            }
            val server = when (val read = servers.get(ServerId(serverId))) {
                is RepositoryResult.Success -> read.value.value
                else -> return@withContext reject("Сервер отсутствует в локальной базе.")
            }
            if (server.id.value != serverId) return@withContext reject("Сервер изменился. Обновите список.")
            val installation = when (val read = installations.get(XuiInstallationId(installationId))) {
                is RepositoryResult.Success -> read.value.value
                else -> return@withContext reject("Установка 3x-ui отсутствует. Обновите список.")
            }
            if (installation.id.value != installationId || installation.serverId.value != serverId) {
                return@withContext reject("Установка не принадлежит выбранному серверу.")
            }
            val route = if (sshAccessId != null) {
                LinkedPanelSshCredentialPolicy.preflight(serverId, installationId, sshAccessId,
                    username, passwordBytes.size, confirmed,
                    installation.baseline.panelPort, installation.baseline.webBasePath,
                )?.let { return@withContext reject(it) }
                val exact = sshAccesses?.get(ServerAccessId(sshAccessId))
                val ssh = when (exact) {
                    is RepositoryResult.Success -> exact.value
                    else -> return@withContext reject("Выбранный SSH-профиль отсутствует. Сохранение отменено.")
                }
                if (ssh.id.value != sshAccessId || ssh.serverId.value != serverId) {
                    return@withContext reject("SSH-профиль не принадлежит выбранному серверу.")
                }
                WebPanelRoute.SshTunnel(ssh.id)
            } else {
                val host = directHost ?: return@withContext reject("HTTPS-хост обязателен.")
                LinkedPanelCredentialPolicy.preflight(
                    serverId, installationId, host, username, passwordBytes.size,
                    confirmed, installation.baseline.panelPort, installation.baseline.webBasePath,
                )?.let { return@withContext reject(it) }
                WebPanelRoute.Direct(host)
            }
            val existing = when (val read = panels.list()) {
                is RepositoryResult.Success -> read.value
                else -> return@withContext reject("Невозможно проверить существующие Web Panel доступы.")
            }
            val isDuplicate = existing.any { record ->
                val panel = record.value
                (panel.installationLink as? WebPanelInstallationLink.Linked)?.installationId?.value == installationId &&
                    panel.username == username && panel.route == route
            }
            if (isDuplicate) return@withContext reject("Такой доступ уже привязан к установке.")
            val access = WebPanelAccess(
                id = WebPanelAccessId(UUID.randomUUID().toString()),
                installationLink = WebPanelInstallationLink.Linked(installation.id),
                username = username,
                passwordSecretId = SecretId(UUID.randomUUID().toString()),
                route = route,
            )
            SecretMaterial.fromBytes(passwordBytes).use { secret ->
                when (credentials.createWebPanelAccess(access, secret)) {
                    is CredentialTransactionResult.Success -> LinkedPanelCredentialResult.Saved(access.id.value)
                    else -> reject("Не удалось сохранить защищённый Web Panel доступ.")
                }
            }
        }
    } catch (cancel: CancellationException) {
        throw cancel
    } catch (_: Exception) {
        LinkedPanelCredentialResult.Rejected("Локальное хранилище недоступно. Реквизиты не подтверждены.")
    } finally { Arrays.fill(passwordBytes, 0) }
}
