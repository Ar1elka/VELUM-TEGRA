package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.StandaloneWebPanelTargetDetails
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardOpenResult
import com.velumtegra.xuimobile.core.ssh.openWebPanelLocalForward
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal data class PrivateWebPanelOpenRequest(
    val accessId: String,
    val scheme: WebPanelScheme,
    val authorityHost: String,
    val remoteHostOverride: String? = null,
    val standaloneTarget: StandaloneWebPanelTargetDetails.SshTunnel? = null,
    /** Set only by the scoped installation list; re-verified here before any SSH connection. */
    val scope: WebPanelInstallationScope? = null,
)

internal sealed interface PrivateWebPanelOpenResult {
    data class Opened(val session: PrivateWebPanelBrowserSession) : PrivateWebPanelOpenResult
    data class Refused(val reason: String) : PrivateWebPanelOpenResult
}

/** Scoped ownership: exact SSH forward -> exact SSH session; no WebView-wide proxy. */
internal class PrivateWebPanelBrowserSession(
    val url: String,
    val isHttpWithinSsh: Boolean,
    val certificateTrustScope: String,
    private val forward: WebPanelLocalForwardHandle,
    private val ssh: SshSessionHandle,
    val savedLoginScript: (suspend (String) -> String?)? = null,
) : AutoCloseable {
    private val closed = AtomicBoolean()
    /** False once the OS/network dropped the SSH connection (e.g. while the app was in the background). */
    val isAlive: Boolean get() = !closed.get() && runCatching { ssh.isOpen && forward.isOpen }.getOrDefault(false)
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { forward.close() }
        runCatching { ssh.close() }
    }
}

internal interface PrivateWebPanelSshPort {
    suspend fun open(request: PrivateWebPanelOpenRequest): PrivateWebPanelOpenResult
}

/** Opens only the resolved SSH route. Panel login stays separate from SSH authentication. */
internal class RepositoryPrivateWebPanelSshPort(
    private val resolver: ExactWebPanelTargetResolver,
    private val accesses: ServerAccessRepository,
    private val sshFactory: SshConnectionFactory,
    private val savedLogin: SavedWebPanelLogin? = null,
) : PrivateWebPanelSshPort {
    override suspend fun open(request: PrivateWebPanelOpenRequest): PrivateWebPanelOpenResult = withContext(Dispatchers.IO) {
        fun refuse(message: String) = PrivateWebPanelOpenResult.Refused(message)
        // An HTTP page is allowed only as a loopback browser authority inside a confirmed SSH tunnel.
        // The browser authority is local-only; TLS still requires valid certificate identity.
        val authority = runCatching { WebPanelHost(request.authorityHost) }.getOrNull()
            ?: return@withContext refuse("Укажи точное имя хоста панели без порта и схемы.")
        if (authority.value != "127.0.0.1") {
            return@withContext refuse("Для прямого SSH-маршрута разрешён только локальный адрес 127.0.0.1.")
        }
        val accessId = runCatching { WebPanelAccessId(request.accessId) }.getOrNull()
            ?: return@withContext refuse("Некорректный сохранённый доступ к панели.")
        if (request.standaloneTarget != null && (request.remoteHostOverride != null ||
            StandalonePrivatePanelPolicy.targetError(
                request.standaloneTarget.remoteHost,
                request.standaloneTarget.port.toString(),
                request.standaloneTarget.webBasePath,
            ) != null)) return@withContext refuse("Некорректный ручной SSH-маршрут панели.")
        val requested = WebPanelTargetResolutionRequest(
            accessId, request.scheme,
            standaloneTarget = request.standaloneTarget,
            linkedSshRemoteHost = request.remoteHostOverride,
        )
        val first = resolver.resolve(requested)
        // A panel listening on all addresses (blank/wildcard) is always reachable on the VPS loopback; the
        // resolver admits only a loopback override for exactly that case, so no other target can be chosen.
        // The same effective request is used later for the saved sign-in, which re-resolves it exactly.
        val loopbackFallback = first is WebPanelTargetResolutionResult.Unresolved &&
            first.reason == com.velumtegra.xuimobile.core.domain.WebPanelTargetUnresolvedReason.SSH_REMOTE_HOST_UNRESOLVED &&
            request.standaloneTarget == null && request.remoteHostOverride == null
        val resolution = if (loopbackFallback) requested.copy(linkedSshRemoteHost = "127.0.0.1") else requested
        val read = if (loopbackFallback) resolver.resolve(resolution) else first
        val resolved = when (read) {
            is WebPanelTargetResolutionResult.Resolved -> read.target
            else -> return@withContext refuse("Не удалось подтвердить связанную панель и SSH-маршрут. Обнови локальную запись установки.")
        }
        if (resolved.webPanelAccessId != accessId)
            return@withContext refuse("Сохранённый доступ к панели изменился.")
        if (!webPanelTargetMatchesScope(request.scope, resolved.installation, resolved.routeTarget))
            return@withContext refuse("Профиль панели больше не относится к выбранной установке и серверу. Обновите список.")
        val route = resolved.routeTarget as? ResolvedWebPanelRouteTarget.SshTunnel
            ?: return@withContext refuse("Выбранная панель не привязана к SSH-туннелю.")
        val access = when (val read = accesses.get(route.serverAccessId)) {
            is RepositoryResult.Success -> read.value
            else -> return@withContext refuse("Сохранённый SSH-профиль недоступен.")
        }
        if (access.id != route.serverAccessId || access.serverId != route.serverId)
            return@withContext refuse("SSH-профиль больше не соответствует выбранному серверу.")
        // User-supplied authority remains syntactically validated above, but the browser MUST
        // reach the app-owned, OS-allocated loopback forward (not the public panel authority).
        // TLS certificates are still checked against 127.0.0.1, not silently trusted.
        var ssh: SshSessionHandle? = null
        var forward: WebPanelLocalForwardHandle? = null
        try {
            when (val connected = sshFactory.connect(access, SessionOwner.WebPanel(accessId))) {
                is SshConnectResult.Failed -> return@withContext refuse(
                    privatePanelSshFailureMessage(connected.failure)
                )
                is SshConnectResult.Connected -> ssh = connected.handle
            }
            val connected = requireNotNull(ssh)
            if (connected.binding.owner != SessionOwner.WebPanel(accessId) ||
                connected.binding.serverAccessId != route.serverAccessId || !connected.isOpen)
                return@withContext refuse("SSH-сессия не соответствует выбранному доступу.")
            when (val opened = connected.openWebPanelLocalForward(resolved)) {
                is WebPanelLocalForwardOpenResult.Opened -> forward = opened.handle
                is WebPanelLocalForwardOpenResult.AlreadyOpen -> forward = opened.handle
                is WebPanelLocalForwardOpenResult.Rejected -> return@withContext refuse(
                    privatePanelForwardFailureMessage(opened.failure)
                )
            }
            val activeForward = requireNotNull(forward)
            if (!activeForward.isOpen || activeForward.sessionBinding != connected.binding ||
                activeForward.target != resolved) return@withContext refuse("Проверка владельца SSH-проброса не пройдена.")
            val browserUrl = directSshLoopbackUrl(request.scheme,
                activeForward.localEndpoint.port, route.webBasePath.value)
                ?: return@withContext refuse("SSH открыт, но локальный адрес панели недопустим.")
            val trustScope = panelCertificateTrustScope(
                accessId.value, route.serverAccessId.value,
                route.remoteEndpoint.host.value, route.remoteEndpoint.port,
                route.webBasePath.value, request.scheme.name)
            val loginScript: (suspend (String) -> String?)? =
                if (savedLogin != null && request.scheme == WebPanelScheme.HTTPS) {
                    { pageUrl ->
                        if (activeForward.isOpen && connected.isOpen && isSavedPanelLoginPage(browserUrl, pageUrl)) {
                            savedLogin.fillScript(resolution, resolved, pageUrl)
                        } else null
                    }
                } else null
            val session = PrivateWebPanelBrowserSession(browserUrl,
                request.scheme == WebPanelScheme.HTTP, trustScope, activeForward, connected, loginScript)
            // Ownership changes hands only after SSH and the validated forward are ready.
            ssh = null
            forward = null
            PrivateWebPanelOpenResult.Opened(session)
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            refuse("Не удалось открыть локальный SSH-туннель панели. VPS не изменён.")
        } finally {
            runCatching { forward?.close() }
            runCatching { ssh?.close() }
        }
    }
}

/** Only categorical, secret-free diagnostics reach the user; never display host keys or credentials. */
internal fun privatePanelSshFailureMessage(failure: SshConnectFailure): String = when (failure) {
    SshConnectFailure.AuthenticationRejected -> "SSH отказал в авторизации. Проверь SSH-логин, пароль или ключ профиля."
    is SshConnectFailure.HostIdentityMismatch -> "SSH-ключ сервера не совпадает с сохранённым. Подключение остановлено."
    is SshConnectFailure.Timeout, is SshConnectFailure.Unreachable ->
        "SSH-сервер не отвечает. Проверь IP, порт SSH и доступность VPS."
    is SshConnectFailure.SecretUnavailable, is SshConnectFailure.SecretCorrupt,
    is SshConnectFailure.SecretStorageFailure -> "SSH-секрет недоступен. Проверь сохранённые учётные данные."
    is SshConnectFailure.NegotiationFailure -> "SSH не согласовал алгоритмы. Проверь совместимость сервера."
    is SshConnectFailure.InvalidConfiguration -> "SSH-профиль заполнен некорректно."
    SshConnectFailure.Cancelled -> "SSH-подключение отменено."
    is SshConnectFailure.Unexpected -> "SSH не удалось подключить. Проверь профиль и повтори попытку."
}

internal fun privatePanelForwardFailureMessage(failure: WebPanelLocalForwardFailure): String = when (failure) {
    WebPanelLocalForwardFailure.LOCAL_FORWARD_OPEN_FAILED,
    WebPanelLocalForwardFailure.INVALID_ALLOCATED_LOCAL_PORT ->
        "SSH подключён, но локальный проброс не открылся. Проверь сеть и повтори попытку."
    WebPanelLocalForwardFailure.UNSUPPORTED_SESSION_CAPABILITY -> "SSH-профиль не поддерживает проброс порта."
    WebPanelLocalForwardFailure.SESSION_NOT_OPEN -> "SSH-соединение закрылось до открытия панели."
    WebPanelLocalForwardFailure.ROUTE_NOT_SSH_TUNNEL,
    WebPanelLocalForwardFailure.SESSION_OWNER_MISMATCH,
    WebPanelLocalForwardFailure.SERVER_ACCESS_MISMATCH,
    WebPanelLocalForwardFailure.DIFFERENT_TARGET_ALREADY_FORWARDED ->
        "SSH-маршрут панели не совпал с выбранным профилем. Проверь сохранённый доступ."
}
