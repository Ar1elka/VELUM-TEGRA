package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelInstallation
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationClient
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationRequest
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationTransport
import com.velumtegra.xuimobile.core.webpanel.WebPanelServerStatusSnapshot
import com.velumtegra.xuimobile.core.webpanel.WebPanelServerStatusFailure
import com.velumtegra.xuimobile.core.webpanel.WebPanelServerStatusResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelServerStatusSession
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal interface LinkedWebPanelServerStatusReadPort {
    suspend fun read(accessId: String, confirmed: Boolean): LinkedWebPanelServerStatusReadOutcome
}

internal sealed interface LinkedWebPanelServerStatusReadOutcome {
    data class Loaded(val snapshot: WebPanelServerStatusSnapshot) : LinkedWebPanelServerStatusReadOutcome
    data class Refused(val explanation: String) : LinkedWebPanelServerStatusReadOutcome
}

internal object LinkedWebPanelServerStatusReadPolicy {
    fun message(failure: WebPanelServerStatusFailure): String = when (failure) {
        WebPanelServerStatusFailure.SESSION_CLOSED -> "Проверочная сессия уже закрыта."
        WebPanelServerStatusFailure.AUTH_REQUIRED -> "Сервер требует повторный вход или отказал в доступе к API."
        WebPanelServerStatusFailure.RESPONSE_TOO_LARGE -> "Ответ 3x-ui слишком большой для безопасного чтения."
        WebPanelServerStatusFailure.TLS_FAILURE -> "HTTPS/TLS-проверка не прошла. Сертификат не игнорируется."
        WebPanelServerStatusFailure.NETWORK_FAILURE -> "Не удалось прочитать данные через HTTPS."
        WebPanelServerStatusFailure.PROTOCOL_INCOMPATIBLE -> "Ответ 3x-ui не соответствует API статуса сервера."
        WebPanelServerStatusFailure.CANCELLED -> "Чтение отменено."
        WebPanelServerStatusFailure.HTTP_FAILURE -> "3x-ui вернул ошибку при чтении состояния сервера."
    }
}

/** No network access until explicit approval. One login, one GET, no persistence or writes. */
internal class RepositoryLinkedWebPanelServerStatusReadPort(
    private val panels: WebPanelAccessRepository,
    private val resolver: ExactWebPanelTargetResolver,
    private val authenticator: WebPanelAuthenticationClient,
) : LinkedWebPanelServerStatusReadPort {
    private val active = AtomicBoolean(false)

    override suspend fun read(accessId: String, confirmed: Boolean): LinkedWebPanelServerStatusReadOutcome {
        fun refuse(message: String) = LinkedWebPanelServerStatusReadOutcome.Refused(message)
        if (!confirmed || accessId.isBlank()) return refuse("Подтвердите разовое чтение данных выбранной панели по HTTPS.")
        if (!active.compareAndSet(false, true)) return refuse("Дождитесь завершения предыдущего запроса.")
        try {
            return withContext(Dispatchers.IO) {
                val id = WebPanelAccessId(accessId)
                val panel = when (val result = panels.get(id)) {
                    is RepositoryResult.Success -> result.value.value
                    else -> return@withContext refuse("Сохранённый доступ не найден.")
                }
                if (panel.id != id || !LinkedWebPanelLoginPolicy.permitted(panel, confirmed))
                    return@withContext refuse("Нужен сохранённый HTTPS-доступ к конкретной установке.")
                val target = when (val result = resolver.resolve(WebPanelTargetResolutionRequest(id, WebPanelScheme.HTTPS))) {
                    is WebPanelTargetResolutionResult.Resolved -> result.target
                    else -> return@withContext refuse("Не удалось подтвердить адрес и привязку установки.")
                }
                val direct = target.routeTarget as? ResolvedWebPanelRouteTarget.Direct
                if (target.installation !is ResolvedWebPanelInstallation.Linked || direct == null ||
                    direct.origin.scheme != WebPanelScheme.HTTPS)
                    return@withContext refuse("Требуется прямой HTTPS-доступ, без автоматического SSH-туннеля.")
                when (val auth = authenticator.authenticate(WebPanelAuthenticationRequest(
                    target, WebPanelAuthenticationTransport.Direct,
                ))) {
                    is WebPanelAuthenticationResult.Failed -> refuse(LinkedWebPanelLoginPolicy.failureMessage(
                        auth.evidence.failure, auth.evidence.credentialSubmission,
                    ))
                    is WebPanelAuthenticationResult.Authenticated -> auth.session.use { session ->
                        if (session.webPanelAccessId != id || !session.isOpen)
                            return@use refuse("Не удалось подтвердить сессию выбранной панели.")
                        val reader = session as? WebPanelServerStatusSession
                            ?: return@use refuse("Эта сессия не поддерживает безопасное чтение API.")
                        when (val result = reader.readServerStatusOnce()) {
                            is WebPanelServerStatusResult.Success -> LinkedWebPanelServerStatusReadOutcome.Loaded(result.snapshot)
                            is WebPanelServerStatusResult.Failed -> refuse(LinkedWebPanelServerStatusReadPolicy.message(result.reason))
                        }
                    }
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            return refuse("Запрос завершился ошибкой; повторная отправка пароля не выполнялась.")
        } finally {
            active.set(false)
        }
    }
}
