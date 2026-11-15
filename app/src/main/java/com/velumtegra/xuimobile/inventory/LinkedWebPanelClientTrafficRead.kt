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
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientTrafficOverview
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientTrafficFailure
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientTrafficResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientTrafficSession
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal interface LinkedWebPanelClientTrafficReadPort {
    suspend fun read(accessId: String, confirmed: Boolean): LinkedWebPanelClientTrafficReadOutcome
}

internal sealed interface LinkedWebPanelClientTrafficReadOutcome {
    data class Loaded(val items: List<WebPanelClientTrafficOverview>) : LinkedWebPanelClientTrafficReadOutcome
    data class Refused(val explanation: String) : LinkedWebPanelClientTrafficReadOutcome
}

internal object LinkedWebPanelClientTrafficReadPolicy {
    fun message(failure: WebPanelClientTrafficFailure): String = when (failure) {
        WebPanelClientTrafficFailure.SESSION_CLOSED -> "Проверочная сессия уже закрыта."
        WebPanelClientTrafficFailure.AUTH_REQUIRED -> "Сервер требует повторный вход или отказал в доступе к API статистики трафика клиентов."
        WebPanelClientTrafficFailure.RESPONSE_TOO_LARGE -> "Ответ 3x-ui слишком большой для безопасного чтения."
        WebPanelClientTrafficFailure.TLS_FAILURE -> "HTTPS/TLS-проверка не прошла. Сертификат не игнорируется."
        WebPanelClientTrafficFailure.NETWORK_FAILURE -> "Не удалось прочитать данные через HTTPS."
        WebPanelClientTrafficFailure.PROTOCOL_INCOMPATIBLE -> "Ответ 3x-ui не соответствует поддерживаемому API статистики трафика клиентов."
        WebPanelClientTrafficFailure.CANCELLED -> "Чтение отменено."
        WebPanelClientTrafficFailure.HTTP_FAILURE -> "3x-ui вернул ошибку при чтении статистики трафика клиентов."
    }
}

/** No network access until explicit approval. One login, one GET, no persistence or writes. */
internal class RepositoryLinkedWebPanelClientTrafficReadPort(
    private val panels: WebPanelAccessRepository,
    private val resolver: ExactWebPanelTargetResolver,
    private val authenticator: WebPanelAuthenticationClient,
) : LinkedWebPanelClientTrafficReadPort {
    private val active = AtomicBoolean(false)

    override suspend fun read(accessId: String, confirmed: Boolean): LinkedWebPanelClientTrafficReadOutcome {
        fun refuse(message: String) = LinkedWebPanelClientTrafficReadOutcome.Refused(message)
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
                        val reader = session as? WebPanelClientTrafficSession
                            ?: return@use refuse("Эта сессия не поддерживает безопасное чтение API статистики трафика клиентов.")
                        when (val result = reader.readClientTrafficOnce()) {
                            is WebPanelClientTrafficResult.Success -> LinkedWebPanelClientTrafficReadOutcome.Loaded(result.items)
                            is WebPanelClientTrafficResult.Failed -> refuse(LinkedWebPanelClientTrafficReadPolicy.message(result.reason))
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
