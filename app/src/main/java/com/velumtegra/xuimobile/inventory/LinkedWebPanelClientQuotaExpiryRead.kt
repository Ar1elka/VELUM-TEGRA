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
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientQuotaExpiryOverview
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientQuotaExpiryFailure
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientQuotaExpiryResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelClientQuotaExpirySession
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal interface LinkedWebPanelClientQuotaExpiryReadPort {
    suspend fun read(accessId: String, confirmed: Boolean): LinkedWebPanelClientQuotaExpiryReadOutcome
}

internal sealed interface LinkedWebPanelClientQuotaExpiryReadOutcome {
    data class Loaded(val items: List<WebPanelClientQuotaExpiryOverview>) : LinkedWebPanelClientQuotaExpiryReadOutcome
    data class Refused(val explanation: String) : LinkedWebPanelClientQuotaExpiryReadOutcome
}

internal object LinkedWebPanelClientQuotaExpiryReadPolicy {
    fun message(failure: WebPanelClientQuotaExpiryFailure): String = when (failure) {
        WebPanelClientQuotaExpiryFailure.SESSION_CLOSED -> "Проверочная сессия уже закрыта."
        WebPanelClientQuotaExpiryFailure.AUTH_REQUIRED -> "Сервер требует повторный вход или отказал в доступе к API статистики лимитов и сроков клиентов."
        WebPanelClientQuotaExpiryFailure.RESPONSE_TOO_LARGE -> "Ответ 3x-ui слишком большой для безопасного чтения."
        WebPanelClientQuotaExpiryFailure.TLS_FAILURE -> "HTTPS/TLS-проверка не прошла. Сертификат не игнорируется."
        WebPanelClientQuotaExpiryFailure.NETWORK_FAILURE -> "Не удалось прочитать данные через HTTPS."
        WebPanelClientQuotaExpiryFailure.PROTOCOL_INCOMPATIBLE -> "Ответ 3x-ui не соответствует поддерживаемому API статистики лимитов и сроков клиентов."
        WebPanelClientQuotaExpiryFailure.CANCELLED -> "Чтение отменено."
        WebPanelClientQuotaExpiryFailure.HTTP_FAILURE -> "3x-ui вернул ошибку при чтении статистики лимитов и сроков клиентов."
    }
}

/** No network access until explicit approval. One login, one GET, no persistence or writes. */
internal class RepositoryLinkedWebPanelClientQuotaExpiryReadPort(
    private val panels: WebPanelAccessRepository,
    private val resolver: ExactWebPanelTargetResolver,
    private val authenticator: WebPanelAuthenticationClient,
) : LinkedWebPanelClientQuotaExpiryReadPort {
    private val active = AtomicBoolean(false)

    override suspend fun read(accessId: String, confirmed: Boolean): LinkedWebPanelClientQuotaExpiryReadOutcome {
        fun refuse(message: String) = LinkedWebPanelClientQuotaExpiryReadOutcome.Refused(message)
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
                        val reader = session as? WebPanelClientQuotaExpirySession
                            ?: return@use refuse("Эта сессия не поддерживает безопасное чтение API статистики лимитов и сроков клиентов.")
                        when (val result = reader.readClientQuotaExpiryOnce()) {
                            is WebPanelClientQuotaExpiryResult.Success -> LinkedWebPanelClientQuotaExpiryReadOutcome.Loaded(result.items)
                            is WebPanelClientQuotaExpiryResult.Failed -> refuse(LinkedWebPanelClientQuotaExpiryReadPolicy.message(result.reason))
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
