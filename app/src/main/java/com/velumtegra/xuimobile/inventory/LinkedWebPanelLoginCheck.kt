package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelInstallation
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.webpanel.CredentialSubmissionState
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationClient
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationFailure
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationRequest
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationTransport
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Explicit one-shot DIRECT HTTPS login check; never writes server configuration or persists cookies. */
internal interface LinkedWebPanelLoginCheckPort {
    suspend fun check(webPanelAccessId: String, confirmed: Boolean): LinkedWebPanelLoginCheckResult
}

internal sealed interface LinkedWebPanelLoginCheckResult {
    data object Verified : LinkedWebPanelLoginCheckResult
    data class NotVerified(val message: String) : LinkedWebPanelLoginCheckResult
}

/** Only linked installation + saved direct origin may enter this HTTPS-only route. */
internal object LinkedWebPanelLoginPolicy {
    fun permitted(access: WebPanelAccess, confirmed: Boolean): Boolean =
        confirmed && access.installationLink is WebPanelInstallationLink.Linked &&
            access.route is WebPanelRoute.Direct

    fun failureMessage(failure: WebPanelAuthenticationFailure, submission: CredentialSubmissionState): String = when {
        submission == CredentialSubmissionState.OUTCOME_UNKNOWN ||
            failure == WebPanelAuthenticationFailure.LOGIN_OUTCOME_UNKNOWN ->
            "Итог входа неизвестен. Сервер мог принять пароль; автоматического повтора не будет."
        failure == WebPanelAuthenticationFailure.SECOND_FACTOR_REQUIRED ->
            "На панели включена двухфакторная защита. Для входа используйте ручную Web Panel."
        failure == WebPanelAuthenticationFailure.AUTHENTICATION_REJECTED ->
            "Панель отклонила учётные данные. Проверьте логин, пароль и адрес."
        failure == WebPanelAuthenticationFailure.TLS_FAILURE ->
            "HTTPS/TLS-проверка не прошла. Недоверенный сертификат не принимается."
        failure == WebPanelAuthenticationFailure.NETWORK_FAILURE ->
            "Панель недоступна по сохранённому HTTPS-адресу. Проверьте порт и сетевой доступ."
        failure == WebPanelAuthenticationFailure.AUTHENTICATED_SESSION_COOKIE_MISSING ->
            "Вход не подтверждён: сервер не выдал ожидаемый cookie сессии."
        failure == WebPanelAuthenticationFailure.PASSWORD_SECRET_UNAVAILABLE ||
            failure == WebPanelAuthenticationFailure.PASSWORD_SECRET_NOT_FOUND ->
            "Защищённый пароль недоступен. Восстановите сохранённый доступ."
        failure == WebPanelAuthenticationFailure.SECOND_FACTOR_INVALID ->
            "Двухфакторная авторизация не подтверждена."
        else -> "Вход не подтверждён. Проверьте HTTPS-адрес и совместимость версии 3x-ui."
    }
}

/** Reuses the existing exact target resolver and bounded one-attempt 3x-ui auth client. */
internal class RepositoryLinkedWebPanelLoginCheckPort(
    private val panels: WebPanelAccessRepository,
    private val resolver: ExactWebPanelTargetResolver,
    private val authenticator: WebPanelAuthenticationClient,
) : LinkedWebPanelLoginCheckPort {
    private val active = AtomicBoolean(false)

    override suspend fun check(webPanelAccessId: String, confirmed: Boolean): LinkedWebPanelLoginCheckResult {
        fun deny(reason: String) = LinkedWebPanelLoginCheckResult.NotVerified(reason)
        if (!confirmed || webPanelAccessId.isBlank()) {
            return deny("Подтвердите разовую передачу сохранённых реквизитов выбранной панели по HTTPS.")
        }
        if (!active.compareAndSet(false, true)) {
            return deny("Другая проверка входа уже выполняется. Дождитесь её окончания.")
        }
        try {
            return withContext(Dispatchers.IO) {
                val id = WebPanelAccessId(webPanelAccessId)
                val panel = when (val read = panels.get(id)) {
                    is RepositoryResult.Success -> read.value.value
                    else -> return@withContext deny("Не удалось получить выбранный сохранённый доступ.")
                }
                if (panel.id != id || !LinkedWebPanelLoginPolicy.permitted(panel, confirmed)) {
                    return@withContext deny("Проверка разрешена только для сохранённого HTTPS-доступа, привязанного к установке.")
                }
                // Exact resolver re-reads installation and panel revisions, saved port/path and server identity.
                val target = when (val resolved = resolver.resolve(
                    WebPanelTargetResolutionRequest(id, WebPanelScheme.HTTPS),
                )) {
                    is WebPanelTargetResolutionResult.Resolved -> resolved.target
                    else -> return@withContext deny("Не удалось однозначно подтвердить адрес и привязку установки 3x-ui.")
                }
                // Copy the cross-module property before checking its sealed subtype.
                // Kotlin cannot smart-cast a public property declared in another module.
                val directRoute = target.routeTarget as? ResolvedWebPanelRouteTarget.Direct
                if (target.installation !is ResolvedWebPanelInstallation.Linked ||
                    directRoute == null ||
                    directRoute.origin.scheme != WebPanelScheme.HTTPS) {
                    return@withContext deny("Требуется точный прямой HTTPS-адрес связанной установки. SSH-туннель здесь не включается.")
                }
                when (val result = authenticator.authenticate(WebPanelAuthenticationRequest(
                    target = target,
                    transport = WebPanelAuthenticationTransport.Direct,
                ))) {
                    is WebPanelAuthenticationResult.Authenticated -> {
                        // This is a check, not a long-lived login. Cookies never leave the in-memory client.
                        result.session.use { session ->
                            if (session.webPanelAccessId != id || !session.isOpen) {
                                deny("Панель ответила, но подтверждённая сессия не совпала с выбранным доступом.")
                            } else LinkedWebPanelLoginCheckResult.Verified
                        }
                    }
                    is WebPanelAuthenticationResult.Failed -> deny(LinkedWebPanelLoginPolicy.failureMessage(
                        result.evidence.failure, result.evidence.credentialSubmission,
                    ))
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            return deny("Проверка завершилась ошибкой; результат неизвестен. Не повторяйте отправку автоматически.")
        } finally {
            active.set(false)
        }
    }
}
