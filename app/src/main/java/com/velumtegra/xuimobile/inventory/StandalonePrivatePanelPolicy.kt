package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.WebPanelBasePath
import com.velumtegra.xuimobile.core.domain.WebPanelHost

/** Manual panel is not a discovered installation and never changes VPS configuration. */
internal object StandalonePrivatePanelPolicy {
    fun credentialError(sshId: String, username: String, passwordSize: Int, confirmed: Boolean): String? = when {
        !confirmed -> "Подтверди сохранение на этом телефоне."
        sshId.isBlank() -> "Выбери сохранённый SSH-профиль."
        username.isBlank() || username != username.trim() || username.length > 128 ||
            username.any { Character.isISOControl(it) } -> "Некорректный логин панели."
        passwordSize !in 1..4096 -> "Пароль панели должен содержать 1–4096 байт."
        else -> null
    }

    fun targetError(remoteHost: String, panelPort: String, webPath: String): String? = when {
        remoteHost !in setOf("127.0.0.1", "localhost", "[::1]") ->
            "Адрес панели на VPS должен быть loopback (обычно 127.0.0.1)."
        panelPort.toIntOrNull()?.let { it in 1..65535 } != true -> "Укажи фактический порт панели на VPS (1–65535)."
        runCatching { WebPanelHost(remoteHost) }.isFailure -> "Некорректный адрес панели на VPS."
        runCatching { WebPanelBasePath(webPath) }.isFailure ->
            "Укажи точный веб-путь начиная с /, без ? и #."
        else -> null
    }
}
