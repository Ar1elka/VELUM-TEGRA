package com.velumtegra.xuimobile.inventory

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import kotlinx.coroutines.delay
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withContext

/** Only this transient screen owns the app-local SSH session and direct loopback forward. */
@Composable
internal fun PrivateSshWebPanelScreen(
    request: PrivateWebPanelOpenRequest,
    port: PrivateWebPanelSshPort,
    onClose: () -> Unit,
) {
    var browser by remember(request) { mutableStateOf<PrivateWebPanelBrowserSession?>(null) }
    var message by remember(request) { mutableStateOf("Устанавливаем SSH-соединение…") }
    var generation by remember(request) { mutableStateOf(0) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    // Android/MIUI may drop the SSH socket while the app is in the background (e.g. a file picker is open).
    // Reconnect once the screen is visible again instead of leaving a dead "Failed to fetch" page.
    LaunchedEffect(browser) {
        val live = browser ?: return@LaunchedEffect
        while (true) {
            delay(3_000L)
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) && !live.isAlive) {
                browser = null
                message = "Настраиваем заново: SSH-соединение прервалось, переподключаемся…"
                generation++
                return@LaunchedEffect
            }
        }
    }
    LaunchedEffect(request, port, generation) {
        var session: PrivateWebPanelBrowserSession? = null
        try {
            // No unbounded NonCancellable SSH handshake: closing the screen must cancel it.
            val opened = withTimeout(45_000L) {
                port.open(request).also { result ->
                    if (result is PrivateWebPanelOpenResult.Opened) session = result.session
                }
            }
            when (opened) {
                is PrivateWebPanelOpenResult.Refused -> message = opened.reason
                is PrivateWebPanelOpenResult.Opened -> {
                    message = "Открываем 3x-ui через локальный SSH-порт…"
                    browser = opened.session
                    message = ""
                }
            }
            awaitCancellation() // Resources belong to this composition, not to background app state.
        } catch (_: TimeoutCancellationException) {
            message = "Время ожидания SSH-подключения истекло (45 секунд). Проверь SSH-профиль, " +
                "доступность сервера и мобильную сеть. Панель не открыта через прямой интернет."
            awaitCancellation()
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            message = "Ошибка запуска SSH-туннеля панели. Проверь сохранённый SSH-профиль " +
                "и повтори попытку. Прямое подключение к VPS запрещено."
            awaitCancellation()
        } finally {
            browser = null
            withContext(NonCancellable + Dispatchers.IO) { session?.close() }
        }
    }
    val current = browser
    Column(Modifier.fillMaxSize().testTag("private_panel_root_frame")) {
        if (current != null) key(current) {
            EmbeddedHttpsWebPanelScreen(
                initialUrl = current.url,
                onClose = onClose,
                allowHttpWithinSsh = current.isHttpWithinSsh,
                onlyLocalSshOrigin = true,
                certificateTrustScope = current.certificateTrustScope,
                savedLoginScript = current.savedLoginScript,
            )
        } else {
            BackHandler(onBack = onClose)
            WebPanelToolbar(viaSsh = true, onClose = onClose)
            Column(
                Modifier.fillMaxSize().padding(20.dp).testTag("private_panel_connecting"),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                if (message.startsWith("Устанавливаем") || message.startsWith("Настраиваем")) {
                    CircularProgressIndicator()
                }
                Text(message)
            }
        }
    }
}
