package com.velumtegra.xuimobile.inventory

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.WebPanelBasePath
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Compose a direct HTTPS URL ONLY from explicitly provided hostname and an exact local
 * installation baseline. Scheme, DNS name and TLS availability are never inferred from SSH.
 * No credentials, query parameters, fragments, path overrides or server commands.
 */
internal fun linkedInstallationHttpsUrl(hostInput: String, port: Int, webBasePath: String): String? {
    if (port !in 1..65535) return null
    val host = runCatching { WebPanelHost(hostInput).value }.getOrNull() ?: return null
    val path = runCatching { WebPanelBasePath(webBasePath).value }.getOrNull() ?: return null
    return exactHttpsPanelUrl("https://$host:$port$path")
}

private sealed interface LinkedInstallationLoad {
    data object Loading : LinkedInstallationLoad
    data class Ready(val port: Int, val path: String, val listenAddress: String?) : LinkedInstallationLoad
    data object Unavailable : LinkedInstallationLoad
}

/** Local-only lookup; opening a URL is an explicit separate action from this dialog. */
@Composable
internal fun LinkedInstallationHttpsLaunchDialog(
    serverId: String,
    installationId: String,
    installationRepository: XuiInstallationRepository,
    onDismiss: () -> Unit,
    onOpenInApp: (String) -> Unit,
) {
    var load by remember(serverId, installationId, installationRepository) {
        mutableStateOf<LinkedInstallationLoad>(LinkedInstallationLoad.Loading)
    }
    var host by remember(serverId, installationId) { mutableStateOf("") }
    var httpsConfirmed by remember(serverId, installationId) { mutableStateOf(false) }

    LaunchedEffect(serverId, installationId, installationRepository) {
        load = LinkedInstallationLoad.Loading
        load = withContext(Dispatchers.IO) {
            try {
                when (val result = installationRepository.get(XuiInstallationId(installationId))) {
                    is RepositoryResult.Success -> {
                        val installation = result.value.value
                        if (installation.id.value != installationId || installation.serverId.value != serverId) {
                            LinkedInstallationLoad.Unavailable
                        } else {
                            LinkedInstallationLoad.Ready(
                                port = installation.baseline.panelPort,
                                path = installation.baseline.webBasePath,
                                listenAddress = installation.baseline.listenAddress,
                            )
                        }
                    }
                    else -> LinkedInstallationLoad.Unavailable
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                LinkedInstallationLoad.Unavailable
            }
        }
    }

    val known = load as? LinkedInstallationLoad.Ready
    val address = known?.let { linkedInstallationHttpsUrl(host, it.port, it.path) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Web Panel выбранной установки") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                when (val current = load) {
                    LinkedInstallationLoad.Loading -> Text("Читаем локальную запись установки…")
                    LinkedInstallationLoad.Unavailable -> Text(
                        "Не удалось подтвердить сохранённую установку на выбранном сервере. " +
                            "Открытие по её параметрам заблокировано.",
                        modifier = Modifier.testTag("xui_linked_panel_unavailable"),
                    )
                    is LinkedInstallationLoad.Ready -> {
                        Text("Порт из сохранённой установки: ${current.port}")
                        Text("Веб-путь из сохранённой установки: ${current.path}")
                        OutlinedTextField(
                            value = host,
                            onValueChange = { host = it; httpsConfirmed = false },
                            label = { Text("Точный HTTPS-хост (без схемы и порта)") },
                            placeholder = { Text("panel.example.com или 203.0.113.10") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().testTag("xui_linked_panel_host"),
                        )
                        if (address != null) {
                            Text(address, style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.testTag("xui_linked_panel_preview"))
                        } else {
                            Text("Введите корректный DNS-хост или IP без пути, порта и логина.",
                                style = MaterialTheme.typography.bodySmall)
                        }
                        androidx.compose.foundation.layout.Row {
                            Checkbox(
                                checked = httpsConfirmed,
                                onCheckedChange = { httpsConfirmed = it },
                                modifier = Modifier.testTag("xui_linked_panel_https_confirm"),
                            )
                            Text("Я подтверждаю, что этот адрес и порт действительно используют HTTPS. " +
                                "Проверка сертификата остаётся обязательной.",
                                style = MaterialTheme.typography.bodySmall)
                        }
                        if (current.listenAddress == "127.0.0.1" || current.listenAddress == "::1") {
                            Text("Установка слушает loopback. Прямое соединение может быть недоступно; " +
                                "здесь нет SSH-туннеля.", style = MaterialTheme.typography.bodySmall)
                        }
                        Text(
                            "Порт и путь взяты из локально сохранённой проверки, а не из нового опроса VPS. " +
                                "Если используется reverse proxy или HTTP, откройте точный адрес вручную " +
                                "на вкладке «Веб-панели». Пароль вводится только на сайте панели.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val current = load as? LinkedInstallationLoad.Ready ?: return@Button
                    val url = linkedInstallationHttpsUrl(host, current.port, current.path)
                    if (httpsConfirmed && url != null) { onOpenInApp(url); onDismiss() }
                },
                enabled = httpsConfirmed && address != null,
                modifier = Modifier.testTag("xui_linked_panel_open"),
            ) { Text("Открыть HTTPS-панель") }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, modifier = Modifier.testTag("xui_linked_panel_cancel")) {
                Text("Отмена")
            }
        },
    )
}
