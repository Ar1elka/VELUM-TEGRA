package com.velumtegra.xuimobile.inventory

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
internal fun LinkedWebPanelInboundDetailsReadDialog(
    accessId: String,
    port: LinkedWebPanelInboundDetailsReadPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var outcome by remember(accessId) { mutableStateOf<LinkedWebPanelInboundDetailsReadOutcome?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Параметры inbound 3x-ui") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                Text("После подтверждения приложение выполнит один HTTPS-вход и запросит " +
                    "GET /panel/api/inbounds/list. Будут показаны только номер inbound, " +
                    "протокол, порт, состояние, тип интерфейса прослушивания и количество " +
                    "клиентских записей. Исходные IP, remarks, UUID, email, пароли, " +
                    "ключи и JSON настроек не выводятся и не сохраняются. " +
                    "Сервер не изменяется; временная сессия закрывается.")
                if (!finished) Row {
                    Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("inbound_details_read_approval"))
                    Text("Разрешаю однократное HTTPS-подключение к выбранной панели и чтение параметров inbound.")
                }
                if (busy) Text("Чтение через HTTPS…")
                when (val result = outcome) {
                    is LinkedWebPanelInboundDetailsReadOutcome.Refused ->
                        Text(result.explanation, modifier = Modifier.testTag("inbound_details_read_result"))
                    is LinkedWebPanelInboundDetailsReadOutcome.Loaded -> {
                        Text("Параметры ${result.items.size} inbound.",
                            modifier = Modifier.testTag("inbound_details_read_result"))
                        result.items.take(50).forEach { item ->
                            val scopeText = when (item.listenScope) {
                                com.velumtegra.xuimobile.core.webpanel.WebPanelInboundListenScope.ALL_INTERFACES -> "все интерфейсы"
                                com.velumtegra.xuimobile.core.webpanel.WebPanelInboundListenScope.LOOPBACK -> "только локальный"
                                com.velumtegra.xuimobile.core.webpanel.WebPanelInboundListenScope.SPECIFIC_INTERFACE -> "определённый интерфейс"
                                com.velumtegra.xuimobile.core.webpanel.WebPanelInboundListenScope.UNKNOWN -> "нет данных"
                            }
                            val clients = item.clientAssignments?.toString() ?: "нет данных"
                            Text("Inbound #${item.inboundId} · ${item.protocol} · порт ${item.port} · " +
                                (if (item.enabled) "включён" else "отключён"))
                            Text("Прослушивание: $scopeText · клиентских записей: $clients")
                        }
                        if (result.items.size > 50) Text("Показаны первые 50 inbound.")
                    }
                    null -> Unit
                }
            }
        },
        confirmButton = {
            if (!finished) Button(onClick = {
                if (!approved || busy) return@Button
                busy = true
                scope.launch {
                    try { outcome = port.read(accessId, true) }
                    catch (cancel: CancellationException) { throw cancel }
                    catch (_: Exception) {
                        outcome = LinkedWebPanelInboundDetailsReadOutcome.Refused("Чтение прервалось. Автоповтора нет.")
                    } finally { busy = false; finished = true; approved = false }
                }
            }, enabled = approved && !busy, modifier = Modifier.testTag("inbound_details_read_confirm")) {
                Text(if (busy) "Загружаем…" else "Прочитать один раз")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("inbound_details_read_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}
