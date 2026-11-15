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
internal fun LinkedWebPanelClientCountReadDialog(
    accessId: String,
    port: LinkedWebPanelClientCountReadPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var outcome by remember(accessId) { mutableStateOf<LinkedWebPanelClientCountReadOutcome?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Клиенты 3x-ui (сводка, только чтение)") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                Text("После вашего подтверждения приложение один раз отправит сохранённые реквизиты " +
                    "через HTTPS и запросит GET /panel/api/inbounds/list. Будут показаны только количества клиентов на inbound, без UUID, email и ключей. Параметры VPS не изменятся. " +
                    "Временная сессия будет закрыта, результат не сохранится на телефоне.")
                if (!finished) Row {
                    Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("client_counts_read_approval"))
                    Text("Разрешаю разовое подключение к выбранному серверу и чтение агрегированной сводки клиентов.")
                }
                if (busy) Text("Чтение через HTTPS…")
                when (val result = outcome) {
                    is LinkedWebPanelClientCountReadOutcome.Refused ->
                        Text(result.explanation, modifier = Modifier.testTag("client_counts_read_result"))
                    is LinkedWebPanelClientCountReadOutcome.Loaded -> {
                        val allKnown = result.items.all { it.clientCount != null }
                        val total = result.items.sumOf { it.clientCount ?: 0 }
                        Text("Клиентских назначений: " + if (allKnown) "$total" else "неполные данные (известно $total)",
                            modifier = Modifier.testTag("client_counts_read_result"))
                        Text("Это сумма назначений на входящие подключения, не число уникальных людей.")
                        result.items.take(50).forEach { item ->
                            val count = item.clientCount
                            val enabled = item.enabledCount
                            val disabled = item.disabledCount
                            val summary = if (count == null) "нет данных о клиентах" else
                                "$count записей" + if (enabled != null && disabled != null)
                                    " · активны: $enabled · отключены: $disabled" else " · состояние неизвестно"
                            Text("${item.inboundName.ifBlank { "#${item.inboundId}" }} · $summary")
                        }
                        if (result.items.size > 50) Text("Показаны первые 50 подключений.")
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
                    try {
                        outcome = port.read(accessId, true)
                    } catch (cancel: CancellationException) { throw cancel }
                    catch (_: Exception) {
                        outcome = LinkedWebPanelClientCountReadOutcome.Refused("Чтение прервалось. Автоповтора нет.")
                    } finally { busy = false; finished = true; approved = false }
                }
            }, enabled = approved && !busy, modifier = Modifier.testTag("client_counts_read_confirm")) {
                Text(if (busy) "Загружаем…" else "Прочитать один раз")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("client_counts_read_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}
