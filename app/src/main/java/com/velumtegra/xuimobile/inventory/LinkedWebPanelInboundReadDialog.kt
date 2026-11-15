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
internal fun LinkedWebPanelInboundReadDialog(
    accessId: String,
    port: LinkedWebPanelInboundReadPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var outcome by remember(accessId) { mutableStateOf<LinkedWebPanelInboundReadOutcome?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Подключения 3x-ui (только чтение)") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                Text("После вашего подтверждения приложение один раз отправит сохранённые реквизиты " +
                    "через HTTPS и запросит GET /panel/api/inbounds/list. Параметры VPS не изменятся. " +
                    "Временная сессия будет закрыта, результат не сохранится на телефоне.")
                if (!finished) Row {
                    Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("inbounds_read_approval"))
                    Text("Разрешаю разовое подключение к выбранному серверу и чтение списка подключений.")
                }
                if (busy) Text("Чтение через HTTPS…")
                when (val result = outcome) {
                    is LinkedWebPanelInboundReadOutcome.Refused ->
                        Text(result.explanation, modifier = Modifier.testTag("inbounds_read_result"))
                    is LinkedWebPanelInboundReadOutcome.Loaded -> {
                        Text("Подключений: ${result.items.size}", modifier = Modifier.testTag("inbounds_read_result"))
                        result.items.take(50).forEach { item ->
                            Text("${item.remark.ifBlank { "#${item.id}" }} · ${item.protocol} · порт ${item.port} · " +
                                if (item.enabled) "Включено" else "Отключено")
                        }
                        if (result.items.size > 50) Text("Показаны первые 50 записей.")
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
                        outcome = LinkedWebPanelInboundReadOutcome.Refused("Чтение прервалось. Автоповтора нет.")
                    } finally { busy = false; finished = true; approved = false }
                }
            }, enabled = approved && !busy, modifier = Modifier.testTag("inbounds_read_confirm")) {
                Text(if (busy) "Загружаем…" else "Прочитать один раз")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("inbounds_read_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}
