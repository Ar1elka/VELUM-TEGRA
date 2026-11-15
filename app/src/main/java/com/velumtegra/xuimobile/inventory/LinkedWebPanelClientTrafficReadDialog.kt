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
internal fun LinkedWebPanelClientTrafficReadDialog(
    accessId: String,
    port: LinkedWebPanelClientTrafficReadPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var outcome by remember(accessId) { mutableStateOf<LinkedWebPanelClientTrafficReadOutcome?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Трафик клиентов 3x-ui (только чтение)") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                Text("После подтверждения приложение один раз выполнит вход через HTTPS и " +
                    "GET /panel/api/inbounds/list. Для каждого inbound будут показаны только " +
                    "суммарные счётчики upload/download записей clientStats. Это накопленный трафик " +
                    "за учётный период сервера, не скорость и не трафик уникальных людей. " +
                    "UUID, email, ключи и пароли не отображаются и не сохраняются. " +
                    "Настройки сервера не меняются, временная сессия закроется.")
                if (!finished) Row {
                    Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("client_traffic_read_approval"))
                    Text("Разрешаю однократное HTTPS-подключение к выбранной панели и чтение агрегированного трафика клиентов.")
                }
                if (busy) Text("Чтение через HTTPS…")
                when (val result = outcome) {
                    is LinkedWebPanelClientTrafficReadOutcome.Refused ->
                        Text(result.explanation, modifier = Modifier.testTag("client_traffic_read_result"))
                    is LinkedWebPanelClientTrafficReadOutcome.Loaded -> {
                        Text("Получены счётчики по ${result.items.size} inbound.",
                            modifier = Modifier.testTag("client_traffic_read_result"))
                        Text("Отсутствующие clientStats и счётчики отмечены как «нет данных», не как ноль.")
                        result.items.take(50).forEach { item ->
                            val records = item.trackedClients?.toString() ?: "нет данных"
                            Text("Inbound #${item.inboundId} · записей: $records · " +
                                "↑ ${formatTrafficBytes(item.uploadBytes)} · " +
                                "↓ ${formatTrafficBytes(item.downloadBytes)}")
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
                    try {
                        outcome = port.read(accessId, true)
                    } catch (cancel: CancellationException) { throw cancel }
                    catch (_: Exception) {
                        outcome = LinkedWebPanelClientTrafficReadOutcome.Refused("Чтение прервалось. Автоповтора нет.")
                    } finally { busy = false; finished = true; approved = false }
                }
            }, enabled = approved && !busy, modifier = Modifier.testTag("client_traffic_read_confirm")) {
                Text(if (busy) "Загружаем…" else "Прочитать один раз")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("client_traffic_read_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}

/** Number-only output, independent of device locale and user-supplied identifiers. */
private fun formatTrafficBytes(bytes: Long?): String {
    if (bytes == null) return "нет данных"
    if (bytes < 1024L) return "$bytes Б"
    val units = listOf("КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ", "ЭиБ")
    var value = bytes.toDouble()
    var index = -1
    do { value /= 1024.0; index++ } while (value >= 1024.0 && index < units.lastIndex)
    return "%.1f %s".format(java.util.Locale.ROOT, value, units[index])
}
