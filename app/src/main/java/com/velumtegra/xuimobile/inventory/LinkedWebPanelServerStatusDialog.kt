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
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
internal fun LinkedWebPanelServerStatusDialog(
    accessId: String,
    port: LinkedWebPanelServerStatusReadPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var outcome by remember(accessId) { mutableStateOf<LinkedWebPanelServerStatusReadOutcome?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Состояние сервера 3x-ui") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                Text("После подтверждения приложение один раз войдёт по HTTPS и выполнит " +
                    "GET /panel/api/server/status. Это только чтение: без перезапуска, " +
                    "изменений конфигурации или фонового опроса. Сеанс закроется после запроса.")
                if (!finished) Row {
                    Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("status_read_approval"))
                    Text("Разрешаю разовое подключение к выбранной панели и чтение состояния VPS.")
                }
                if (busy) Text("Получаем состояние через HTTPS…")
                when (val result = outcome) {
                    is LinkedWebPanelServerStatusReadOutcome.Refused ->
                        Text(result.explanation, modifier = Modifier.testTag("status_read_result"))
                    is LinkedWebPanelServerStatusReadOutcome.Loaded -> {
                        val snapshot = result.snapshot
                        Text("Состояние получено", modifier = Modifier.testTag("status_read_result"))
                        snapshot.cpuPercent?.let { Text("CPU: ${String.format(Locale.ROOT, "%.1f", it)} %") }
                        val memoryUsedBytes = snapshot.memoryUsedBytes
                        val memoryTotalBytes = snapshot.memoryTotalBytes
                        if (memoryUsedBytes != null && memoryTotalBytes != null) {
                            Text("ОЗУ: ${mb(memoryUsedBytes)} / ${mb(memoryTotalBytes)} МиБ")
                        }
                        snapshot.networkUploadedBytes?.let { Text("Сеть передано: ${mb(it)} МиБ (накопительно)") }
                        snapshot.networkDownloadedBytes?.let { Text("Сеть получено: ${mb(it)} МиБ (накопительно)") }
                        snapshot.xrayState?.let { Text("Xray: $it") }
                        Text("Неподдерживаемые показатели не отображаются. Результат не сохраняется.")
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
                        outcome = LinkedWebPanelServerStatusReadOutcome.Refused("Чтение прервалось. Автоповтора нет.")
                    } finally { busy = false; finished = true; approved = false }
                }
            }, enabled = approved && !busy, modifier = Modifier.testTag("status_read_confirm")) {
                Text(if (busy) "Загружаем…" else "Прочитать один раз")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("status_read_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}

private fun mb(bytes: Long): Long = bytes / (1024L * 1024L)
