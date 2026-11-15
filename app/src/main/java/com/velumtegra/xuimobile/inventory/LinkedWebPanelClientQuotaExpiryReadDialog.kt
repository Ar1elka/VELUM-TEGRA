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
internal fun LinkedWebPanelClientQuotaExpiryReadDialog(
    accessId: String,
    port: LinkedWebPanelClientQuotaExpiryReadPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var outcome by remember(accessId) { mutableStateOf<LinkedWebPanelClientQuotaExpiryReadOutcome?>(null) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Лимиты и сроки клиентов 3x-ui") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                Text("После подтверждения приложение выполнит один вход через HTTPS и " +
                    "GET /panel/api/inbounds/list. По каждому inbound будут показаны только " +
                    "количества записей с лимитом/без лимита и категории сроков действия. " +
                    "Положительный срок измеряется в миллисекундах Unix, отрицательный " +
                    "показывается как особый режим. Отсутствующие сведения помечаются «нет данных». " +
                    "UUID, email, пароли и ключи не выводятся и не сохраняются. " +
                    "Никаких изменений на сервере; временная сессия закроется.")
                if (!finished) Row {
                    Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("client_quota_expiry_read_approval"))
                    Text("Разрешаю однократное HTTPS-подключение к выбранной панели и чтение сводки лимитов и сроков.")
                }
                if (busy) Text("Чтение через HTTPS…")
                when (val result = outcome) {
                    is LinkedWebPanelClientQuotaExpiryReadOutcome.Refused ->
                        Text(result.explanation, modifier = Modifier.testTag("client_quota_expiry_read_result"))
                    is LinkedWebPanelClientQuotaExpiryReadOutcome.Loaded -> {
                        Text("Сводка по ${result.items.size} inbound.",
                            modifier = Modifier.testTag("client_quota_expiry_read_result"))
                        Text("Сроки: истёк / в ближайшие 7 дней / позже / бессрочно / особый режим / неизвестно. " +
                            "Категории относятся к записям в inbound, не к уникальным людям.")
                        result.items.take(50).forEach { item ->
                            fun n(value: Int?) = value?.toString() ?: "нет данных"
                            Text("Inbound #${item.inboundId} · клиентов: ${n(item.assignments)}")
                            Text("Лимит: ${n(item.limitedQuota)} · без лимита: ${n(item.unlimitedQuota)} · " +
                                "неизвестно: ${n(item.unknownQuota)}")
                            Text("Истёк: ${n(item.expired)} · ≤7 дней: ${n(item.expiringWithinSevenDays)} · " +
                                "позже: ${n(item.laterExpiry)} · бессрочно: ${n(item.noExpiry)} · " +
                                "особый: ${n(item.specialExpiry)} · неизвестно: ${n(item.unknownExpiry)}")
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
                        outcome = LinkedWebPanelClientQuotaExpiryReadOutcome.Refused("Чтение прервалось. Автоповтора нет.")
                    } finally { busy = false; finished = true; approved = false }
                }
            }, enabled = approved && !busy, modifier = Modifier.testTag("client_quota_expiry_read_confirm")) {
                Text(if (busy) "Загружаем…" else "Прочитать один раз")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("client_quota_expiry_read_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}
