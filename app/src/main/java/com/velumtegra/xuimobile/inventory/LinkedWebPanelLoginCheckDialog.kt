package com.velumtegra.xuimobile.inventory

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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

/** Requires an unambiguous per-attempt approval before any connection or secret read. */
@Composable
internal fun LinkedWebPanelLoginCheckDialog(
    accessId: String,
    port: LinkedWebPanelLoginCheckPort,
    onDismiss: () -> Unit,
) {
    var approved by remember(accessId) { mutableStateOf(false) }
    var busy by remember(accessId) { mutableStateOf(false) }
    var finished by remember(accessId) { mutableStateOf(false) }
    var notice by remember(accessId) { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Проверить вход в 3x-ui") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Однократная проверка авторизации сохранённого доступа. " +
                    "Пароль отправляется выбранной панели по HTTPS после подтверждения. " +
                    "Порт и веб-путь берутся из связанной установки. " +
                    "Конфигурация VPS не изменяется; временная сессия закрывается после проверки.")
                if (!finished) {
                    androidx.compose.foundation.layout.Row {
                        Checkbox(checked = approved, onCheckedChange = { approved = it }, enabled = !busy,
                            modifier = Modifier.testTag("webpanel_login_approval"))
                        Text("Разрешаю сейчас проверить авторизацию на выбранном сервере. " +
                            "Понимаю, что это сетевой запрос с сохранёнными реквизитами.")
                    }
                }
                if (notice.isNotEmpty()) Text(notice, modifier = Modifier.testTag("webpanel_login_result"))
            }
        },
        confirmButton = {
            if (!finished) Button(
                onClick = {
                    if (!approved || busy) return@Button
                    busy = true
                    notice = "Проверяем HTTPS и авторизацию…"
                    scope.launch {
                        try {
                            notice = when (val result = port.check(accessId, true)) {
                                LinkedWebPanelLoginCheckResult.Verified ->
                                    "Вход подтверждён сервером, cookie получен. Проверочная сессия закрыта."
                                is LinkedWebPanelLoginCheckResult.NotVerified -> result.message
                            }
                        } catch (cancel: CancellationException) { throw cancel }
                        catch (_: Exception) {
                            notice = "Проверка прервалась. Результат неизвестен; повтора не было."
                        } finally { busy = false; finished = true; approved = false }
                    }
                },
                enabled = approved && !busy,
                modifier = Modifier.testTag("webpanel_login_confirm"),
            ) { Text(if (busy) "Проверяем…" else "Проверить один раз") }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, enabled = !busy,
                modifier = Modifier.testTag("webpanel_login_close")) {
                Text(if (finished) "Закрыть" else "Отмена")
            }
        },
    )
}
