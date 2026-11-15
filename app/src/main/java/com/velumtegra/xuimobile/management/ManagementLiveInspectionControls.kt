package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Runs only after exact offline review AND an additional, visible operator authorization. */
@Composable
internal fun ManagementLiveInspectionControls(
    serverId: String,
    installationId: String,
    accessId: String,
    port: VisibleManagementInspectionsPort,
) {
    var pending by remember(serverId, installationId, accessId) { mutableStateOf<InspectionKind?>(null) }
    var launching by remember(serverId, installationId, accessId) { mutableStateOf(false) }
    var active by remember(serverId, installationId, accessId) { mutableStateOf<Pair<InspectionKind, String>?>(null) }
    var outcome by remember(serverId, installationId, accessId) { mutableStateOf<InspectionStatus?>(null) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(active, port, serverId, installationId, accessId) {
        val run = active ?: return@LaunchedEffect
        // The loop reads only local journal/result projection. It does NOT repeat SSH or login.
        repeat(120) {
            val observed = try {
                port.status(run.first, run.second, serverId, installationId, accessId)
            } catch (cancel: CancellationException) { throw cancel }
            catch (_: Exception) { InspectionStatus("Ошибка чтения состояния. Итог операции неизвестен.", true) }
            outcome = observed
            if (observed.terminal) return@LaunchedEffect
            delay(1_000)
        }
        outcome = InspectionStatus("Пока нет конечного результата. Проверка может ещё идти; повторный запуск не выполнялся.", false)
    }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()
        .testTag("management_live_controls")) {
        Text("Проверить реальный VPS", fontWeight = FontWeight.SemiBold)
        Text("Только по явному разрешению: SSH-доступ $accessId. Команды ограничены чтением; сервер и конфигурация не изменяются.",
            style = MaterialTheme.typography.bodySmall)
        OutlinedButton(
            onClick = { pending = InspectionKind.QUICK_INSPECT },
            enabled = !launching && active == null,
            modifier = Modifier.fillMaxWidth().testTag("management_live_quick_authorize"),
        ) { Text("Быстрая проверка 3x-ui") }
        OutlinedButton(
            onClick = { pending = InspectionKind.DEEP_DIAGNOSTIC },
            enabled = !launching && active == null,
            modifier = Modifier.fillMaxWidth().testTag("management_live_deep_authorize"),
        ) { Text("Глубокая диагностика 3x-ui") }
        if (launching) Text("Передаём запрос на выполнение…", modifier = Modifier.testTag("management_live_launching"))
        outcome?.let { state ->
            Text(state.text, modifier = Modifier.testTag("management_live_result"))
            if (active != null && !state.terminal) {
                OutlinedButton(onClick = {
                    val current = active ?: return@OutlinedButton
                    scope.launch {
                        outcome = try {
                            port.status(current.first, current.second, serverId, installationId, accessId)
                        } catch (cancel: CancellationException) { throw cancel }
                        catch (_: Exception) { InspectionStatus("Нет достоверного результата. Не запускайте операцию повторно вслепую.", false) }
                    }
                }, modifier = Modifier.testTag("management_live_refresh_status")) {
                    Text("Обновить состояние операции")
                }
            }
        }
        // Clearing the display after a finished operation is NOT a retry/remote action.
        if (outcome?.terminal == true && active != null) {
            OutlinedButton(onClick = { active = null; outcome = null },
                modifier = Modifier.testTag("management_live_clear_result")) {
                Text("Закрыть результат")
            }
        }
    }

    val candidate = pending
    if (candidate != null) {
        AlertDialog(
            onDismissRequest = { if (!launching) pending = null },
            title = { Text(if (candidate == InspectionKind.QUICK_INSPECT) "Запустить быструю проверку?" else "Запустить глубокую диагностику?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Сервер: $serverId")
                    Text("Установка: $installationId")
                    Text("SSH-доступ: $accessId")
                    Text("Разрешить однократное SSH-подключение и строго ограниченные команды только чтения? Результат придёт из реального VPS; автоматических повторов не будет.")
                }
            },
            confirmButton = {
                Button(enabled = !launching, onClick = {
                    if (launching) return@Button
                    launching = true
                    pending = null
                    outcome = null
                    scope.launch {
                        val start = try {
                            port.start(candidate, serverId, installationId, accessId)
                        } catch (cancel: CancellationException) { throw cancel }
                        catch (_: Exception) { InspectionStart.Blocked("Запуск не подтверждён; состояние VPS не изменялось этой кнопкой намеренно.") }
                        launching = false
                        when (start) {
                            is InspectionStart.Accepted -> {
                                active = candidate to start.operationId
                                outcome = InspectionStatus("Запрос принят Android. Ожидаем подтверждения выполнения…", false)
                            }
                            is InspectionStart.Blocked -> outcome = InspectionStatus(start.message, true)
                        }
                    }
                }, modifier = Modifier.testTag("management_live_confirm")) { Text("Разрешить и запустить") }
            },
            dismissButton = {
                OutlinedButton(enabled = !launching, onClick = { pending = null },
                    modifier = Modifier.testTag("management_live_cancel")) { Text("Отмена") }
            },
        )
    }
}
