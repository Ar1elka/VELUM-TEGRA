package com.velumtegra.xuimobile.management

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.time.ZoneId
import java.time.format.DateTimeFormatter

import com.velumtegra.xuimobile.core.model.ExistingInstallationServiceAction

@Composable
fun ManagementRestartScreen(
    viewModel: ManagementRestartViewModel,
    actions: ManagementRestartActionPort,
    onBack: () -> Unit,
    serviceAction: ExistingInstallationServiceAction = ExistingInstallationServiceAction.RESTART,
) {
    BackHandler(onBack = onBack)
    val s by viewModel.state.collectAsState(); val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, viewModel) {
        val observer = LifecycleEventObserver { _, event -> when (event) {
            Lifecycle.Event.ON_START -> viewModel.enterForeground()
            Lifecycle.Event.ON_STOP -> viewModel.leaveForeground()
            else -> Unit
        } }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer); viewModel.leaveForeground() }
    }
    Box(Modifier.fillMaxSize().safeDrawingPadding().testTag("management_restart_root"), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 960.dp).fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(onClick = onBack, modifier = Modifier.testTag("management_restart_back")) { Text("‹ Назад") }
                Text(serviceAction.fullLabel(), Modifier.weight(1f), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
            if (s.loading) Card(Modifier.fillMaxWidth()) { Row(Modifier.padding(20.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                CircularProgressIndicator(); Text("Читаем сохранённые сведения…")
            } }
            s.review?.let { r ->
                Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(r.serverName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, modifier = Modifier.testTag("management_restart_server"))
                        Text(r.sshLabel, modifier = Modifier.testTag("management_restart_ssh"))
                        Button(onClick = { viewModel.requestServiceAction(serviceAction) }, enabled = s.mayRestart,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("management_restart_review")) {
                            Text(serviceAction.fullLabel())
                        }
                    }
                }
            }
            if (s.unfinished.isNotEmpty()) Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Незавершённые запросы этого SSH-профиля", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                s.unfinished.forEach { op -> OutlinedButton(onClick = { viewModel.observeExisting(op.operationId) }, enabled = !s.working && s.pending == null,
                    modifier = Modifier.fillMaxWidth().testTag("management_restart_observe_" + op.operationId)) {
                    Text("Запрос от " + DateTimeFormatter.ofPattern("dd.MM HH:mm").withZone(ZoneId.systemDefault()).format(op.startedAt))
                } }
            } }
            s.observation?.let { r -> Card(Modifier.fillMaxWidth().testTag("management_restart_result"),
                colors = CardDefaults.cardColors(containerColor = if (r.succeeded) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant)) {
                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(if (r.succeeded) "Готово" else "Результат операции", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(r.text, modifier = Modifier.testTag("management_restart_result_text"))
                    r.observedAt?.let { Text("Запись обновлена: " + DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault()).format(it), style = MaterialTheme.typography.bodySmall) }
                    if (r.mayCheckReadOnly) OutlinedButton(onClick = viewModel::requestCheckResult, enabled = !s.working && s.review != null,
                        modifier = Modifier.fillMaxWidth().testTag("management_restart_check_result")) { Text("Проверить результат") }
                    if (r.mayCancelBeforeDispatch) OutlinedButton(onClick = { viewModel.cancelBeforeDispatch(actions) }, enabled = !s.working && s.review != null,
                        modifier = Modifier.fillMaxWidth().testTag("management_restart_cancel_request")) { Text("Отменить ожидающий запрос") }
                }
            } }
            s.notice?.let { Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text(it, Modifier.padding(18.dp).testTag("management_restart_notice"))
            } }
            if (s.working) { LinearProgressIndicator(Modifier.fillMaxWidth()); Text("Выполняем на сервере…") }
            if (s.review == null && !s.loading) OutlinedButton(onClick = viewModel::refreshLocal, enabled = !s.working, modifier = Modifier.fillMaxWidth().testTag("management_restart_refresh_local")) { Text("Повторить") }
        }
    }
    val pending = s.pending; val r = s.review
    val confirmedAction = pending?.serviceAction
    if (pending != null && r != null) AlertDialog(onDismissRequest = viewModel::dismissReview,
        title = { Text(confirmedAction?.let { it.fullLabel() + "?" } ?: "Проверить результат?") },
        text = { Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(r.serverName, fontWeight = FontWeight.Bold); Text(r.sshLabel)
            Text(when (confirmedAction) {
                ExistingInstallationServiceAction.START -> "Приложение проверит установку и запустит службу."
                ExistingInstallationServiceAction.STOP -> "Панель и подключения через 3x-ui перестанут работать до запуска службы."
                ExistingInstallationServiceAction.RESTART -> "Панель и подключения через 3x-ui могут кратковременно прерваться."
                ExistingInstallationServiceAction.XRAY_RESTART -> "Подключения Xray могут прерваться. Приложение проверит процесс Xray после команды."
                ExistingInstallationServiceAction.ENABLE_AUTOSTART -> "3x-ui будет запускаться при загрузке сервера."
                ExistingInstallationServiceAction.DISABLE_AUTOSTART -> "3x-ui не будет запускаться автоматически после загрузки сервера."
                null -> "Приложение проверит состояние службы по SSH."
            })
        } },
        confirmButton = { Button(onClick = { viewModel.confirm(actions) }, modifier = Modifier.testTag("management_restart_confirm")) {
            Text(if (confirmedAction != null) "Подтвердить" else "Проверить")
        } },
        dismissButton = { OutlinedButton(onClick = viewModel::dismissReview, modifier = Modifier.testTag("management_restart_dismiss")) { Text("Отмена") } })
}


private fun ExistingInstallationServiceAction.fullLabel(): String = when (this) {
    ExistingInstallationServiceAction.START -> "Запустить 3x-ui"
    ExistingInstallationServiceAction.STOP -> "Остановить 3x-ui"
    ExistingInstallationServiceAction.RESTART -> "Перезапустить 3x-ui"
    ExistingInstallationServiceAction.XRAY_RESTART -> "Перезапустить Xray"
    ExistingInstallationServiceAction.ENABLE_AUTOSTART -> "Включить автозапуск"
    ExistingInstallationServiceAction.DISABLE_AUTOSTART -> "Выключить автозапуск"
}
