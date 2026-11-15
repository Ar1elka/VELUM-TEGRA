package com.velumtegra.xuimobile.management

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun ManagementDatabaseBackupScreen(viewModel: ManagementDatabaseBackupViewModel, actions: DatabaseBackupActionPort, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    val state by viewModel.state.collectAsState()
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, viewModel) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) viewModel.enterForeground()
            if (event == Lifecycle.Event.ON_STOP) viewModel.leaveForeground()
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer); viewModel.leaveForeground() }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp)
        .testTag("database_backup_root"), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("database_backup_back")) { Text("‹ Назад") }
        Text("Копия базы 3x-ui", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        StepIntro(
            step = "Шаг 2 из 2 · создание копии",
            summary = DetailLine("Сохраним базу панели (настройки и клиенты) в закрытую папку на этом же сервере. Панель при этом продолжает работать.",
                "database_backup_scope"),
            details = listOf(
                DetailLine("В копию входит только база. Файлы 3x-ui, Xray и сертификаты сохраняет «Резервная копия панели»."),
                DetailLine("Размер базы до 128 МБ. На сервере хранится не больше 4 копий, старые сами не удаляются."),
                DetailLine("Копия содержит логины и ключи, поэтому лежит в папке, доступной только root."),
            ),
        )
        if (state.loading || state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.review?.let { r ->
            TargetLines(r.serverName, r.sshLabel, "database_backup_ssh")
            Text(backupSlotInventoryText(state.slots), style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.testTag("database_backup_slots"))
            if (!state.sourceReady) Text("Сначала вернитесь назад и заново проверьте установку: предыдущая проверка устарела или в ней есть замечания.",
                color = MaterialTheme.colorScheme.error)
            Button(onClick = viewModel::requestCreate, enabled = !state.loading && !state.busy && state.sourceReady &&
                (state.operationId == null || state.observation?.terminal == true),
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("database_backup_create")) { Text("Создать копию базы") }
        }
        state.observation?.let { o ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(o.text, modifier = Modifier.testTag("database_backup_status"))
                    o.receipt?.let { receipt ->
                        Text("Размер копии: " + humanBytes(receipt.sizeBytes) + " · проверена " + humanTime(receipt.verifiedAt),
                            modifier = Modifier.testTag("database_backup_size"))
                        TechDetails(listOf(
                            DetailLine("SHA-256: " + receipt.sha256, "database_backup_hash"),
                            DetailLine("Папка на сервере: " + receipt.binding.remoteDirectory),
                            DetailLine("Запрос: " + state.operationId.orEmpty()),
                        ))
                    }
                    if (o.mayCheck) Button(onClick = viewModel::requestCheck, enabled = !state.busy && !state.loading,
                        modifier = Modifier.fillMaxWidth().testTag("database_backup_check")) { Text("Проверить копию") }
                    if (o.mayCancel) OutlinedButton(onClick = { viewModel.cancelPending(actions) }, enabled = !state.busy && !state.loading,
                        modifier = Modifier.fillMaxWidth().testTag("database_backup_cancel_pending")) { Text("Отменить запрос") }
                }
            }
        }
        state.notice?.let { Text(it, modifier = Modifier.testTag("database_backup_notice")) }
        QuietRefresh(viewModel::refresh, !state.busy, "database_backup_refresh")
    }
    state.dialog?.let { mode ->
        AlertDialog(onDismissRequest = viewModel::dismiss, title = {
            Text(if (mode == "CREATE") "Создать копию базы?" else "Проверить копию?")
        }, text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                state.review?.let { Text(it.serverName + " · " + it.sshLabel) }
                Text(if (mode == "CREATE") "Приложение создаст на сервере одну копию базы и проверит её целостность. Панель не останавливается."
                    else "Приложение только прочитает уже созданную копию и проверит её целостность. Новая копия не создаётся.")
            }
        }, confirmButton = {
            Button(onClick = { viewModel.confirm(actions) }, modifier = Modifier.testTag("database_backup_confirm")) {
                Text(if (mode == "CREATE") "Создать" else "Проверить")
            }
        }, dismissButton = { OutlinedButton(onClick = viewModel::dismiss,
            modifier = Modifier.testTag("database_backup_dismiss")) { Text("Отмена") } })
    }
}
