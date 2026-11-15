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
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryPlanReview
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryReadinessPolicy

@Composable
fun ManagementInstallationBackupScreen(viewModel: ManagementInstallationBackupViewModel, actions: InstallationBackupActionPort, onBack: () -> Unit) {
    ManagementInstallationBackupScreen(viewModel, actions, onBack, onRestoreCheck = {})
}

@Composable
fun ManagementInstallationBackupScreen(viewModel: ManagementInstallationBackupViewModel, actions: InstallationBackupActionPort, onBack: () -> Unit, onRestoreCheck: (String) -> Unit) {
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
        .testTag("installation_backup_root"), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("installation_backup_back")) { Text("‹ Назад") }
        Text("Резервная копия панели", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        StepIntro(
            step = "Шаг 2 из 2 · создание копии",
            summary = DetailLine("Сохраним базу, файлы 3x-ui и Xray, настройки службы и сертификаты в закрытую папку на этом же сервере. Панель продолжает работать."),
            details = listOf(
                DetailLine("В копию входят только файлы самой панели. Система, nginx и другие службы сервера в неё не попадают.",
                    "installation_backup_scope"),
                DetailLine("Пределы: до 96 файлов и 512 МБ, база до 128 МБ. На сервере хранится не больше 4 копий, старые сами не удаляются."),
                DetailLine("После создания копию нужно отдельно проверить. На сервере должен быть Python 3.8 или новее."),
            ),
        )
        if (state.loading || state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.review?.let { r ->
            TargetLines(r.serverName, r.sshLabel, "installation_backup_ssh")
            Text(backupSlotInventoryText(state.slots), style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.testTag("installation_backup_slots"))
            state.source?.let { report ->
                Card(Modifier.fillMaxWidth().testTag("installation_backup_source_details")) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Что войдёт в копию · версия " + report.currentVersion.orEmpty(), style = MaterialTheme.typography.titleMedium)
                        val at = viewModel.sourceReviewTime()
                        val assessment = UpdateRecoveryReadinessPolicy.review(report, at)
                        if (assessment is UpdateRecoveryPlanReview.Blocked) assessment.reasons.forEach {
                            Text(recoveryBlockerText(it), modifier = Modifier.testTag("installation_backup_blocker_" + it.name))
                        }
                        RecoveryFileInventorySection(report, at)
                        report.recoveryFiles?.let { files ->
                            if (files.sourceSetDigest == null)
                                Text("Источник архива не связан с полным набором файлов. Выполните новую проверку установки.",
                                    modifier = Modifier.testTag("installation_backup_fingerprint_missing"))
                        }
                    }
                }
            }
            if (!state.sourceReady) Text("Сначала вернитесь назад и заново проверьте установку: предыдущая проверка устарела или в ней есть замечания.",
                color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("installation_backup_source_blocked"))
            Button(onClick = viewModel::requestCreate, enabled = !state.loading && !state.busy && state.sourceReady &&
                (state.operationId == null || state.observation?.terminal == true),
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("installation_backup_create")) { Text("Создать резервную копию") }
        }
        state.observation?.let { o ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(o.text, modifier = Modifier.testTag("installation_backup_status"))
                    o.receipt?.let { receipt ->
                        Text("Копия: " + humanBytes(receipt.sizeBytes) + ", файлов: " + receipt.fileCount + " · проверена " + humanTime(receipt.verifiedAt),
                            modifier = Modifier.testTag("installation_backup_size"))
                        TechDetails(listOf(
                            DetailLine("SHA-256 архива: " + receipt.sha256, "installation_backup_hash"),
                            DetailLine("SHA-256 базы: " + receipt.databaseSha256, "installation_backup_database_hash"),
                            DetailLine("Запрос: " + state.operationId.orEmpty()),
                        ))
                    }
                    if (o.mayCheck) Button(onClick = viewModel::requestCheck, enabled = !state.busy && !state.loading,
                        modifier = Modifier.fillMaxWidth().testTag("installation_backup_check")) { Text("Проверить копию") }
                    if (o.mayReviewRestore) OutlinedButton(onClick = { state.operationId?.let(onRestoreCheck) }, enabled = !state.busy && !state.loading,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("installation_backup_restore_check")) { Text("Восстановить из этой копии") }
                    if (o.mayCancel) OutlinedButton(onClick = { viewModel.cancelPending(actions) }, enabled = !state.busy && !state.loading,
                        modifier = Modifier.fillMaxWidth().testTag("installation_backup_cancel_pending")) { Text("Отменить запрос") }
                }
            }
        }
        state.notice?.let { Text(it, modifier = Modifier.testTag("installation_backup_notice")) }
        QuietRefresh(viewModel::refresh, !state.busy, "installation_backup_refresh")
    }
    state.dialog?.let { mode ->
        AlertDialog(onDismissRequest = viewModel::dismiss, title = { Text(if (mode == "CREATE") "Создать резервную копию?" else "Проверить копию?") },
            text = {
                Column(Modifier.heightIn(max = 380.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    state.review?.let { Text(it.serverName + " · " + it.sshLabel) }
                    Text(if (mode == "CREATE") "Приложение создаст на сервере один архив с базой, файлами панели и ключами. Панель продолжает работать. После создания копию нужно проверить."
                        else "Приложение только прочитает архив и проверит его состав и целостность. Новая копия не создаётся, ничего не восстанавливается.")
                }
            }, confirmButton = {
                Button(onClick = { viewModel.confirm(actions) }, modifier = Modifier.testTag("installation_backup_confirm")) {
                    Text(if (mode == "CREATE") "Создать" else "Проверить")
                }
            }, dismissButton = { OutlinedButton(onClick = viewModel::dismiss, modifier = Modifier.testTag("installation_backup_dismiss")) { Text("Отмена") } })
    }
}
