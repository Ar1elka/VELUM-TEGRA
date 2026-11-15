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
import com.velumtegra.xuimobile.core.domain.UpdatePreparationCheck
import com.velumtegra.xuimobile.core.domain.UpdatePreparationPolicy
import com.velumtegra.xuimobile.core.model.*
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun ManagementUpdatePreparationScreen(viewModel: ManagementUpdatePreparationViewModel,
    actions: UpdatePreflightActionPort, onBack: () -> Unit, onDatabaseBackup: ((UpdatePreflightPointer) -> Unit)? = null,
    onInstallationBackup: ((UpdatePreflightPointer) -> Unit)? = null, backupMode: Boolean = false,
    archives: ManagementBackupArchiveHistoryViewModel? = null, onArchive: ((String) -> Unit)? = null,
    pendingRestores: ManagementPendingWorkingRestoreViewModel? = null, onPendingRestore: ((String, String) -> Unit)? = null) {
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
    Box(Modifier.fillMaxSize().safeDrawingPadding(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 1040.dp).fillMaxWidth().verticalScroll(rememberScrollState())
            .padding(18.dp).testTag("update_preparation_root"), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            OutlinedButton(onClick = onBack, modifier = Modifier.testTag("update_preparation_back")) { Text("‹ Назад") }
            Text(if (backupMode) "Резервное копирование" else "Подготовка обновления", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text(if (backupMode) "Шаг 1: проверка установки. На этом шаге копия ещё не создаётся и на сервере ничего не меняется."
                else "Шаг 1: проверка установки. Новая версия на этом шаге не ставится, на сервере ничего не меняется.",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("update_preparation_boundary"))
            if (backupMode && pendingRestores != null && onPendingRestore != null) PendingWorkingRestoreSection(
                viewModel = pendingRestores,
                onOpen = onPendingRestore,
                selectionEnabled = !state.launching && !state.reading && !state.reviewing &&
                    !state.recoveryReading && state.recoveryPlan == null,
            )
            if (backupMode && archives != null && onArchive != null) BackupArchiveHistorySection(
                viewModel = archives,
                onSelect = onArchive,
                selectionEnabled = !state.launching && !state.reading && !state.reviewing &&
                    !state.recoveryReading && state.recoveryPlan == null,
            )
            when (val local = state.local) {
                LocalManagementReview.Loading -> { LinearProgressIndicator(Modifier.fillMaxWidth()); Text("Проверяем сохранённые сведения…") }
                is LocalManagementReview.Unavailable -> Text(local.reason, color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.testTag("update_preparation_unavailable"))
                is LocalManagementReview.Ready -> {
                    Text(local.serverName, style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("update_preparation_server"))
                    state.profile?.let { Text(it.username + "@" + it.host + ":" + it.port,
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    Button(onClick = viewModel::requestRead, enabled = !state.launching && !state.reviewing && !state.packageBusy && state.packageReview == null && !state.recoveryReading && state.recoveryPlan == null,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("update_preparation_request")) {
                        Text(if (state.pointer == null) "Проверить установку" else "Новая проверка установки")
                    }
                }
            }
            if (state.local is LocalManagementReview.Unavailable) OutlinedButton(onClick = viewModel::refreshLocal, enabled = !state.launching && !state.packageBusy && !state.recoveryReading,
                modifier = Modifier.fillMaxWidth().testTag("update_preparation_local_refresh")) { Text("Повторить") }
            if (state.launching || state.reading) LinearProgressIndicator(Modifier.fillMaxWidth())
            state.notice?.let { Text(it, modifier = Modifier.testTag("update_preparation_notice")) }
            state.result?.let { result ->
                Text(if (backupMode) result.text.replace("Обновление не запускалось.", "Резервная копия ещё не создавалась.") else result.text,
                    modifier = Modifier.testTag("update_preparation_status"))
                result.snapshot?.let {
                    UpdatePreparationReport(it, backupMode)
                    if (!backupMode && viewModel.supportsPackagePreparation) UpdatePackagePreparationSection(viewModel, state, it)
                    UpdateRecoveryReadinessSection(viewModel, state, it, onDatabaseBackup, onInstallationBackup)
                }
            }
        }
    }
    if (state.reviewing) AlertDialog(onDismissRequest = viewModel::dismissReview,
        title = { Text(if (backupMode) "Проверить установку перед копированием?" else "Проверить установку перед обновлением?") },
        text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            val local = state.local as? LocalManagementReview.Ready
            Text(local?.serverName.orEmpty())
            state.profile?.let { Text(it.username + "@" + it.host + ":" + it.port) }
            Text("Приложение подключится по SSH и прочитает версию, настройки, состояние службы и сведения о файлах 3x-ui. Содержимое ключей не читается, на сервере ничего не меняется.")
        } },
        confirmButton = { Button(onClick = { viewModel.confirmRead(actions) }, modifier = Modifier.testTag("update_preparation_confirm")) { Text("Разрешить проверку") } },
        dismissButton = { OutlinedButton(onClick = viewModel::dismissReview, modifier = Modifier.testTag("update_preparation_cancel")) { Text("Отмена") } })
}

@Composable
private fun UpdatePreparationReport(snapshot: UpdatePreflightSnapshot, backupMode: Boolean) {
    val blocking = UpdatePreparationPolicy.blockingChecks(snapshot)
    val time = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault())
    Text(if (blocking.isEmpty()) "Установка в порядке" else "Есть замечания",
        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
        color = if (blocking.isEmpty()) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error,
        modifier = Modifier.testTag("update_preparation_verdict"))
    Text("Проверено " + humanTime(snapshot.observedAt), style = MaterialTheme.typography.bodySmall)
    PreparationFact(UpdatePreparationCheck.CURRENT_VERSION, "Текущая версия", snapshot.currentVersion ?: "Версия не подтверждена", blocking)
    PreparationFact(UpdatePreparationCheck.DIRECT_ROOT, "Права подключения", when (snapshot.root) {
        UpdateRootStatus.DIRECT_ROOT -> "Прямое подключение с правами root"
        UpdateRootStatus.NOT_ROOT -> "Подключение без прав root"
        UpdateRootStatus.UNOBSERVED -> "Права не проверены"
    }, blocking)
    PreparationFact(UpdatePreparationCheck.STANDARD_LAYOUT, "Структура установки",
        when {
            snapshot.layout == UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD -> "Стандартная структура 3x-ui / systemd"
            backupMode -> "Структура установки требует дополнительной проверки"
            else -> "Структура требует отдельного пути обновления"
        }, blocking)
    PreparationFact(UpdatePreparationCheck.SERVICE_EXECUTABLE, "Запускаемый файл службы", when (snapshot.serviceDefinition) {
        DeepDiagnosticServiceDefinitionStatus.CONSISTENT -> "Совпадает с выбранной установкой"
        DeepDiagnosticServiceDefinitionStatus.EXEC_START_MISMATCH -> "Служба запускает другой файл"
        DeepDiagnosticServiceDefinitionStatus.UNIT_MISSING -> "Служба не найдена"
        DeepDiagnosticServiceDefinitionStatus.UNREADABLE -> "Путь запуска не подтверждён"
    }, blocking)
    PreparationFact(UpdatePreparationCheck.ACTIVE_SERVICE, "Состояние службы", when (snapshot.serviceState) {
        ManagementServiceState.ACTIVE -> "Работает"
        ManagementServiceState.INACTIVE -> "Остановлена"
        ManagementServiceState.FAILED -> "Ошибка службы"
        ManagementServiceState.ACTIVATING -> "Запускается"
        ManagementServiceState.DEACTIVATING -> "Останавливается"
        ManagementServiceState.RELOADING -> "Перечитывает настройки"
        ManagementServiceState.UNKNOWN -> "Состояние не подтверждено"
    }, blocking)
    PreparationFact(UpdatePreparationCheck.SAVED_SETTINGS, "Сохранённые настройки", when (snapshot.baselineStatus) {
        ManagementBaselineStatus.Matched -> "Совпадают с прочитанными настройками"
        is ManagementBaselineStatus.Drift -> "Обнаружены изменения настроек"
        is ManagementBaselineStatus.Insufficient -> "Для сравнения недостаточно данных"
    }, blocking)
    if (!backupMode) Card(Modifier.fillMaxWidth().testTag("update_preparation_next_steps")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Перед установкой новой версии", fontWeight = FontWeight.Bold)
            Text("Потребуются проверенный пакет обновления и резервная копия. Этот отчёт подтверждает только выполненные проверки текущей установки.")
            Text("Обновление не запускалось.", fontWeight = FontWeight.Medium)
        }
    }
}

@Composable
private fun PreparationFact(check: UpdatePreparationCheck, title: String, value: String, blocking: Set<UpdatePreparationCheck>) {
    // One compact line per check instead of six stacked cards.
    Column(Modifier.fillMaxWidth().testTag("update_preparation_check_" + check.name), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(title, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text((if (check in blocking) "✕ " else "✓ ") + value, fontWeight = FontWeight.Medium,
            color = if (check in blocking) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
    }
}
