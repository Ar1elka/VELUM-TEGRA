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

@Composable
fun ManagementRestoreCheckScreen(viewModel: ManagementRestoreCheckViewModel, actions: RestoreCheckActionPort, onBack: () -> Unit) =
    ManagementRestoreCheckScreen(viewModel, actions, onBack, onCompare = {})

@Composable
fun ManagementRestoreCheckScreen(viewModel: ManagementRestoreCheckViewModel, actions: RestoreCheckActionPort,
    onBack: () -> Unit, onCompare: (String) -> Unit) {
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
        .testTag("restore_check_root"), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("restore_check_back")) { Text("‹ Назад") }
        Text("Пробное восстановление", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        StepIntro(
            step = "Восстановление · шаг 1 из 4",
            summary = DetailLine("Развернём копию в отдельную папку на сервере и убедимся, что она целая. Работающая панель при этом не затрагивается.",
                "restore_check_scope"),
            details = listOf(
                DetailLine("Проверка показывает, что копию можно прочитать и развернуть. Запуск панели из неё и переход между версиями здесь не проверяются."),
                DetailLine("Пробная папка содержит настройки и ключи и остаётся на сервере. Таких папок не больше 4, сами они не удаляются."),
            ),
        )
        if (state.loading || state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.review?.let { r ->
            TargetLines(r.serverName, r.sshLabel, "restore_check_ssh")
            state.source?.let { source ->
                Text("Копия от " + humanTime(source.verifiedAt) + " · версия " + source.binding.version)
                Button(onClick = viewModel::requestInspect, enabled = !state.loading && !state.busy &&
                    (state.operationId == null || state.observation?.terminal == true),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("restore_check_source")) { Text("Проверить копию") }
            }
        }
        state.observation?.let { o ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(o.text, modifier = Modifier.testTag("restore_check_status"))
                    o.sourceProof?.let { proof ->
                        Text("В копии файлов: " + proof.fileCount + ", размер " + humanBytes(proof.archiveBytes), modifier = Modifier.testTag("restore_check_source_size"))
                    }
                    o.receipt?.let { result ->
                        Text("Развёрнуто и сверено с копией: " + humanBytes(result.restoredBytes) + " · " + humanTime(result.verifiedAt),
                            modifier = Modifier.testTag("restore_check_receipt_size"))
                    }
                    if (o.mayRestore) Button(onClick = viewModel::requestRestore, enabled = !state.loading && !state.busy,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("restore_check_restore")) { Text("Развернуть в пробную папку") }
                    if (o.mayCheck) Button(onClick = viewModel::requestCheck, enabled = !state.loading && !state.busy,
                        modifier = Modifier.fillMaxWidth().testTag("restore_check_verify")) { Text("Проверить результат") }
                    if (o.mayCompare) Button(onClick = { onCompare(o.operationId) }, enabled = !state.loading && !state.busy,
                        modifier = Modifier.fillMaxWidth().testTag("restore_check_compare")) { Text("Дальше: сверить с панелью") }
                    if (o.mayInspect) OutlinedButton(onClick = viewModel::requestInspectCurrent, enabled = !state.loading && !state.busy,
                        modifier = Modifier.fillMaxWidth().testTag("restore_check_source_again")) { Text("Проверить копию ещё раз") }
                    if (o.mayCancel) OutlinedButton(onClick = { viewModel.cancelPending(actions) }, enabled = !state.loading && !state.busy,
                        modifier = Modifier.fillMaxWidth().testTag("restore_check_cancel")) { Text("Отменить запрос") }
                    o.sourceProof?.let { proof ->
                        TechDetails(listOf(DetailLine("SHA-256 копии: " + proof.archiveSha256, "restore_check_source_hash")))
                    }
                }
            }
        }
        state.notice?.let { Text(it, modifier = Modifier.testTag("restore_check_notice")) }
        QuietRefresh(viewModel::refresh, !state.busy, "restore_check_refresh")
    }
    state.dialog?.let { mode ->
        AlertDialog(onDismissRequest = viewModel::dismiss,
            title = { Text(when (mode) { "RESTORE" -> "Развернуть копию в пробную папку?"; "CHECK" -> "Проверить результат?"; else -> "Проверить копию?" }) },
            text = {
                Column(Modifier.heightIn(max = 380.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    state.review?.let { Text(it.serverName + " · " + it.sshLabel) }
                    Text(when (mode) {
                        "RESTORE" -> "Файлы и база из копии будут развёрнуты в отдельную закрытую папку. Работающая панель не меняется. После этого результат нужно проверить."
                        "CHECK" -> "Приложение только прочитает пробную папку и сверит её с копией. На сервере ничего не изменится."
                        else -> "Приложение только прочитает копию и проверит её состав и целостность. Пробная папка пока не создаётся."
                    }, modifier = Modifier.testTag("restore_check_review_scope"))
                    state.dialogProof?.let { Text("SHA-256: " + it.archiveSha256.take(16) + "…", style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("restore_check_review_hash")) }
                }
            }, confirmButton = { Button(onClick = { viewModel.confirm(actions) }, modifier = Modifier.testTag("restore_check_confirm")) {
                Text(if (mode == "RESTORE") "Развернуть" else "Проверить")
            } }, dismissButton = { OutlinedButton(onClick = viewModel::dismiss, modifier = Modifier.testTag("restore_check_dismiss")) { Text("Отмена") } })
    }
}
