package com.velumtegra.xuimobile.management

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.*
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

@Composable
fun ManagementInspectionHistoryScreen(viewModel: ManagementInspectionHistoryViewModel, onBack: () -> Unit) {
    val state by viewModel.state.collectAsState()
    val back = { if (state.selected != null) viewModel.clearSelection() else onBack() }
    BackHandler(onBack = back)
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, viewModel) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> viewModel.enterForeground()
                Lifecycle.Event.ON_STOP -> viewModel.leaveForeground()
                else -> Unit
            }
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer); viewModel.leaveForeground() }
    }
    Box(Modifier.fillMaxSize().safeDrawingPadding().testTag("inspection_history_root"),
        contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 1040.dp).fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = back, modifier = Modifier.testTag("inspection_history_back")) { Text("‹ Назад") }
                Text(if (state.selected == null) "История проверок" else "Отчёт проверки",
                    style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            }
            when (val local = state.local) {
                LocalManagementReview.Loading -> {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text("Читаем сохранённые сведения…")
                }
                is LocalManagementReview.Unavailable -> {
                    Text(local.reason, modifier = Modifier.testTag("inspection_history_unavailable"))
                    OutlinedButton(onClick = viewModel::refresh) { Text("Обновить сведения") }
                }
                is LocalManagementReview.Ready -> {
                    Text(local.serverName, style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold, modifier = Modifier.testTag("inspection_history_server"))
                    Text("Служба: " + local.serviceUnit + " · Порт панели: " + local.panelPort,
                        style = MaterialTheme.typography.bodySmall)
                    Text("Локальный журнал проверок. Просмотр и обновление отчёта читают сохранённый результат.",
                        style = MaterialTheme.typography.bodySmall)
                    state.notice?.let { Text(it, color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("inspection_history_notice")) }
                    val selected = state.selected
                    if (selected != null) {
                        Text(inspectionKindLabel(selected.kind), style = MaterialTheme.typography.titleMedium)
                        state.entries.singleOrNull { it.operationId == selected.operationId }?.let {
                            Text("Начата: " + inspectionTime(it.startedAt), style = MaterialTheme.typography.bodySmall)
                        }
                        if (state.reading) LinearProgressIndicator(Modifier.fillMaxWidth())
                        state.result?.let { InspectionReportCard(it, Modifier.testTag("inspection_history_report")) }
                        OutlinedButton(onClick = viewModel::refreshResult, enabled = !state.reading,
                            modifier = Modifier.fillMaxWidth().testTag("inspection_history_refresh_report")) {
                            Text("Обновить результат этой проверки")
                        }
                    } else {
                        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            InspectionHistoryFilter.entries.forEach { filter ->
                                FilterChip(selected = state.filter == filter, onClick = { viewModel.setFilter(filter) },
                                    modifier = Modifier.testTag("inspection_history_filter_" + filter.name),
                                    label = { Text(when (filter) {
                                        InspectionHistoryFilter.ALL -> "Все"
                                        InspectionHistoryFilter.QUICK -> "Состояние"
                                        InspectionHistoryFilter.DEEP -> "Диагностика"
                                    }) })
                            }
                        }
                        OutlinedButton(onClick = viewModel::refresh, modifier = Modifier.fillMaxWidth()
                            .testTag("inspection_history_refresh")) { Text("Обновить историю") }
                        if (state.historyAvailable && state.filtered.isEmpty()) Text(
                            if (state.entries.isEmpty()) "Сохранённых проверок этой установки пока нет."
                            else "Проверок выбранного вида в этой выборке нет.",
                            modifier = Modifier.testTag("inspection_history_empty"))
                        if (state.hasOlder) Text("Показаны 50 последних проверок. Более ранние записи не включены в эту выборку.",
                            modifier = Modifier.testTag("inspection_history_limit"), style = MaterialTheme.typography.bodySmall)
                        state.filtered.forEach { entry ->
                            val linked = entry.accessId in local.accessIds
                            Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceVariant) {
                                Column(Modifier.fillMaxWidth().padding(16.dp).testTag("inspection_history_entry_" + entry.operationId),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text(inspectionKindLabel(entry.kind), fontWeight = FontWeight.Bold)
                                    Text(inspectionTime(entry.startedAt), style = MaterialTheme.typography.bodySmall)
                                    Text(inspectionHistoryStatusLabel(entry.status))
                                    if (!linked) Text("SSH-доступ больше не связан с установкой.",
                                        style = MaterialTheme.typography.bodySmall)
                                    OutlinedButton(onClick = { viewModel.select(entry.operationId) }, enabled = linked,
                                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                                            .testTag("inspection_history_open_" + entry.operationId)) { Text("Посмотреть отчёт") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
