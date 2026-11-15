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
import com.velumtegra.xuimobile.core.model.ServiceLogCategory
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun ManagementServiceLogsScreen(viewModel: ManagementServiceLogsViewModel, actions: ServiceLogActionPort, onBack: () -> Unit) {
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
    Column(Modifier.fillMaxSize().safeDrawingPadding().widthIn(max = 1040.dp)
        .verticalScroll(rememberScrollState()).padding(18.dp).testTag("service_logs_root"),
        verticalArrangement = Arrangement.spacedBy(14.dp)) {
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("service_logs_back")) { Text("‹ Назад") }
        Text("Журнал службы", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text("Последние 100 событий 3x-ui: время, важность и тип. Текст записей, адреса и коды скрыты.",
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        when (val local = state.local) {
            LocalManagementReview.Loading -> { LinearProgressIndicator(Modifier.fillMaxWidth()); Text("Проверяем сохранённые сведения…") }
            is LocalManagementReview.Unavailable -> Text(local.reason, modifier = Modifier.testTag("service_logs_unavailable"),
                color = MaterialTheme.colorScheme.error)
            is LocalManagementReview.Ready -> {
                Text(local.serverName, style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("service_logs_server"))
                state.profile?.let { Text(it.username + "@" + it.host + ":" + it.port,
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                Button(onClick = viewModel::requestRead, enabled = !state.launching && !state.reviewing,
                    modifier = Modifier.fillMaxWidth().testTag("service_logs_request")) {
                    Text(if (state.pointer == null) "Показать журнал" else "Прочитать заново")
                }
            }
        }
        if (state.local is LocalManagementReview.Unavailable) OutlinedButton(onClick = viewModel::refreshLocal, enabled = !state.launching,
            modifier = Modifier.fillMaxWidth().testTag("service_logs_local_refresh")) { Text("Повторить") }
        if (state.launching || state.reading) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.notice?.let { Text(it, modifier = Modifier.testTag("service_logs_notice")) }
        state.result?.let { result ->
            Text(result.text, modifier = Modifier.testTag("service_logs_status"))
            result.snapshot?.let { snapshot ->
                val time = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault())
                Text("Снимок получен: " + time.format(snapshot.observedAt), style = MaterialTheme.typography.bodySmall)
                if (snapshot.hasOlder) Text("Показаны последние 100 записей. Более старые записи есть.", modifier = Modifier.testTag("service_logs_older"))
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(selected = state.filter == ServiceLogFilter.ALL, onClick = { viewModel.setFilter(ServiceLogFilter.ALL) },
                        label = { Text("Все") }, modifier = Modifier.testTag("service_logs_all"))
                    FilterChip(selected = state.filter == ServiceLogFilter.WARNING_AND_ERROR,
                        onClick = { viewModel.setFilter(ServiceLogFilter.WARNING_AND_ERROR) },
                        label = { Text("Предупреждения и ошибки") }, modifier = Modifier.testTag("service_logs_warnings"))
                }
                if (snapshot.entries.isEmpty()) Text("В этом чтении нет доступных записей службы. Это не подтверждает отсутствие ошибок.",
                    modifier = Modifier.testTag("service_logs_empty"))
                else if (state.visibleEntries.isEmpty()) Text("В этом снимке нет записей выбранной важности.", modifier = Modifier.testTag("service_logs_filter_empty"))
                state.visibleEntries.asReversed().forEachIndexed { index, entry ->
                    Card(Modifier.fillMaxWidth().testTag("service_logs_entry_$index")) {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(time.format(entry.recordedAt), style = MaterialTheme.typography.labelMedium)
                            Text(serviceLogPriorityText(entry.priority), color = if (entry.priority?.let { it <= 3 } == true)
                                MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(serviceLogCategoryText(entry.category), fontWeight = FontWeight.Medium)
                        }
                    }
                }
            }
        }
    }
    if (state.reviewing) AlertDialog(onDismissRequest = viewModel::dismissReview,
        title = { Text("Прочитать события службы?") },
        text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            val local = state.local as? LocalManagementReview.Ready
            Text(local?.serverName.orEmpty())
            state.profile?.let { Text(it.username + "@" + it.host + ":" + it.port) }
            Text("Приложение подключится по SSH и прочитает до 100 последних событий. На сервере ничего не изменится.")
        } },
        confirmButton = { Button(onClick = { viewModel.confirmRead(actions) }, modifier = Modifier.testTag("service_logs_confirm")) { Text("Прочитать") } },
        dismissButton = { OutlinedButton(onClick = viewModel::dismissReview, modifier = Modifier.testTag("service_logs_cancel")) { Text("Отмена") } })
}

internal fun serviceLogCategoryText(value: ServiceLogCategory) = when (value) {
    ServiceLogCategory.CONNECTION_REFUSED -> "Соединение отклонено"
    ServiceLogCategory.TIMEOUT -> "Истекло время ожидания"
    ServiceLogCategory.TLS_ERROR -> "Ошибка TLS или срока сертификата"
    ServiceLogCategory.PERMISSION_DENIED -> "Недостаточно прав"
    ServiceLogCategory.ADDRESS_IN_USE -> "Адрес или порт уже занят"
    ServiceLogCategory.OTHER_REDACTED -> "Другая запись · текст скрыт"
}
internal fun serviceLogPriorityText(value: Int?) = when (value) {
    0 -> "Аварийное событие"; 1 -> "Тревога"; 2 -> "Критическая ошибка"; 3 -> "Ошибка"
    4 -> "Предупреждение"; 5 -> "Уведомление"; 6 -> "Информация"; 7 -> "Отладка"
    else -> "Важность не указана"
}
