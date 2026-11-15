package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class PendingWorkingRestoreState(val loading: Boolean = true, val available: Boolean = false,
    val entries: List<WorkingDatabaseRestoreRegistered> = emptyList())

/** Local journal reads only. It can list exactly proven records but has no launch, SSH or write method. */
class ManagementPendingWorkingRestoreViewModel(private val server: String, private val installation: String,
    private val access: String, private val statuses: WorkingDatabaseRestoreStatusPort) : ViewModel() {
    private val mutable = MutableStateFlow(PendingWorkingRestoreState())
    val state: StateFlow<PendingWorkingRestoreState> = mutable
    private var generation = 0L
    private var job: Job? = null
    fun enterForeground() = refresh()
    fun leaveForeground() { generation++; job?.cancel(); mutable.value = PendingWorkingRestoreState() }
    fun refresh() {
        job?.cancel(); val g = ++generation
        mutable.value = PendingWorkingRestoreState()
        job = viewModelScope.launch {
            val read = try { statuses.registered(server, installation, access) } catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { null }
            if (g == generation) mutable.value = if (read == null) PendingWorkingRestoreState(loading = false)
                else PendingWorkingRestoreState(loading = false, available = true, entries = read)
        }
    }
}

internal class ManagementPendingWorkingRestoreViewModelFactory(private val server: String, private val installation: String,
    private val access: String, private val statuses: WorkingDatabaseRestoreStatusPort) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        require(modelClass == ManagementPendingWorkingRestoreViewModel::class.java)
        return ManagementPendingWorkingRestoreViewModel(server, installation, access, statuses) as T
    }
}

/** Explicit selection only opens the existing restore screen on exactly this record; nothing runs from here. */
@Composable
fun PendingWorkingRestoreSection(viewModel: ManagementPendingWorkingRestoreViewModel, onOpen: (operationId: String, sourceOperationId: String) -> Unit,
    selectionEnabled: Boolean = true) {
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
    if (!state.loading && state.available && state.entries.isEmpty()) return
    Card(Modifier.fillMaxWidth().testTag("pending_working_restore")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Начатое восстановление рабочей базы", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text("По локальному журналу. Открытие записи ничего не запускает: там можно отменить ожидающий запрос или отдельно проверить результат.",
                style = MaterialTheme.typography.bodySmall)
            when {
                state.loading -> LinearProgressIndicator(Modifier.fillMaxWidth())
                !state.available -> Text("Журнал начатых восстановлений недоступен. Вернитесь назад и откройте экран заново.", modifier = Modifier.testTag("pending_working_restore_unavailable"))
                else -> state.entries.forEach { entry ->
                    Text(entry.text, style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = { onOpen(entry.operationId, entry.sourceOperationId) }, enabled = selectionEnabled,
                        modifier = Modifier.fillMaxWidth().testTag("pending_working_restore_" + entry.operationId)) {
                        Text("Открыть запись · " + entry.operationId.take(8))
                    }
                }
            }
        }
    }
}
