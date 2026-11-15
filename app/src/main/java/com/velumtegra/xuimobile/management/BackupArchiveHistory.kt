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
import com.velumtegra.xuimobile.core.domain.InstallationBackupArchiveInventory
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RestoreCheckBindingPolicy
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** One locally journaled, previously verified installation archive. Not proof that it still exists on the server. */
data class BackupArchiveEntry(val operationId: String, val verifiedAt: Instant) {
    val shortId: String get() = operationId.take(8)
}

sealed interface BackupArchiveHistoryRead {
    data class Page(val entries: List<BackupArchiveEntry>) : BackupArchiveHistoryRead
    data object Unavailable : BackupArchiveHistoryRead
}

/** Local journal read only: no launch, connect, SSH or replay methods. */
fun interface ManagementBackupArchiveHistoryPort {
    suspend fun readExact(server: String, installation: String, access: String): BackupArchiveHistoryRead
}

internal object BackupArchiveHistoryPolicy {
    const val LIMIT = 10
    /** Re-checks every row against the CURRENT exact installation and SSH profile; rejected rows are dropped. */
    fun accepted(rows: List<VersionedOperationSnapshot>, review: ManagementRestartReview): List<BackupArchiveEntry> =
        rows.filter { row ->
            val s = row.snapshot
            s.operationId.value.isNotBlank() && s.updatedAt == s.checkpoint.recordedAt &&
                RestoreCheckBindingPolicy.parentMatches(row, review.installation, review.access)
        }.distinctBy { it.snapshot.operationId.value }
            .sortedWith(compareByDescending<VersionedOperationSnapshot> { it.snapshot.startedAt }.thenBy { it.snapshot.operationId.value })
            .take(LIMIT).map { BackupArchiveEntry(it.snapshot.operationId.value, it.snapshot.updatedAt) }
}

internal class JournalBackupArchiveHistoryPort(private val inventory: InstallationBackupArchiveInventory,
    private val local: ManagementRestartLocalPort) : ManagementBackupArchiveHistoryPort {
    override suspend fun readExact(server: String, installation: String, access: String): BackupArchiveHistoryRead {
        if (listOf(server, installation, access).any { it.isBlank() }) return BackupArchiveHistoryRead.Unavailable
        return try {
            val review = (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review
                ?.takeIf { it.matches(server, installation, access) } ?: return BackupArchiveHistoryRead.Unavailable
            val rows = (inventory.recentVerifiedArchives(ServerId(server), XuiInstallationId(installation), ServerAccessId(access))
                as? OperationJournalResult.Success)?.value?.takeIf { it.size <= BackupArchiveHistoryPolicy.LIMIT }
                ?: return BackupArchiveHistoryRead.Unavailable
            val entries = BackupArchiveHistoryPolicy.accepted(rows, review)
            if ((local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review != review)
                BackupArchiveHistoryRead.Unavailable else BackupArchiveHistoryRead.Page(entries)
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            BackupArchiveHistoryRead.Unavailable
        }
    }
}

data class BackupArchiveHistoryState(val loading: Boolean = true, val available: Boolean = false,
    val entries: List<BackupArchiveEntry> = emptyList())

class ManagementBackupArchiveHistoryViewModel(private val server: String, private val installation: String,
    private val access: String, private val port: ManagementBackupArchiveHistoryPort) : ViewModel() {
    private val mutable = MutableStateFlow(BackupArchiveHistoryState())
    val state: StateFlow<BackupArchiveHistoryState> = mutable
    private var generation = 0L
    private var job: Job? = null
    fun enterForeground() = refresh()
    fun leaveForeground() { generation++; job?.cancel(); mutable.value = BackupArchiveHistoryState() }
    fun refresh() {
        job?.cancel(); val g = ++generation
        mutable.value = BackupArchiveHistoryState()
        job = viewModelScope.launch {
            val read = try { port.readExact(server, installation, access) } catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { BackupArchiveHistoryRead.Unavailable }
            if (g == generation) mutable.value = when (read) {
                is BackupArchiveHistoryRead.Page -> BackupArchiveHistoryState(loading = false, available = true, entries = read.entries)
                BackupArchiveHistoryRead.Unavailable -> BackupArchiveHistoryState(loading = false)
            }
        }
    }
}

internal class ManagementBackupArchiveHistoryViewModelFactory(private val server: String, private val installation: String,
    private val access: String, private val port: ManagementBackupArchiveHistoryPort) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        require(modelClass == ManagementBackupArchiveHistoryViewModel::class.java)
        return ManagementBackupArchiveHistoryViewModel(server, installation, access, port) as T
    }
}

/** Selection only opens the existing restore-check screen; nothing is launched from here. */
@Composable
internal fun BackupArchiveHistorySection(
    viewModel: ManagementBackupArchiveHistoryViewModel,
    onSelect: (String) -> Unit,
    selectionEnabled: Boolean = true,
) {
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
    val time = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm").withZone(ZoneId.systemDefault())
    Card(Modifier.fillMaxWidth().testTag("backup_archives")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Готовые копии", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text("Нажмите на копию, чтобы восстановить панель из неё.",
                style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("backup_archives_note"))
            when {
                state.loading -> { LinearProgressIndicator(Modifier.fillMaxWidth()); Text("Читаем список копий…") }
                !state.available -> Text("Список копий недоступен. Вернитесь назад и откройте экран заново.", modifier = Modifier.testTag("backup_archives_unavailable"))
                state.entries.isEmpty() -> Text("Копий пока нет. Проверьте установку ниже и создайте первую.", modifier = Modifier.testTag("backup_archives_empty"))
                else -> state.entries.forEach { entry ->
                    OutlinedButton(
                        onClick = { onSelect(entry.operationId) },
                        enabled = selectionEnabled,
                        modifier = Modifier.fillMaxWidth().testTag("backup_archive_" + entry.operationId),
                    ) {
                        Text("Копия от " + humanTime(entry.verifiedAt))
                    }
                }
            }
        }
    }
}
