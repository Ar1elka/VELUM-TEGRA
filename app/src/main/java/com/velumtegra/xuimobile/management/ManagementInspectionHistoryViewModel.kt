package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.savedstate.SavedStateRegistryOwner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class InspectionHistoryFilter { ALL, QUICK, DEEP }

data class InspectionHistoryState(
    val local: LocalManagementReview = LocalManagementReview.Loading,
    val loading: Boolean = true,
    val historyAvailable: Boolean = false,
    val entries: List<InspectionHistoryEntry> = emptyList(),
    val hasOlder: Boolean = false,
    val filter: InspectionHistoryFilter = InspectionHistoryFilter.ALL,
    val selected: ActiveManagementInspection? = null,
    val result: InspectionStatus? = null,
    val reading: Boolean = false,
    val notice: String? = null,
) {
    val filtered: List<InspectionHistoryEntry> get() = entries.filter {
        filter == InspectionHistoryFilter.ALL ||
            (filter == InspectionHistoryFilter.QUICK && it.kind == InspectionKind.QUICK_INSPECT) ||
            (filter == InspectionHistoryFilter.DEEP && it.kind == InspectionKind.DEEP_DIAGNOSTIC)
    }
}

/** Local reads only. There is deliberately no action, Activity, SSH or credential port. */
class ManagementInspectionHistoryViewModel(
    private val saved: SavedStateHandle,
    private val serverId: String,
    private val installationId: String,
    private val localPort: ManagementLocalReviewPort,
    private val historyPort: ManagementInspectionHistoryPort,
    private val statusPort: ManagementInspectionStatusPort,
) : ViewModel() {
    private val restored = restoreHistoryPointer(saved, serverId, installationId)
    private val _state = MutableStateFlow(InspectionHistoryState(
        selected = restored,
        filter = InspectionHistoryFilter.entries.firstOrNull { it.name == saved.get<String>("history_filter") }
            ?: InspectionHistoryFilter.ALL,
    ))
    val state = _state.asStateFlow()
    private var foreground = false
    private var loadGeneration = 0L
    private var reportGeneration = 0L
    private var loadJob: Job? = null
    private var reportJob: Job? = null

    fun enterForeground() {
        foreground = true
        refresh()
    }

    fun leaveForeground() {
        foreground = false
        loadGeneration++
        reportGeneration++
        loadJob?.cancel()
        reportJob?.cancel()
        _state.value = _state.value.copy(local = LocalManagementReview.Loading,
            entries = emptyList(), result = null, historyAvailable = false, loading = true, reading = false)
    }

    fun refresh() {
        if (!foreground) return
        loadJob?.cancel()
        reportJob?.cancel()
        reportGeneration++
        val generation = ++loadGeneration
        _state.value = _state.value.copy(local = LocalManagementReview.Loading,
            entries = emptyList(), result = null, historyAvailable = false, loading = true, reading = false, notice = null)
        loadJob = viewModelScope.launch {
            try {
                val review = localPort.readExact(serverId, installationId)
                    .requireExactInstallation(serverId, installationId)
                if (!isLoadCurrent(generation)) return@launch
                if (review !is LocalManagementReview.Ready) {
                    invalidate(review)
                    return@launch
                }
                val history = historyPort.readExact(serverId, installationId)
                if (!isLoadCurrent(generation)) return@launch
                val fresh = localPort.readExact(serverId, installationId)
                    .requireExactInstallation(serverId, installationId)
                if (!isLoadCurrent(generation)) return@launch
                if (fresh != review) {
                    invalidate(LocalManagementReview.Unavailable("Сохранённые сведения изменились. Обновите историю."))
                    return@launch
                }
                val page = (history as? InspectionHistoryRead.Page)?.takeIf(::validPage)
                _state.value = _state.value.copy(local = review, loading = false,
                    entries = page?.entries.orEmpty(), historyAvailable = page != null,
                    hasOlder = page?.hasOlder ?: false,
                    notice = if (page == null) "История проверок недоступна. Попробуйте обновить её." else null)
                val selected = _state.value.selected
                if (selected != null && selected.accessId !in review.accessIds) {
                    clearSelection()
                    _state.value = _state.value.copy(notice = "SSH-доступ этой проверки больше не связан с установкой.")
                } else if (selected != null) {
                    startReading(selected, review)
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (isLoadCurrent(generation)) invalidate(LocalManagementReview.Unavailable(
                    "Не удалось подтвердить установку или прочитать историю. Обновите сведения."))
            }
        }
    }

    fun setFilter(filter: InspectionHistoryFilter) {
        _state.value = _state.value.copy(filter = filter)
        saved["history_filter"] = filter.name
    }

    fun select(operationId: String) {
        val current = _state.value
        if (!foreground || current.loading || !current.historyAvailable) return
        val review = current.local as? LocalManagementReview.Ready ?: return
        val entry = current.entries.singleOrNull { it.operationId == operationId } ?: return
        if (entry.accessId !in review.accessIds) {
            _state.value = current.copy(notice = "SSH-доступ этой проверки больше не связан с установкой.")
            return
        }
        savePointer(entry.pointer)
        _state.value = current.copy(selected = entry.pointer, result = null, notice = null)
        startReading(entry.pointer, review)
    }

    fun refreshResult() {
        val current = _state.value
        val review = current.local as? LocalManagementReview.Ready ?: return
        if (foreground && !current.loading) current.selected?.let { startReading(it, review) }
    }

    fun clearSelection() {
        reportGeneration++
        reportJob?.cancel()
        savePointer(null)
        _state.value = _state.value.copy(selected = null, result = null, reading = false, notice = null)
    }

    private fun startReading(pointer: ActiveManagementInspection, review: LocalManagementReview.Ready) {
        reportJob?.cancel()
        val attempt = ++reportGeneration
        _state.value = _state.value.copy(result = null, reading = true, notice = null)
        reportJob = viewModelScope.launch {
            fun current() = foreground && reportGeneration == attempt && _state.value.selected == pointer
            try {
                repeat(120) {
                    val before = localPort.readExact(serverId, installationId)
                        .requireExactInstallation(serverId, installationId)
                    if (!current()) return@launch
                    if (before != review || pointer.accessId !in review.accessIds) {
                        invalidate(LocalManagementReview.Unavailable("Привязка установки или SSH-доступа изменилась. Обновите сведения."))
                        return@launch
                    }
                    val result = statusPort.status(pointer.kind, pointer.operationId,
                        serverId, installationId, pointer.accessId)
                    if (!current()) return@launch
                    val after = localPort.readExact(serverId, installationId)
                        .requireExactInstallation(serverId, installationId)
                    if (!current()) return@launch
                    if (after != review) {
                        invalidate(LocalManagementReview.Unavailable("Сохранённые сведения изменились. Отчёт скрыт до обновления."))
                        return@launch
                    }
                    _state.value = _state.value.copy(result = result, reading = false)
                    if (result.terminal) return@launch
                    delay(1_000)
                }
                if (current()) _state.value = _state.value.copy(reading = false,
                    notice = "Итог пока недоступен. Можно перечитать эту же запись журнала.")
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (current()) _state.value = _state.value.copy(result = null, reading = false,
                    notice = "Не удалось прочитать отчёт. Обновите результат этой проверки.")
            }
        }
    }

    private fun validPage(page: InspectionHistoryRead.Page): Boolean = page.entries.size <= 50 &&
        page.entries.map { it.operationId }.distinct().size == page.entries.size && page.entries.all {
            it.serverId == serverId && it.installationId == installationId &&
                it.operationId.isNotBlank() && it.accessId.isNotBlank() && !it.updatedAt.isBefore(it.startedAt)
        }

    private fun invalidate(review: LocalManagementReview) {
        reportGeneration++
        reportJob?.cancel()
        savePointer(null)
        _state.value = _state.value.copy(local = review, loading = false, entries = emptyList(),
            historyAvailable = false, selected = null, result = null, reading = false)
    }

    private fun isLoadCurrent(generation: Long) = foreground && loadGeneration == generation

    private fun savePointer(pointer: ActiveManagementInspection?) {
        saved["history_server"] = serverId
        saved["history_installation"] = installationId
        saved["history_operation"] = pointer?.operationId
        saved["history_access"] = pointer?.accessId
        saved["history_kind"] = pointer?.kind?.name
    }
}

internal fun restoreHistoryPointer(saved: SavedStateHandle, serverId: String,
    installationId: String): ActiveManagementInspection? {
    if (serverId.isBlank() || installationId.isBlank() || saved.get<String>("history_server") != serverId ||
        saved.get<String>("history_installation") != installationId) return null
    val operation = saved.get<String>("history_operation")?.takeIf { it.isNotBlank() } ?: return null
    val access = saved.get<String>("history_access")?.takeIf { it.isNotBlank() } ?: return null
    val kind = InspectionKind.entries.firstOrNull { it.name == saved.get<String>("history_kind") } ?: return null
    return ActiveManagementInspection(kind, operation, access)
}

@Suppress("DEPRECATION")
internal class ManagementInspectionHistoryViewModelFactory(
    owner: SavedStateRegistryOwner,
    private val serverId: String,
    private val installationId: String,
    private val localPort: ManagementLocalReviewPort,
    private val historyPort: ManagementInspectionHistoryPort,
    private val statusPort: ManagementInspectionStatusPort,
) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T {
        require(modelClass == ManagementInspectionHistoryViewModel::class.java)
        return ManagementInspectionHistoryViewModel(handle, serverId, installationId,
            localPort, historyPort, statusPort) as T
    }
}
