package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class ServiceLogFilter { ALL, WARNING_AND_ERROR }
data class ManagementServiceLogsState(
    val local: LocalManagementReview = LocalManagementReview.Loading,
    val profile: LocalSshAccessSummary? = null,
    val reviewing: Boolean = false,
    val launching: Boolean = false,
    val reading: Boolean = false,
    val pointer: ServiceLogPointer? = null,
    val result: ServiceLogStatus? = null,
    val filter: ServiceLogFilter = ServiceLogFilter.ALL,
    val notice: String? = null,
) {
    val visibleEntries get() = result?.snapshot?.entries.orEmpty().filter {
        filter == ServiceLogFilter.ALL || (it.priority?.let { priority -> priority <= 4 } == true)
    }
}

/** Only confirmation calls a visible action port. Refresh/restoration/polling are local reads. */
class ManagementServiceLogsViewModel(
    private val saved: SavedStateHandle,
    private val server: String,
    private val installation: String,
    private val access: String,
    private val localPort: ManagementLocalReviewPort,
    private val statuses: ServiceLogStatusPort,
    private val readiness: SshReadinessPort,
) : ViewModel() {
    private val restored = saved.get<String>("logs_operation")?.takeIf { it.isNotBlank() &&
        saved.get<String>("logs_server") == server && saved.get<String>("logs_installation") == installation &&
        saved.get<String>("logs_access") == access }?.let { ServiceLogPointer(it, access) }
    private val _state = MutableStateFlow(ManagementServiceLogsState(pointer = restored,
        filter = ServiceLogFilter.entries.firstOrNull { it.name == saved.get<String>("logs_filter") } ?: ServiceLogFilter.ALL,
        notice = if (saved.get<Boolean>("logs_launch_pending") == true)
            "Передача запроса была прервана. Автоматического повтора не будет." else null))
    val state = _state.asStateFlow()
    private var foreground = false
    private var generation = 0L
    private var launchTicket = 0L
    private var job: Job? = null
    private var actionJob: Job? = null
    private var reviewed: LocalManagementReview.Ready? = null
    private var reviewedProfile: LocalSshAccessSummary? = null

    fun enterForeground() { foreground = true; refreshLocal() }
    fun leaveForeground() {
        foreground = false; generation++; job?.cancel(); actionJob?.cancel(); reviewed = null; reviewedProfile = null
        _state.value = _state.value.copy(local = LocalManagementReview.Loading, profile = null, reviewing = false,
            launching = false, reading = false, result = null)
    }

    fun refreshLocal() {
        if (!foreground || _state.value.launching) return
        job?.cancel(); reviewed = null
        val g = ++generation
        _state.value = _state.value.copy(local = LocalManagementReview.Loading, profile = null, reviewing = false, result = null, reading = false)
        job = viewModelScope.launch {
            try {
                val review = readLocal()
                if (!current(g)) return@launch
                val profile = readProfile()
                if (!current(g)) return@launch
                if (profile == null) { invalidate(); return@launch }
                _state.value = _state.value.copy(local = review, profile = profile)
                if (review is LocalManagementReview.Ready) _state.value.pointer?.let { poll(it, review, g) }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) { if (current(g)) invalidate() }
        }
    }

    fun requestRead() {
        val s = _state.value
        val ready = s.local as? LocalManagementReview.Ready ?: return
        if (!foreground || s.launching || s.reviewing || access !in ready.accessIds) return
        val profile = s.profile ?: return
        reviewed = ready
        reviewedProfile = profile
        _state.value = s.copy(reviewing = true)
    }
    fun dismissReview() { reviewed = null; reviewedProfile = null; _state.value = _state.value.copy(reviewing = false) }

    fun confirmRead(actions: ServiceLogActionPort) {
        val review = reviewed ?: return
        val profile = reviewedProfile ?: return
        if (!foreground || !_state.value.reviewing || _state.value.launching) return
        reviewed = null; job?.cancel()
        val g = ++generation
        val ticket = ++launchTicket
        _state.value = _state.value.copy(reviewing = false, launching = true, result = null, notice = null)
        saved["logs_launch_pending"] = true
        actionJob = viewModelScope.launch {
            try {
                val before = readLocal()
                if (!current(g)) return@launch
                if (before != review || readProfile() != profile) { if (current(g)) invalidate(); return@launch }
                if (!current(g)) return@launch
                val started = actions.start(server, installation, access)
                // Keep a hidden attempt's pointer, but never replace a newer explicit request with its late return.
                if (ticket != launchTicket) return@launch
                if (started is ServiceLogStart.Registered && (started.pointer.accessId != access || started.pointer.operationId.isBlank())) {
                    if (current(g)) invalidate()
                    return@launch
                }
                if (started is ServiceLogStart.Registered) {
                    savePointer(started.pointer)
                    _state.value = _state.value.copy(pointer = started.pointer)
                }
                saved["logs_launch_pending"] = false
                if (!current(g)) return@launch
                val after = readLocal()
                if (!current(g)) return@launch
                if (after != review || readProfile() != profile) { if (current(g)) invalidate(); return@launch }
                if (!current(g)) return@launch
                _state.value = _state.value.copy(launching = false)
                when (started) {
                    is ServiceLogStart.Blocked -> _state.value = _state.value.copy(notice = started.text)
                    is ServiceLogStart.Registered -> poll(started.pointer, review, g)
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (current(g)) _state.value = _state.value.copy(launching = false,
                    notice = "Передача запроса не подтверждена. Автоматического повтора не будет.")
            }
        }
    }

    fun setFilter(filter: ServiceLogFilter) {
        saved["logs_filter"] = filter.name
        _state.value = _state.value.copy(filter = filter)
    }

    private suspend fun poll(pointer: ServiceLogPointer, review: LocalManagementReview.Ready, g: Long) {
        val profile = _state.value.profile ?: return
        _state.value = _state.value.copy(reading = true)
        repeat(90) {
            val before = readLocal()
            if (!current(g)) return
            if (before != review || readProfile() != profile) { if (current(g)) invalidate(); return }
            if (!current(g)) return
            val result = statuses.read(server, installation, pointer)
            if (!current(g)) return
            val after = readLocal()
            if (!current(g)) return
            if (after != review || readProfile() != profile) { if (current(g)) invalidate(); return }
            if (!current(g)) return
            // Independently fence an incorrectly implemented fixture/adapter before projecting any events.
            val scope = result.snapshot?.scope
            if (scope != null && (!result.terminal || scope.operationId.value != pointer.operationId || scope.serverId.value != server ||
                scope.installationId.value != installation || scope.serverAccessId.value != access)) { invalidate(); return }
            _state.value = _state.value.copy(result = result, reading = false)
            if (result.terminal || result.attemptEnded) return
            delay(1000)
        }
        if (current(g)) _state.value = _state.value.copy(reading = false,
            notice = "Подтверждённого итога пока нет. Обновление перечитает только локальный статус.")
    }

    private suspend fun readProfile(): LocalSshAccessSummary? =
        (readiness.previewExact(server, access) as? LocalSshReadinessResult.MetadataPresent)?.summary?.takeIf { it.accessId == access }

    private suspend fun readLocal(): LocalManagementReview {
        val review = localPort.readExact(server, installation).requireExactInstallation(server, installation)
        return if (review is LocalManagementReview.Ready && inspectionReviewMatches(review, server, installation, access)) review
            else LocalManagementReview.Unavailable("Установка или выбранный SSH-доступ больше недоступны.")
    }
    private fun current(g: Long) = foreground && generation == g
    private fun invalidate() {
        reviewed = null
        _state.value = _state.value.copy(local = LocalManagementReview.Unavailable("Сохранённые сведения изменились. Обновите их."),
            profile = null, result = null, reviewing = false, reading = false, launching = false)
    }
    private fun savePointer(pointer: ServiceLogPointer) {
        saved["logs_server"] = server; saved["logs_installation"] = installation
        saved["logs_access"] = pointer.accessId; saved["logs_operation"] = pointer.operationId
    }
}

class ManagementServiceLogsViewModelFactory(owner: SavedStateRegistryOwner, private val server: String,
    private val installation: String, private val access: String, private val local: ManagementLocalReviewPort,
    private val statuses: ServiceLogStatusPort, private val readiness: SshReadinessPort) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T {
        require(modelClass == ManagementServiceLogsViewModel::class.java)
        return ManagementServiceLogsViewModel(handle, server, installation, access, local, statuses, readiness) as T
    }
}
