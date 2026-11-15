package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import com.velumtegra.xuimobile.core.model.ExistingInstallationServiceAction
import androidx.lifecycle.viewModelScope
import androidx.savedstate.SavedStateRegistryOwner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

enum class ManagementRestartReviewAction(val serviceAction: ExistingInstallationServiceAction?) {
    START(ExistingInstallationServiceAction.START),
    STOP(ExistingInstallationServiceAction.STOP),
    RESTART(ExistingInstallationServiceAction.RESTART),
    XRAY_RESTART(ExistingInstallationServiceAction.XRAY_RESTART),
    ENABLE_AUTOSTART(ExistingInstallationServiceAction.ENABLE_AUTOSTART),
    DISABLE_AUTOSTART(ExistingInstallationServiceAction.DISABLE_AUTOSTART),
    CHECK_RESULT(null),
}
data class ManagementRestartUiState(val loading: Boolean = true, val review: ManagementRestartReview? = null,
    val notice: String? = null, val pending: ManagementRestartReviewAction? = null, val working: Boolean = false,
    val operationId: String? = null, val observation: ManagementRestartObservation? = null,
    val unfinished: List<UnfinishedManagementRestart> = emptyList()) {
    val mayRestart get() = !loading && !working && pending == null && review != null &&
        (operationId == null || observation?.terminal == true) && unfinished.isEmpty()
}
/** No Activity/session/credential material. Persist only exact journal/scope identifiers. */
class ManagementRestartViewModel(private val saved: SavedStateHandle, private val serverId: String,
    private val installationId: String, private val accessId: String, private val local: ManagementRestartLocalPort,
    private val statuses: ManagementRestartStatusPort) : ViewModel() {
    private val mutableState = MutableStateFlow(ManagementRestartUiState(operationId = restoredOperation()))
    val state: StateFlow<ManagementRestartUiState> = mutableState
    private var foreground = false
    private var generation = 0L
    private var statusGeneration = 0L
    private var readJob: Job? = null
    private var pollJob: Job? = null
    fun enterForeground() { if (!foreground) { foreground = true; refreshLocal() } }
    fun leaveForeground() {
        foreground = false; generation++; statusGeneration++; readJob?.cancel(); pollJob?.cancel()
        mutableState.value = mutableState.value.copy(pending = null, review = null, observation = null, loading = true)
    }
    fun refreshLocal() {
        if (!foreground || mutableState.value.working) return
        val turn = ++generation; statusGeneration++; readJob?.cancel(); pollJob?.cancel()
        mutableState.value = mutableState.value.copy(loading = true, review = null, pending = null, notice = null)
        readJob = viewModelScope.launch {
            try {
                val r = local.readExact(serverId, installationId, accessId)
                val operations = statuses.unfinishedExact(serverId, installationId, accessId)
                if (!isCurrent(turn)) return@launch
                val ready = (r as? ManagementRestartLocalReview.Ready)?.review?.takeIf { it.matches(serverId, installationId, accessId) }
                mutableState.value = mutableState.value.copy(loading = false, review = ready, unfinished = operations,
                    notice = if (ready != null) null else (r as? ManagementRestartLocalReview.Unavailable)?.message ?: "Цель не соответствует выбранному серверу.")
                refreshStatus()
            } catch (c: CancellationException) { throw c } catch (_: Exception) { if (isCurrent(turn)) mutableState.value = mutableState.value.copy(loading = false,
                review = null, pending = null, notice = "Не удалось прочитать сведения и журнал.") }
        }
    }
    fun requestServiceAction(action: ExistingInstallationServiceAction) {
        if (foreground && mutableState.value.mayRestart) {
            val pending = ManagementRestartReviewAction.entries.single { it.serviceAction == action }
            mutableState.value = mutableState.value.copy(pending = pending, notice = null)
        }
    }
    fun requestCheckResult() {
        val s = mutableState.value
        if (foreground && !s.working && s.pending == null && s.review != null && s.observation?.mayCheckReadOnly == true)
            mutableState.value = s.copy(pending = ManagementRestartReviewAction.CHECK_RESULT, notice = null)
    }
    fun dismissReview() { mutableState.value = mutableState.value.copy(pending = null) }
    fun confirm(port: ManagementRestartActionPort) {
        val s = mutableState.value; val action = s.pending ?: return; val review = s.review ?: return
        if (!foreground || s.working || !review.matches(serverId, installationId, accessId)) return
        val turn = generation; val operation = s.operationId
        mutableState.value = s.copy(pending = null, working = true, notice = null)
        viewModelScope.launch {
            try {
                val fresh = (local.readExact(serverId, installationId, accessId) as? ManagementRestartLocalReview.Ready)?.review
                if (!isCurrent(turn) || fresh != review) {
                    if (isCurrent(turn)) mutableState.value = mutableState.value.copy(notice = "Цель изменилась после просмотра. Обновите сведения и подтвердите заново.")
                    return@launch
                }
                when (action) {
                    ManagementRestartReviewAction.START, ManagementRestartReviewAction.STOP, ManagementRestartReviewAction.RESTART,
                    ManagementRestartReviewAction.XRAY_RESTART, ManagementRestartReviewAction.ENABLE_AUTOSTART,
                    ManagementRestartReviewAction.DISABLE_AUTOSTART ->
                        when (val r = port.runServiceActionConfirmed(review, requireNotNull(action.serviceAction))) {
                        is ManagementRestartStart.Recorded -> {
                            if (r.operationId.isNotBlank()) bindOperation(r.operationId)
                            else if (isCurrent(turn)) mutableState.value = mutableState.value.copy(notice = "Не получен идентификатор операции.")
                        }
                        is ManagementRestartStart.Blocked -> if (isCurrent(turn)) mutableState.value = mutableState.value.copy(notice = r.message)
                    }
                    ManagementRestartReviewAction.CHECK_RESULT -> {
                        if (operation == null || mutableState.value.operationId != operation) return@launch
                        val error = port.checkResultConfirmed(operation, review)
                        if (isCurrent(turn) && mutableState.value.operationId == operation) mutableState.value = mutableState.value.copy(notice = error)
                    }
                }
            } catch (c: CancellationException) { throw c } catch (_: Exception) { if (isCurrent(turn)) mutableState.value = mutableState.value.copy(
                notice = "Не удалось подтвердить запуск. Посмотрите незавершённые операции перед новым запросом.") }
            finally { finishAction() }
        }
    }
    fun cancelBeforeDispatch(port: ManagementRestartActionPort) {
        val s = mutableState.value; val id = s.operationId ?: return; val review = s.review ?: return
        if (!foreground || s.working || s.pending != null || s.observation?.mayCancelBeforeDispatch != true) return
        val turn = generation; mutableState.value = s.copy(working = true, notice = null)
        viewModelScope.launch {
            try {
                val error = port.cancelBeforeDispatch(id, review)
                if (isCurrent(turn) && mutableState.value.operationId == id) mutableState.value = mutableState.value.copy(notice = error)
            } catch (c: CancellationException) { throw c } catch (_: Exception) { if (isCurrent(turn)) mutableState.value = mutableState.value.copy(notice = "Отмена не подтверждена. Обновите результат.") }
            finally { finishAction() }
        }
    }
    fun observeExisting(id: String) {
        val s = mutableState.value
        if (!foreground || s.working || s.pending != null || id.isBlank() || s.unfinished.none { it.operationId == id }) return
        bindOperation(id); refreshStatus()
    }
    fun refreshStatus() {
        if (!foreground) return
        val id = mutableState.value.operationId ?: return
        val turn = generation; val reading = ++statusGeneration; pollJob?.cancel()
        pollJob = viewModelScope.launch {
            repeat(120) {
                try {
                    val r = statuses.readExact(id, serverId, installationId, accessId)
                    if (!isCurrent(turn) || reading != statusGeneration || mutableState.value.operationId != id) return@launch
                    if (r == null || r.operationId != id) {
                        mutableState.value = mutableState.value.copy(observation = null, notice = "Запись не подтверждена для этой цели. Команда автоматически не отправляется.")
                        return@launch
                    }
                    mutableState.value = mutableState.value.copy(observation = r)
                    if (r.terminal) {
                        val list = statuses.unfinishedExact(serverId, installationId, accessId)
                        if (isCurrent(turn) && reading == statusGeneration && mutableState.value.operationId == id)
                            mutableState.value = mutableState.value.copy(unfinished = list)
                        return@launch
                    }
                } catch (c: CancellationException) { throw c } catch (_: Exception) {
                    if (isCurrent(turn) && reading == statusGeneration && mutableState.value.operationId == id)
                        mutableState.value = mutableState.value.copy(observation = null, notice = "Не удалось прочитать результат из журнала.")
                    return@launch
                }
                delay(1000)
            }
        }
    }
    private fun finishAction() {
        mutableState.value = mutableState.value.copy(working = false)
        if (!foreground) return
        if (mutableState.value.review == null) { refreshLocal(); return }
        val turn = generation
        viewModelScope.launch {
            try {
                val list = statuses.unfinishedExact(serverId, installationId, accessId)
                if (isCurrent(turn)) { mutableState.value = mutableState.value.copy(unfinished = list); refreshStatus() }
            } catch (c: CancellationException) { throw c } catch (_: Exception) { if (isCurrent(turn)) mutableState.value = mutableState.value.copy(notice = "Не удалось обновить список операций.") }
        }
    }
    private fun bindOperation(id: String) {
        statusGeneration++; pollJob?.cancel()
        saved["restart_server"] = serverId; saved["restart_installation"] = installationId
        saved["restart_access"] = accessId; saved["restart_operation"] = id
        mutableState.value = mutableState.value.copy(operationId = id, observation = null)
    }
    private fun restoredOperation(): String? = if (saved.get<String>("restart_server") == serverId &&
        saved.get<String>("restart_installation") == installationId && saved.get<String>("restart_access") == accessId)
        saved.get<String>("restart_operation")?.takeIf { it.isNotBlank() } else null
    private fun isCurrent(turn: Long) = foreground && generation == turn
}
internal class ManagementRestartViewModelFactory(owner: SavedStateRegistryOwner, private val serverId: String,
    private val installationId: String, private val accessId: String, private val local: ManagementRestartLocalPort,
    private val statuses: ManagementRestartStatusPort) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T {
        require(modelClass == ManagementRestartViewModel::class.java)
        return ManagementRestartViewModel(handle, serverId, installationId, accessId, local, statuses) as T
    }
}
