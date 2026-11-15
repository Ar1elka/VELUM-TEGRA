package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.savedstate.SavedStateRegistryOwner
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryPlanReview
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryReadinessPolicy
import com.velumtegra.xuimobile.core.model.BackupSlotInventory
import com.velumtegra.xuimobile.core.model.UpdatePreflightSnapshot
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class ManagementDatabaseBackupState(val review: ManagementRestartReview? = null,
    val source: UpdatePreflightSnapshot? = null, val sourceReady: Boolean = false, val loading: Boolean = true,
    val busy: Boolean = false, val dialog: String? = null, val operationId: String? = null,
    val observation: DatabaseBackupObservation? = null, val notice: String? = null,
    val slots: BackupSlotInventory? = null)

/** Restores pointers only. Opening/refreshing/foregrounding this screen performs local reads only. */
class ManagementDatabaseBackupViewModel(private val saved: SavedStateHandle,
    private val server: String, private val installation: String, private val access: String,
    private val sourcePointer: UpdatePreflightPointer, private val local: ManagementRestartLocalPort,
    private val sources: UpdatePreflightStatusPort, private val statuses: DatabaseBackupStatusPort,
    private val now: () -> Instant = Instant::now) : ViewModel() {
    private val restored: String? = saved.get<String>("dbb_operation")?.takeIf { it.isNotBlank() &&
        saved.get<String>("dbb_server") == server && saved.get<String>("dbb_installation") == installation &&
        saved.get<String>("dbb_access") == access }
    private val mutable = MutableStateFlow(ManagementDatabaseBackupState(operationId = restored,
        notice = if (saved.get<Boolean>("dbb_launch_pending") == true) "Передача предыдущего запроса не подтверждена. Автоматического повтора не будет." else null))
    val state: StateFlow<ManagementDatabaseBackupState> = mutable
    private var foreground = false
    private var generation = 0L
    private var job: Job? = null
    private var actionJob: Job? = null
    private var reviewed: ManagementRestartReview? = null
    private var ticket = 0L
    fun enterForeground() { foreground = true; refresh() }
    fun leaveForeground() {
        foreground = false; generation++; job?.cancel(); actionJob?.cancel(); reviewed = null
        mutable.value = mutable.value.copy(review = null, source = null, sourceReady = false, observation = null,
            loading = true, busy = false, dialog = null)
    }
    fun refresh() {
        if (!foreground || mutable.value.busy) return
        job?.cancel(); reviewed = null
        val g = ++generation
        mutable.value = mutable.value.copy(loading = true, dialog = null, review = null, source = null, sourceReady = false, observation = null)
        job = viewModelScope.launch {
            try {
                val r = readLocal() ?: run { invalidate(g); return@launch }
                val report = sources.read(server, installation, sourcePointer).snapshot
                if (!current(g)) return@launch
                if (readLocal() != r) { invalidate(g); return@launch }
                if (!current(g)) return@launch
                val unfinished = statuses.unfinished(server, installation, access)
                if (!current(g)) return@launch
                var id = mutable.value.operationId
                if (id == null && unfinished.isNotEmpty()) { id = unfinished.first(); save(id) }
                val sourceExact = report?.takeIf { it.scope.operationId.value == sourcePointer.operationId &&
                    it.scope.serverId.value == server && it.scope.installationId.value == installation &&
                    it.scope.serverAccessId.value == access && sourcePointer.accessId == access }
                mutable.value = mutable.value.copy(review = r, source = sourceExact, loading = false, operationId = id, slots = statuses.slots(r),
                    sourceReady = sourceExact != null && UpdateRecoveryReadinessPolicy.review(sourceExact, now()) is UpdateRecoveryPlanReview.Draft)
                if (id != null) poll(id, r, g)
            } catch (cancel: CancellationException) { throw cancel
            } catch (_: Exception) { invalidate(g) }
        }
    }
    fun requestCreate() {
        val s = mutable.value
        if (!foreground || s.busy || s.loading || s.dialog != null || !s.sourceReady ||
            (s.operationId != null && s.observation?.terminal != true)) return
        if (s.source == null || UpdateRecoveryReadinessPolicy.review(s.source, now()) !is UpdateRecoveryPlanReview.Draft) {
            mutable.value = s.copy(sourceReady = false, notice = "Отчёт устарел. Нужна новая проверка установки."); return
        }
        reviewed = s.review ?: return
        mutable.value = s.copy(dialog = "CREATE")
    }
    fun requestCheck() {
        val s = mutable.value
        if (!foreground || s.busy || s.loading || s.dialog != null || s.observation?.mayCheck != true) return
        reviewed = s.review ?: return
        mutable.value = s.copy(dialog = "CHECK")
    }
    fun dismiss() { reviewed = null; mutable.value = mutable.value.copy(dialog = null) }
    fun confirm(actions: DatabaseBackupActionPort) {
        val r = reviewed ?: return
        val mode = mutable.value.dialog ?: return
        if (!foreground || mutable.value.busy) return
        reviewed = null
        runAction(r, actions, mode)
    }
    fun cancelPending(actions: DatabaseBackupActionPort) {
        val s = mutable.value
        if (!foreground || s.busy || s.dialog != null || s.observation?.mayCancel != true) return
        runAction(s.review ?: return, actions, "CANCEL")
    }
    private fun runAction(r: ManagementRestartReview, actions: DatabaseBackupActionPort, mode: String) {
        job?.cancel()
        val g = ++generation
        val ownTicket = ++ticket
        val operation = mutable.value.operationId
        mutable.value = mutable.value.copy(busy = true, dialog = null, notice = null,
            observation = if (mode == "CREATE") null else mutable.value.observation)
        if (mode == "CREATE") saved["dbb_launch_pending"] = true
        actionJob = viewModelScope.launch {
            try {
                if (readLocal() != r) { invalidate(g); return@launch }
                if (!current(g)) return@launch
                if (mode == "CREATE") {
                    val report = sources.read(server, installation, sourcePointer).snapshot
                    if (!current(g)) return@launch
                    if (report == null || report != mutable.value.source || UpdateRecoveryReadinessPolicy.review(report, now()) !is UpdateRecoveryPlanReview.Draft) {
                        mutable.value = mutable.value.copy(busy = false, sourceReady = false, notice = "Отчёт изменился или устарел. Нужна новая проверка установки.")
                        saved["dbb_launch_pending"] = false
                        return@launch
                    }
                }
                val message = when (mode) {
                    "CREATE" -> when (val result = actions.createConfirmed(r, sourcePointer)) {
                        is DatabaseBackupStart.Recorded -> {
                            if (ticket == ownTicket) { save(result.operationId); mutable.value = mutable.value.copy(operationId = result.operationId) }
                            null
                        }
                        is DatabaseBackupStart.Blocked -> result.text
                    }
                    "CHECK" -> if (operation != null) actions.checkConfirmed(r, operation) else "Запись недоступна."
                    else -> if (operation != null) actions.cancelPending(r, operation) else "Запись недоступна."
                }
                if (ticket != ownTicket) return@launch
                saved["dbb_launch_pending"] = false
                if (!current(g)) return@launch
                if (readLocal() != r) { invalidate(g); return@launch }
                if (!current(g)) return@launch
                mutable.value = mutable.value.copy(busy = false, notice = message)
                refresh()
            } catch (cancel: CancellationException) { throw cancel
            } catch (_: Exception) {
                if (current(g)) mutable.value = mutable.value.copy(busy = false,
                    notice = "Передача запроса не подтверждена. Обновите локальный статус; автоматического повтора не будет.")
            }
        }
    }
    private suspend fun poll(id: String, r: ManagementRestartReview, g: Long) {
        repeat(120) {
            val result = statuses.read(server, installation, access, id)
            if (!current(g)) return
            if (readLocal() != r) { invalidate(g); return }
            if (!current(g)) return
            val exact = result?.takeIf { it.operationId == id }
            mutable.value = mutable.value.copy(observation = exact, slots = statuses.slots(r), notice = if (exact == null) "Точная запись или связь с установкой недоступна." else mutable.value.notice)
            if (result == null || result.operationId != id || result.terminal) return
            delay(1000)
        }
    }
    private suspend fun readLocal(): ManagementRestartReview? =
        (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review
            ?.takeIf { it.matches(server, installation, access) }
    private fun current(g: Long) = foreground && generation == g
    private fun invalidate(g: Long) {
        if (!current(g)) return
        reviewed = null
        mutable.value = mutable.value.copy(review = null, source = null, sourceReady = false, loading = false,
            busy = false, dialog = null, observation = null, notice = "Сохранённая цель изменилась или недоступна. Выберите установку и SSH-профиль заново.")
    }
    override fun onCleared() { foreground = false; generation++; job?.cancel(); actionJob?.cancel(); super.onCleared() }
    private fun save(id: String) {
        saved["dbb_operation"] = id; saved["dbb_server"] = server; saved["dbb_installation"] = installation; saved["dbb_access"] = access
    }
}

class ManagementDatabaseBackupViewModelFactory(owner: SavedStateRegistryOwner, private val server: String,
    private val installation: String, private val access: String, private val source: UpdatePreflightPointer,
    private val local: ManagementRestartLocalPort, private val sources: UpdatePreflightStatusPort,
    private val statuses: DatabaseBackupStatusPort) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T {
        require(modelClass == ManagementDatabaseBackupViewModel::class.java)
        return ManagementDatabaseBackupViewModel(handle, server, installation, access, source, local, sources, statuses) as T
    }
}
