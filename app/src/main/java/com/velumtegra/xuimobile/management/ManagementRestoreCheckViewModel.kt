package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.savedstate.SavedStateRegistryOwner
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.velumtegra.xuimobile.core.model.RestoreCheckBinding
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

private const val RESTORE_CHECK_RECORD_UNAVAILABLE = "Точная запись или исходная копия недоступна."

data class ManagementRestoreCheckState(val review: ManagementRestartReview? = null, val source: RestoreCheckSourceReview? = null,
    val loading: Boolean = true, val busy: Boolean = false, val dialog: String? = null, val operationId: String? = null,
    val observation: RestoreCheckObservation? = null, val dialogProof: RestoreCheckBinding? = null, val notice: String? = null)

/** Foreground reads are local. Saved state contains pointers only, never confirmations or execution permission. */
class ManagementRestoreCheckViewModel(private val saved: SavedStateHandle, private val server: String,
    private val installation: String, private val access: String, private val source: String,
    private val local: ManagementRestartLocalPort, private val statuses: RestoreCheckStatusPort) : ViewModel() {
    private val restored = saved.get<String>("rc_operation")?.takeIf { it.isNotBlank() && saved.get<String>("rc_server") == server &&
        saved.get<String>("rc_installation") == installation && saved.get<String>("rc_access") == access && saved.get<String>("rc_source") == source }
    private val mutable = MutableStateFlow(ManagementRestoreCheckState(operationId = restored,
        notice = if (saved.get<Boolean>("rc_launch_pending") == true) "Передача предыдущего запроса не подтверждена. Автоматического повтора не будет." else null))
    val state: StateFlow<ManagementRestoreCheckState> = mutable
    private var foreground = false
    private var generation = 0L
    private var ticket = 0L
    private var job: Job? = null
    private var actionJob: Job? = null
    private var reviewed: Pair<ManagementRestartReview, RestoreCheckSourceReview>? = null
    fun enterForeground() { foreground = true; refresh() }
    fun leaveForeground() {
        foreground = false; generation++; ticket++; job?.cancel(); actionJob?.cancel(); reviewed = null
        mutable.value = mutable.value.copy(review = null, source = null, observation = null, loading = true, busy = false, dialog = null, dialogProof = null)
    }
    fun refresh() {
        if (!foreground || mutable.value.busy) return
        job?.cancel(); reviewed = null
        val g = ++generation
        mutable.value = mutable.value.copy(loading = true, review = null, source = null, observation = null, dialog = null, dialogProof = null)
        job = viewModelScope.launch {
            try {
                val r = readLocal() ?: run { invalidate(g); return@launch }
                val original = statuses.source(server, installation, access, source)?.takeIf { it.operationId == source }
                if (!current(g)) return@launch
                if (original == null || readLocal() != r) { invalidate(g); return@launch }
                if (!current(g)) return@launch
                var id = mutable.value.operationId
                var observation = id?.let { statuses.read(server, installation, access, it) }?.takeIf { exact(it, id, original) }
                if (!current(g)) return@launch
                if (observation == null) {
                    // Saved pointer absent or stale: newest unfinished for this archive, then the latest verified
                    // result. A failed unfinished read never falls through to the finished result.
                    val unfinished = statuses.unfinishedChecked(server, installation, access, source)
                    if (!current(g)) return@launch
                    if (unfinished == null) {
                        invalidate(g, "Журнал восстановления недоступен. Обновите локальный статус.")
                        return@launch
                    }
                    val candidate = unfinished.firstOrNull() ?: statuses.latestVerified(server, installation, access, source)
                    if (!current(g)) return@launch
                    val found = candidate?.let { c -> statuses.read(server, installation, access, c)?.takeIf { exact(it, c, original) } }
                    if (found != null) { id = found.operationId; observation = found }
                    else if (id == null && unfinished.isNotEmpty()) id = unfinished.first()
                }
                if (!current(g)) return@launch
                if (readLocal() != r || statuses.source(server, installation, access, source) != original) { invalidate(g); return@launch }
                if (!current(g)) return@launch
                if (id != null && id != mutable.value.operationId) save(id)
                mutable.value = mutable.value.copy(review = r, source = original, loading = false, operationId = id, observation = observation,
                    notice = if (observation != null) mutable.value.notice.takeUnless { it == RESTORE_CHECK_RECORD_UNAVAILABLE } else mutable.value.notice)
                if (id != null && observation?.terminal != true) poll(id, r, original, g)
            } catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { if (current(g)) invalidate(g) }
        }
    }
    fun requestInspect() = request("SOURCE", mutable.value.source != null && (mutable.value.operationId == null || mutable.value.observation?.terminal == true))
    fun requestInspectCurrent() = request("SOURCE_AGAIN", mutable.value.observation?.mayInspect == true)
    fun requestRestore() = request("RESTORE", mutable.value.observation?.mayRestore == true)
    fun requestCheck() = request("CHECK", mutable.value.observation?.mayCheck == true)
    private fun request(mode: String, allowed: Boolean) {
        val s = mutable.value
        if (!foreground || s.loading || s.busy || !allowed || s.review == null || s.source == null) return
        reviewed = s.review to s.source; mutable.value = s.copy(dialog = mode, dialogProof = s.observation?.sourceProof)
    }
    fun dismiss() { reviewed = null; mutable.value = mutable.value.copy(dialog = null, dialogProof = null) }
    fun confirm(actions: RestoreCheckActionPort) {
        val s = mutable.value; val mode = s.dialog ?: return; val r = reviewed ?: return
        if (!foreground || s.busy || s.loading || actionJob?.isActive == true) return
        val g = generation; val t = ++ticket; reviewed = null; job?.cancel()
        mutable.value = s.copy(dialog = null, dialogProof = null, busy = true, notice = null)
        saved["rc_launch_pending"] = true
        actionJob = viewModelScope.launch {
            try {
                if (readLocal() != r.first || statuses.source(server, installation, access, source) != r.second) { invalidate(g); return@launch }
                if (!current(g) || t != ticket) return@launch
                var id = mutable.value.operationId
                val notice = if (mode == "SOURCE") {
                    when (val result = actions.inspectConfirmed(r.first, source)) {
                        is RestoreCheckStart.Recorded -> if (result.operationId.isBlank()) "Не удалось сохранить точный запрос." else { id = result.operationId; save(result.operationId); null }
                        is RestoreCheckStart.Blocked -> result.text
                    }
                } else {
                    val operation = id ?: return@launch
                    when (mode) {
                        "RESTORE" -> if (s.dialogProof == null) "Состав копии не подтверждён."
                            else actions.restoreConfirmed(r.first, operation, s.dialogProof)
                        "SOURCE_AGAIN" -> actions.inspectCurrentConfirmed(r.first, operation)
                        else -> actions.checkConfirmed(r.first, operation)
                    }
                }
                if (!current(g) || t != ticket) return@launch
                saved["rc_launch_pending"] = false
                mutable.value = mutable.value.copy(busy = false, operationId = id, notice = notice)
                if (id != null) {
                    val target = requireNotNull(id)
                    job = viewModelScope.launch { poll(target, r.first, r.second, g) }
                }
            } catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { if (current(g)) mutable.value = mutable.value.copy(busy = false, notice = "Передача запроса не подтверждена. Обновите локальный статус; повтор не отправляется.") }
        }
    }
    fun cancelPending(actions: RestoreCheckActionPort) {
        val s = mutable.value; val r = s.review ?: return; val id = s.operationId ?: return
        if (!foreground || s.busy || s.loading || s.observation?.mayCancel != true) return
        val g = generation; job?.cancel(); mutable.value = s.copy(busy = true)
        actionJob = viewModelScope.launch {
            try {
                val notice = if (readLocal() == r) actions.cancelPending(r, id) else "Точная цель изменилась."
                if (!current(g)) return@launch
                mutable.value = mutable.value.copy(busy = false, notice = notice); refresh()
            } catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { if (current(g)) mutable.value = mutable.value.copy(busy = false, notice = "Отмена не подтверждена. Обновите локальный статус.") }
        }
    }
    private suspend fun poll(id: String, r: ManagementRestartReview, original: RestoreCheckSourceReview, g: Long) {
        repeat(210) {
            val result = statuses.read(server, installation, access, id)
            if (!current(g)) return
            if (readLocal() != r || statuses.source(server, installation, access, source) != original) { invalidate(g); return }
            if (!current(g)) return
            val checked = result?.takeIf { exact(it, id, original) }
            mutable.value = mutable.value.copy(observation = checked,
                notice = if (checked == null) RESTORE_CHECK_RECORD_UNAVAILABLE
                    else mutable.value.notice.takeUnless { it == RESTORE_CHECK_RECORD_UNAVAILABLE })
            if (checked == null || checked.terminal) return
            delay(1000)
        }
    }
    private fun exact(o: RestoreCheckObservation, id: String?, original: RestoreCheckSourceReview) =
        o.operationId == id && o.sourceOperationId == source &&
            (o.sourceProof == null || (o.sourceProof.source == original.binding && o.sourceProof.sourceOperationId.value == source)) &&
            (o.receipt == null || (o.receipt.scope.operationId.value == id && o.receipt.scope.serverId.value == server &&
                o.receipt.scope.installationId.value == installation && o.receipt.scope.serverAccessId.value == access && o.receipt.binding == o.sourceProof))
    private suspend fun readLocal() = (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review
        ?.takeIf { it.matches(server, installation, access) }
    private fun current(g: Long) = foreground && generation == g
    private fun invalidate(g: Long, notice: String = "Установка, SSH-профиль или исходная копия изменились. Выберите их заново.") {
        if (!current(g)) return
        reviewed = null; mutable.value = mutable.value.copy(review = null, source = null, observation = null, loading = false, busy = false,
            dialog = null, dialogProof = null, notice = notice)
    }
    private fun save(id: String) {
        saved["rc_operation"] = id; saved["rc_server"] = server; saved["rc_installation"] = installation
        saved["rc_access"] = access; saved["rc_source"] = source
    }
    override fun onCleared() { foreground = false; generation++; ticket++; job?.cancel(); actionJob?.cancel(); super.onCleared() }
}

class ManagementRestoreCheckViewModelFactory(owner: SavedStateRegistryOwner, private val server: String,
    private val installation: String, private val access: String, private val source: String,
    private val local: ManagementRestartLocalPort, private val statuses: RestoreCheckStatusPort) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T {
        require(modelClass == ManagementRestoreCheckViewModel::class.java)
        return ManagementRestoreCheckViewModel(handle, server, installation, access, source, local, statuses) as T
    }
}
