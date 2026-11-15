package com.velumtegra.xuimobile.management

import androidx.lifecycle.*
import androidx.savedstate.SavedStateRegistryOwner
import java.time.Instant
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

data class RecoveryPanelCheckState(val choices: List<RecoveryPanelChoice> = emptyList(), val loading: Boolean = true,
    val busy: Boolean = false, val review: RecoveryPanelReview? = null, val result: RecoveryPanelCheckResult? = null,
    val notice: String? = null)
class ManagementRecoveryPanelCheckViewModel(private val saved: SavedStateHandle, private val server: String,
    private val installation: String, private val ssh: String, private val operation: String,
    private val port: RecoveryPanelCheckPort) : ViewModel() {
    private val mutable = MutableStateFlow(RecoveryPanelCheckState())
    val state: StateFlow<RecoveryPanelCheckState> = mutable
    private var foreground = false; private var generation = 0L; private var job: Job? = null
    private fun same(g: Long) = foreground && generation == g
    fun enterForeground() { foreground = true; refresh() }
    fun leaveForeground() { foreground = false; generation++; job?.cancel(); mutable.value.review?.let(port::discard)
        mutable.value = RecoveryPanelCheckState(loading = true) }
    fun refresh() {
        if (!foreground || mutable.value.busy) return
        job?.cancel(); mutable.value.review?.let(port::discard); val g = ++generation
        mutable.value = RecoveryPanelCheckState()
        job = viewModelScope.launch { try {
            val choices = port.choices(server, installation, ssh, operation)
            if (same(g)) mutable.value = RecoveryPanelCheckState(choices = choices, loading = false,
                notice = if (choices.isEmpty()) "Нет точного связанного доступа или источник недоступен. Доступы можно настроить отдельно в WebPanel." else if (saved.get<Boolean>("rpc_attempted") == true) "Предыдущая проверка могла передать пароль. Автоматической отправки нет; прошлое наблюдение не восстанавливается." else null)
        } catch (c: CancellationException) { throw c } catch (_: Exception) {
            if (same(g)) mutable.value = RecoveryPanelCheckState(loading = false, notice = "Не удалось прочитать локальные доступы.")
        } }
    }
    fun select(panel: String) {
        val s = mutable.value
        if (!foreground || s.loading || s.busy || s.choices.none { it.accessId == panel }) return
        s.review?.let(port::discard); val g = ++generation; job?.cancel()
        mutable.value = s.copy(busy = true, review = null, result = null, notice = null)
        job = viewModelScope.launch { try {
            val review = port.review(server, installation, ssh, operation, panel)
            if (!same(g)) { review?.let(port::discard); return@launch }
            val exact = review?.takeIf { it.accessId == panel && it.operationId == operation }
            if (exact == null) review?.let(port::discard)
            mutable.value = mutable.value.copy(busy = false, review = exact,
                notice = if (exact == null) "Доступ не подтверждён. Для приватного HTTPS сначала отдельно проверьте сертификат в WebPanel; другой маршрут не выбирается." else null)
        } catch (c: CancellationException) { throw c } catch (_: Exception) {
            if (same(g)) mutable.value = mutable.value.copy(busy = false, notice = "Локальная проверка доступа не завершена.")
        } }
    }
    fun dismiss() { mutable.value.review?.let(port::discard); mutable.value = mutable.value.copy(review = null) }
    fun confirm() {
        val s = mutable.value; val review = s.review ?: return
        if (!foreground || s.busy || s.loading || review.operationId != operation) return
        val g = ++generation; mutable.value = s.copy(busy = true, review = null, result = null, notice = null)
        // Pointer/unknown notice only: never persist consent, password, cookie or observed success.
        saved["rpc_attempted"] = true
        job = viewModelScope.launch { try {
            val result = port.check(review)
            if (same(g)) mutable.value = mutable.value.copy(busy = false, result = when (result) {
                is RecoveryPanelCheckResult.Verified -> if (result.accessId == review.accessId && !result.observedAt.isBefore(review.reviewedAt) &&
                    !result.observedAt.isAfter(Instant.now().plusSeconds(5))) result
                    else RecoveryPanelCheckResult.Unverified("Результат не совпал с выбранным доступом или временем.")
                is RecoveryPanelCheckResult.Unverified -> result
            })
        } catch (c: CancellationException) { throw c } catch (_: Exception) {
            if (same(g)) mutable.value = mutable.value.copy(busy = false, result = RecoveryPanelCheckResult.Unverified("Итог входа неизвестен. Автоматического повтора нет."))
        } }
    }
}
class ManagementRecoveryPanelCheckViewModelFactory(owner: SavedStateRegistryOwner, private val server: String,
    private val installation: String, private val ssh: String, private val operation: String, private val port: RecoveryPanelCheckPort)
    : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST") override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T =
        ManagementRecoveryPanelCheckViewModel(handle, server, installation, ssh, operation, port) as T
}
