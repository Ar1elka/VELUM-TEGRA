package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.core.domain.UpdatePackageEligibility
import com.velumtegra.xuimobile.core.domain.UpdatePackagePolicy
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryReadinessPolicy
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryPlanReview
import com.velumtegra.xuimobile.core.model.UpdateRecoveryDraftPlan
import com.velumtegra.xuimobile.core.model.UpdatePackageReceipt
import com.velumtegra.xuimobile.core.model.UpdatePackageRequest
import com.velumtegra.xuimobile.core.model.UpdatePreflightSnapshot
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.Instant

data class ManagementUpdatePreparationState(
    val local: LocalManagementReview = LocalManagementReview.Loading,
    val profile: LocalSshAccessSummary? = null,
    val reviewing: Boolean = false,
    val launching: Boolean = false,
    val reading: Boolean = false,
    val pointer: UpdatePreflightPointer? = null,
    val result: UpdatePreflightStatus? = null,
    val notice: String? = null,
    val packageReview: UpdatePackageRequest? = null,
    val packageBusy: Boolean = false,
    val packageReceipt: UpdatePackageReceipt? = null,
    val packageNotice: String? = null,
    val recoveryReading: Boolean = false,
    val recoveryPlan: UpdateRecoveryDraftPlan? = null,
    val recoveryNotice: String? = null,
)

/** Only confirmation calls a visible action port. Refresh/restoration/polling are local reads. */
class ManagementUpdatePreparationViewModel(
    private val saved: SavedStateHandle,
    private val server: String,
    private val installation: String,
    private val access: String,
    private val localPort: ManagementLocalReviewPort,
    private val statuses: UpdatePreflightStatusPort,
    private val readiness: SshReadinessPort,
    private val packages: UpdatePackagePreparationPort? = null,
    private val now: () -> Instant = Instant::now,
) : ViewModel() {
    private val restored = saved.get<String>("update_preflight_operation")?.takeIf { it.isNotBlank() &&
        saved.get<String>("update_preflight_server") == server && saved.get<String>("update_preflight_installation") == installation &&
        saved.get<String>("update_preflight_access") == access }?.let { UpdatePreflightPointer(it, access) }
    private val _state = MutableStateFlow(ManagementUpdatePreparationState(pointer = restored,
        notice = if (saved.get<Boolean>("update_preflight_launch_pending") == true)
            "Передача запроса была прервана. Автоматического повтора не будет." else null))
    val state = _state.asStateFlow()
    private var foreground = false
    private var generation = 0L
    private var launchTicket = 0L
    private var job: Job? = null
    private var actionJob: Job? = null
    private var reviewed: LocalManagementReview.Ready? = null
    private var reviewedProfile: LocalSshAccessSummary? = null
    private var packageJob: Job? = null
    private var recoveryJob: Job? = null
    private var packageReviewedLocal: LocalManagementReview.Ready? = null
    private var packageReviewedProfile: LocalSshAccessSummary? = null
    val supportsPackagePreparation: Boolean get() = packages != null

    fun enterForeground() { foreground = true; refreshLocal() }
    fun leaveForeground() {
        foreground = false; generation++; job?.cancel(); actionJob?.cancel(); reviewed = null; reviewedProfile = null
        clearPackage()
        clearRecovery()
        _state.value = _state.value.copy(local = LocalManagementReview.Loading, profile = null, reviewing = false,
            launching = false, reading = false, result = null)
    }

    fun refreshLocal() {
        if (!foreground || _state.value.launching || _state.value.packageBusy || _state.value.recoveryReading) return
        clearPackage()
        clearRecovery()
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
        if (!foreground || s.launching || s.reviewing || s.packageBusy || s.packageReview != null || s.recoveryReading ||
            s.recoveryPlan != null || access !in ready.accessIds) return
        val profile = s.profile ?: return
        reviewed = ready
        reviewedProfile = profile
        _state.value = s.copy(reviewing = true)
    }
    fun dismissReview() { reviewed = null; reviewedProfile = null; _state.value = _state.value.copy(reviewing = false) }

    fun confirmRead(actions: UpdatePreflightActionPort) {
        val review = reviewed ?: return
        val profile = reviewedProfile ?: return
        if (!foreground || !_state.value.reviewing || _state.value.launching) return
        reviewed = null; job?.cancel()
        clearPackage()
        clearRecovery()
        val g = ++generation
        val ticket = ++launchTicket
        _state.value = _state.value.copy(reviewing = false, launching = true, result = null, notice = null)
        saved["update_preflight_launch_pending"] = true
        actionJob = viewModelScope.launch {
            try {
                val before = readLocal()
                if (!current(g)) return@launch
                if (before != review || readProfile() != profile) { if (current(g)) invalidate(); return@launch }
                if (!current(g)) return@launch
                val started = actions.start(server, installation, access)
                // Keep a hidden attempt's pointer, but never replace a newer explicit request with its late return.
                if (ticket != launchTicket) return@launch
                if (started is UpdatePreflightStart.Registered && (started.pointer.accessId != access || started.pointer.operationId.isBlank())) {
                    if (current(g)) invalidate()
                    return@launch
                }
                if (started is UpdatePreflightStart.Registered) {
                    savePointer(started.pointer)
                    _state.value = _state.value.copy(pointer = started.pointer)
                }
                saved["update_preflight_launch_pending"] = false
                if (!current(g)) return@launch
                val after = readLocal()
                if (!current(g)) return@launch
                if (after != review || readProfile() != profile) { if (current(g)) invalidate(); return@launch }
                if (!current(g)) return@launch
                _state.value = _state.value.copy(launching = false)
                when (started) {
                    is UpdatePreflightStart.Blocked -> _state.value = _state.value.copy(notice = started.text)
                    is UpdatePreflightStart.Registered -> poll(started.pointer, review, g)
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (current(g)) _state.value = _state.value.copy(launching = false,
                    notice = "Передача запроса не подтверждена. Автоматического повтора не будет.")
            }
        }
    }

    private suspend fun poll(pointer: UpdatePreflightPointer, review: LocalManagementReview.Ready, g: Long) {
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
            // Independently fence an incorrectly implemented fixture/adapter before projecting any facts.
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
        clearPackage()
        clearRecovery()
        _state.value = _state.value.copy(local = LocalManagementReview.Unavailable("Сохранённые сведения изменились. Обновите их."),
            profile = null, result = null, reviewing = false, reading = false, launching = false)
    }
    private fun savePointer(pointer: UpdatePreflightPointer) {
        saved["update_preflight_server"] = server; saved["update_preflight_installation"] = installation
        saved["update_preflight_access"] = pointer.accessId; saved["update_preflight_operation"] = pointer.operationId
    }

    fun packageEligibility(report: UpdatePreflightSnapshot): UpdatePackageEligibility = UpdatePackagePolicy.review(report, now())

    fun recoveryReview(report: UpdatePreflightSnapshot): UpdateRecoveryPlanReview = UpdateRecoveryReadinessPolicy.review(report, now())

    fun recoveryFilesObservedAt(): Instant = now()

    fun requestRecoveryPlan() {
        val s = _state.value
        val review = s.local as? LocalManagementReview.Ready ?: return
        val profile = s.profile ?: return
        val pointer = s.pointer ?: return
        val report = s.result?.takeIf { it.terminal }?.snapshot ?: return
        if (!foreground || s.launching || s.reading || s.reviewing || s.packageBusy || s.packageReview != null ||
            s.recoveryReading || s.recoveryPlan != null || pointer.accessId != access ||
            report.scope.operationId.value != pointer.operationId || report.scope.serverId.value != server ||
            report.scope.installationId.value != installation || report.scope.serverAccessId.value != access) return
        job?.cancel()
        val g = ++generation
        _state.value = s.copy(recoveryReading = true, recoveryPlan = null, recoveryNotice = null)
        recoveryJob = viewModelScope.launch {
            try {
                val before = readLocal()
                if (!current(g)) return@launch
                val beforeProfile = readProfile()
                if (!current(g)) return@launch
                val latest = statuses.read(server, installation, pointer)
                if (!current(g)) return@launch
                val after = readLocal()
                if (!current(g)) return@launch
                val afterProfile = readProfile()
                if (!current(g)) return@launch
                if (before != review || after != review || beforeProfile != profile || afterProfile != profile ||
                    !latest.terminal || latest.snapshot != report) { invalidate(); return@launch }
                when (val checked = recoveryReview(report)) {
                    is UpdateRecoveryPlanReview.Draft -> _state.value = _state.value.copy(recoveryReading = false, recoveryPlan = checked.plan)
                    is UpdateRecoveryPlanReview.Blocked -> _state.value = _state.value.copy(recoveryReading = false,
                        recoveryNotice = recoveryBlockerText(checked.reasons.first()))
                }
            } catch (cancel: CancellationException) { throw cancel
            } catch (_: Exception) {
                if (current(g)) _state.value = _state.value.copy(recoveryReading = false,
                    recoveryNotice = "Не удалось подтвердить сведения для плана. Обновите локальный статус.")
            }
        }
    }

    fun dismissRecoveryPlan() { _state.value = _state.value.copy(recoveryPlan = null) }

    private fun clearRecovery() {
        recoveryJob?.cancel()
        _state.value = _state.value.copy(recoveryReading = false, recoveryPlan = null, recoveryNotice = null)
    }

    fun requestPackageReview() {
        if (packages == null) return
        val s = _state.value
        val local = s.local as? LocalManagementReview.Ready ?: return
        val profile = s.profile ?: return
        val pointer = s.pointer ?: return
        val report = s.result?.takeIf { it.terminal }?.snapshot ?: return
        if (!foreground || s.launching || s.reading || s.reviewing || s.packageBusy || s.packageReview != null || s.recoveryReading || s.recoveryPlan != null ||
            report.scope.operationId.value != pointer.operationId || report.scope.serverId.value != server ||
            report.scope.installationId.value != installation || report.scope.serverAccessId.value != access || pointer.accessId != access) return
        val eligibility = packageEligibility(report)
        if (eligibility !is UpdatePackageEligibility.Available) {
            _state.value = s.copy(packageNotice = updatePackageBlockerText((eligibility as UpdatePackageEligibility.Blocked).reason))
            return
        }
        // Keep the application-owned port out of SavedStateHandle; no package work on restoration.
        packageReviewedLocal = local; packageReviewedProfile = profile
        _state.value = s.copy(packageReview = UpdatePackageRequest(report, eligibility.release), packageNotice = null)
    }

    fun dismissPackageReview() {
        packageReviewedLocal = null; packageReviewedProfile = null
        _state.value = _state.value.copy(packageReview = null)
    }

    fun confirmPackage() {
        val port = packages ?: return
        val s = _state.value
        val request = s.packageReview ?: return
        val review = packageReviewedLocal ?: return
        val profile = packageReviewedProfile ?: return
        if (!foreground || s.packageBusy || s.launching || s.reviewing || s.recoveryReading || s.recoveryPlan != null) return
        packageReviewedLocal = null; packageReviewedProfile = null
        s.packageReceipt?.let(port::discard)
        job?.cancel()
        val g = ++generation
        _state.value = s.copy(packageReview = null, packageBusy = true, packageReceipt = null, packageNotice = null)
        packageJob = viewModelScope.launch {
            var received: UpdatePackageReceipt? = null
            var keep = false
            try {
                if (!packageContextMatches(request, review, profile, g)) return@launch
                val outcome = port.prepare(request)
                if (outcome is UpdatePackagePreparationResult.Verified) received = outcome.receipt
                if (!current(g)) return@launch
                if (!packageContextMatches(request, review, profile, g)) return@launch
                when (outcome) {
                    is UpdatePackagePreparationResult.Verified -> {
                        if (!UpdatePackagePolicy.receiptMatches(request, outcome.receipt, now())) {
                            _state.value = _state.value.copy(packageBusy = false, packageNotice = "Пакет не относится к текущей проверке установки.")
                            return@launch
                        }
                        _state.value = _state.value.copy(packageBusy = false, packageReceipt = outcome.receipt)
                        keep = true
                    }
                    is UpdatePackagePreparationResult.Failed -> _state.value = _state.value.copy(packageBusy = false,
                        packageNotice = updatePackageFailureText(outcome.reason))
                }
            } catch (cancel: CancellationException) { throw cancel
            } catch (_: Exception) {
                if (current(g)) _state.value = _state.value.copy(packageBusy = false,
                    packageNotice = "Загрузка и проверка пакета не подтверждены. Повторите действие явно.")
            } finally { if (!keep) received?.let(port::discard) }
        }
    }

    fun cancelPackage() {
        if (!_state.value.packageBusy) return
        generation++; packageJob?.cancel()
        _state.value = _state.value.copy(packageBusy = false, packageNotice = "Загрузка отменена.")
    }

    private suspend fun packageContextMatches(request: UpdatePackageRequest, review: LocalManagementReview.Ready,
        profile: LocalSshAccessSummary, g: Long): Boolean {
        val before = readLocal()
        if (!current(g)) return false
        val beforeProfile = readProfile()
        if (!current(g)) return false
        val status = statuses.read(server, installation, UpdatePreflightPointer(request.report.scope.operationId.value, access))
        if (!current(g)) return false
        val after = readLocal()
        if (!current(g)) return false
        val afterProfile = readProfile()
        if (!current(g)) return false
        if (before != review || after != review || beforeProfile != profile || afterProfile != profile ||
            !status.terminal || status.snapshot != request.report) { invalidate(); return false }
        if (!UpdatePackagePolicy.matches(request, now())) {
            _state.value = _state.value.copy(packageBusy = false, packageNotice = "Нужна новая проверка установки перед загрузкой пакета.")
            return false
        }
        return true
    }

    private fun clearPackage() {
        packageJob?.cancel(); packageReviewedLocal = null; packageReviewedProfile = null
        _state.value.packageReceipt?.let { packages?.discard(it) }
        _state.value = _state.value.copy(packageReview = null, packageBusy = false, packageReceipt = null, packageNotice = null)
    }

    override fun onCleared() {
        foreground = false; generation++; job?.cancel(); actionJob?.cancel()
        clearPackage(); clearRecovery(); super.onCleared()
    }
}

class ManagementUpdatePreparationViewModelFactory(owner: SavedStateRegistryOwner, private val server: String,
    private val installation: String, private val access: String, private val local: ManagementLocalReviewPort,
    private val statuses: UpdatePreflightStatusPort, private val readiness: SshReadinessPort,
    private val packages: UpdatePackagePreparationPort? = null) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(key: String, modelClass: Class<T>, handle: SavedStateHandle): T {
        require(modelClass == ManagementUpdatePreparationViewModel::class.java)
        return ManagementUpdatePreparationViewModel(handle, server, installation, access, local, statuses, readiness, packages) as T
    }
}
