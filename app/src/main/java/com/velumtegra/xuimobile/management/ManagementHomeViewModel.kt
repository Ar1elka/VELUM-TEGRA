package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.discovery.XuiVersionVerificationResult
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class ManagementHomeAction { QUICK_INSPECT, DEEP_DIAGNOSTIC, READ_VERSION }

data class ActiveManagementInspection(
    val kind: InspectionKind,
    val operationId: String,
    val accessId: String,
)

data class ManagementActionReview(
    val action: ManagementHomeAction,
    val installation: LocalManagementReview.Ready,
    val access: LocalSshAccessSummary,
)

data class ManagementHomeState(
    val local: LocalManagementReview = LocalManagementReview.Loading,
    val accesses: List<LocalSshAccessSummary> = emptyList(),
    val selectedAccessId: String? = null,
    val pending: ManagementActionReview? = null,
    val launching: Boolean = false,
    val active: ActiveManagementInspection? = null,
    val result: InspectionStatus? = null,
    val unfinished: List<UnfinishedManagementInspection> = emptyList(),
    val notice: String? = null,
    val version: String? = null,
    val versionObservedAt: Instant? = null,
    val versionLoading: Boolean = false,
    val versionError: String? = null,
) {
    val selectedAccess: LocalSshAccessSummary?
        get() = accesses.singleOrNull { it.accessId == selectedAccessId }
    val canRequest: Boolean
        get() = local is LocalManagementReview.Ready && selectedAccess != null &&
            !launching && !versionLoading && (active == null || result?.terminal == true) &&
            unfinished.isEmpty()
}

/**
 * Presentation owns no SSH session. Saved state stores only an exact journal pointer.
 * Foreground refresh and status observation read local state; network starts only in confirmAction.
 */
class ManagementHomeViewModel(
    private val saved: SavedStateHandle,
    private val serverId: String,
    private val installationId: String,
    private val localPort: ManagementLocalReviewPort,
    private val readinessPort: SshReadinessPort,
    private val statusPort: ManagementInspectionStatusPort,
    private val versionPort: ManagementVersionReadPort,
) : ViewModel() {
    private val restored = restoreInspectionPointer(saved, serverId, installationId)
    private val _state = MutableStateFlow(ManagementHomeState(
        active = restored,
        notice = if (saved.get<Boolean>("launch_pending") == true)
            "Передача запроса была прервана. Проверьте незавершённые операции перед новым запуском." else null,
    ))
    val state = _state.asStateFlow()
    private var foreground = false
    private var localGeneration = 0L
    private var launchGeneration = 0L
    private var versionGeneration = 0L
    private var localJob: Job? = null
    private var pollJob: Job? = null
    private var launchJob: Job? = null
    private var versionJob: Job? = null

    fun enterForeground() {
        foreground = true
        refreshLocal()
    }

    fun leaveForeground() {
        foreground = false
        localGeneration++
        launchGeneration++
        versionGeneration++
        localJob?.cancel()
        pollJob?.cancel()
        versionJob?.cancel()
        launchJob?.cancel()
        _state.value = _state.value.copy(
            local = LocalManagementReview.Loading, accesses = emptyList(),
            selectedAccessId = null, pending = null, launching = false, versionLoading = false,
        )
    }

    /** Local refresh cannot launch, resume or repeat a remote operation. */
    fun refreshLocal() {
        if (!foreground || _state.value.launching || _state.value.versionLoading) return
        localJob?.cancel()
        val generation = ++localGeneration
        val previous = _state.value
        _state.value = previous.copy(
            local = LocalManagementReview.Loading, accesses = emptyList(),
            selectedAccessId = null, pending = null,
        )
        localJob = viewModelScope.launch {
            try {
                val review = localPort.readExact(serverId, installationId)
                    .requireExactInstallation(serverId, installationId)
                if (!isCurrent(generation)) return@launch
                val ready = review as? LocalManagementReview.Ready
                if (ready == null) {
                    _state.value = _state.value.copy(local = review, unfinished = emptyList())
                    return@launch
                }
                val choices = ready.accessIds.map { id ->
                    val read = readinessPort.previewExact(serverId, id)
                    val summary = (read as? LocalSshReadinessResult.MetadataPresent)?.summary
                    if (summary == null || summary.accessId != id)
                        throw IllegalStateException("Exact SSH metadata is unavailable")
                    summary
                }
                val unfinished = statusPort.unfinishedExact(serverId, installationId)
                if (unfinished.any { it.serverId != serverId || it.installationId != installationId ||
                        it.accessId !in ready.accessIds || it.operationId.isBlank() })
                    throw IllegalStateException("Foreign operation inventory")
                if (!isCurrent(generation)) return@launch
                // A single local profile is unambiguous. Network actions still require their own consent.
                val selected = previous.selectedAccess?.takeIf { it in choices }?.accessId
                    ?: choices.singleOrNull()?.accessId
                _state.value = _state.value.copy(
                    local = ready, accesses = choices, selectedAccessId = selected,
                    unfinished = unfinished.filter { it.operationId != _state.value.active?.operationId },
                )
                startObservation()
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (isCurrent(generation)) _state.value = _state.value.copy(
                    local = LocalManagementReview.Unavailable(
                        "Не удалось подтвердить установку, SSH-профили или журнал. Обновите сохранённые сведения.",
                    ), accesses = emptyList(), selectedAccessId = null,
                )
            }
        }
    }

    fun selectAccess(accessId: String) {
        val current = _state.value
        if (!foreground || current.launching || current.versionLoading || current.pending != null) return
        if (current.accesses.count { it.accessId == accessId } != 1) return
        _state.value = current.copy(selectedAccessId = accessId, versionError = null)
    }

    fun requestAction(action: ManagementHomeAction) {
        val current = _state.value
        if (!foreground || !current.canRequest) return
        val ready = current.local as? LocalManagementReview.Ready ?: return
        val access = current.selectedAccess ?: return
        _state.value = current.copy(pending = ManagementActionReview(action, ready, access))
    }

    fun dismissReview() {
        if (!_state.value.launching && !_state.value.versionLoading)
            _state.value = _state.value.copy(pending = null)
    }

    /** The Activity-owned launcher is passed for this attempt only, never retained by the ViewModel. */
    fun confirmAction(launcher: VisibleManagementInspectionsPort) {
        val request = _state.value.pending ?: return
        if (!foreground || !_state.value.canRequest) return
        _state.value = _state.value.copy(
            pending = null, launching = true, notice = null, versionError = null,
        )
        val attempt = ++launchGeneration
        saved["launch_pending"] = true
        launchJob = viewModelScope.launch {
            try {
                val fresh = localPort.readExact(serverId, installationId)
                    .requireExactInstallation(serverId, installationId)
                val access = readinessPort.previewExact(serverId, request.access.accessId)
                if (!foreground || attempt != launchGeneration) return@launch
                if (fresh != request.installation ||
                    (access as? LocalSshReadinessResult.MetadataPresent)?.summary != request.access ||
                    !inspectionReviewMatches(fresh, serverId, installationId, request.access.accessId)) {
                    saved["launch_pending"] = false
                    _state.value = _state.value.copy(
                        notice = "Сохранённые сведения изменились. Обновите их и снова выберите SSH-профиль.",
                    )
                    return@launch
                }
                if (request.action == ManagementHomeAction.READ_VERSION) {
                    saved["launch_pending"] = false
                    _state.value = _state.value.copy(launching = false)
                    readVersion(request.access)
                    return@launch
                }
                val kind = when (request.action) {
                    ManagementHomeAction.QUICK_INSPECT -> InspectionKind.QUICK_INSPECT
                    ManagementHomeAction.DEEP_DIAGNOSTIC -> InspectionKind.DEEP_DIAGNOSTIC
                    ManagementHomeAction.READ_VERSION -> return@launch
                }
                val launched = launcher.start(kind, serverId, installationId, request.access.accessId)
                if (!foreground || attempt != launchGeneration) return@launch
                when (launched) {
                    is InspectionStart.Accepted -> {
                        if (launched.operationId.isBlank()) {
                            _state.value = _state.value.copy(notice = "Запуск не подтверждён. Перечитайте журнал.")
                            return@launch
                        }
                        val pointer = ActiveManagementInspection(kind, launched.operationId, request.access.accessId)
                        saveInspectionPointer(saved, serverId, installationId, pointer)
                        _state.value = _state.value.copy(
                            active = pointer, result = InspectionStatus(
                                "Запрос принят. Ожидаем результата проверки…", false,
                            ),
                        )
                        startObservation()
                    }
                    is InspectionStart.Blocked -> _state.value = _state.value.copy(notice = launched.message)
                }
                saved["launch_pending"] = false
            } catch (cancel: CancellationException) {
                // The journal may already contain an operation. Never repeat it from cancellation.
                if (attempt == launchGeneration) _state.value = _state.value.copy(
                    notice = "Передача запроса прервана. Перечитайте журнал незавершённых операций.",
                )
                throw cancel
            } catch (_: Exception) {
                if (attempt == launchGeneration) _state.value = _state.value.copy(
                    notice = "Нет подтверждения запуска. Перечитайте журнал перед новым действием.",
                )
            } finally {
                if (attempt == launchGeneration) _state.value = _state.value.copy(launching = false)
            }
        }
    }

    private fun readVersion(access: LocalSshAccessSummary) {
        if (!foreground) return
        val generation = ++versionGeneration
        _state.value = _state.value.copy(versionLoading = true, versionError = null)
        versionJob = viewModelScope.launch {
            try {
                when (val result = versionPort.readExact(serverId, installationId, access)) {
                    is XuiVersionVerificationResult.Observed -> if (foreground && generation == versionGeneration) _state.value =
                        _state.value.copy(version = result.version, versionObservedAt = Instant.now())
                    is XuiVersionVerificationResult.Blocked -> if (foreground && generation == versionGeneration) _state.value =
                        _state.value.copy(versionError = result.message)
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (foreground && generation == versionGeneration) _state.value = _state.value.copy(
                    versionError = "Не удалось подтвердить версию. Предыдущее значение не обновлено.",
                )
            } finally {
                if (generation == versionGeneration) _state.value = _state.value.copy(versionLoading = false)
            }
        }
    }

    fun observeExisting(operationId: String) {
        val current = _state.value
        if (!foreground || current.launching || current.versionLoading) return
        val chosen = current.unfinished.singleOrNull { it.operationId == operationId } ?: return
        if (chosen.serverId != serverId || chosen.installationId != installationId) return
        val pointer = ActiveManagementInspection(chosen.kind, chosen.operationId, chosen.accessId)
        saveInspectionPointer(saved, serverId, installationId, pointer)
        saved["launch_pending"] = false
        _state.value = current.copy(
            active = pointer, result = null, pending = null,
            unfinished = current.unfinished.filter { it.operationId != operationId },
        )
        startObservation()
    }

    fun refreshResult() {
        if (foreground) startObservation()
    }

    fun clearResult() {
        if (_state.value.result?.terminal != true) return
        pollJob?.cancel()
        saveInspectionPointer(saved, serverId, installationId, null)
        _state.value = _state.value.copy(active = null, result = null)
    }

    private fun startObservation() {
        pollJob?.cancel()
        val pointer = _state.value.active ?: return
        if (!foreground || _state.value.local !is LocalManagementReview.Ready) return
        pollJob = viewModelScope.launch {
            repeat(120) {
                val result = statusPort.status(
                    pointer.kind, pointer.operationId, serverId, installationId, pointer.accessId,
                )
                if (!foreground || _state.value.active != pointer) return@launch
                _state.value = _state.value.copy(result = result)
                if (result.terminal) return@launch
                delay(1_000)
            }
            if (foreground && _state.value.active == pointer) _state.value = _state.value.copy(
                result = InspectionStatus(
                    "Конечный результат ещё не получен. Можно обновить состояние этой же операции.",
                    false,
                ),
            )
        }
    }

    private fun isCurrent(generation: Long) = foreground && localGeneration == generation
}

internal fun restoreInspectionPointer(
    saved: SavedStateHandle, serverId: String, installationId: String,
): ActiveManagementInspection? {
    if (serverId.isBlank() || installationId.isBlank() ||
        saved.get<String>("operation_server") != serverId ||
        saved.get<String>("operation_installation") != installationId) return null
    val operation = saved.get<String>("operation_id")?.takeIf { it.isNotBlank() } ?: return null
    val access = saved.get<String>("operation_access")?.takeIf { it.isNotBlank() } ?: return null
    val kind = saved.get<String>("operation_kind")?.let { value ->
        InspectionKind.entries.singleOrNull { it.name == value }
    } ?: return null
    return ActiveManagementInspection(kind, operation, access)
}

private fun saveInspectionPointer(
    saved: SavedStateHandle, serverId: String, installationId: String,
    pointer: ActiveManagementInspection?,
) {
    saved["operation_server"] = serverId
    saved["operation_installation"] = installationId
    saved["operation_id"] = pointer?.operationId
    saved["operation_access"] = pointer?.accessId
    saved["operation_kind"] = pointer?.kind?.name
}

@Suppress("DEPRECATION")
internal class ManagementHomeViewModelFactory(
    owner: SavedStateRegistryOwner,
    private val serverId: String,
    private val installationId: String,
    private val localPort: ManagementLocalReviewPort,
    private val readinessPort: SshReadinessPort,
    private val statusPort: ManagementInspectionStatusPort,
    private val versionPort: ManagementVersionReadPort,
) : AbstractSavedStateViewModelFactory(owner, null) {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(
        key: String, modelClass: Class<T>, handle: SavedStateHandle,
    ): T {
        require(modelClass == ManagementHomeViewModel::class.java)
        return ManagementHomeViewModel(
            handle, serverId, installationId, localPort, readinessPort, statusPort, versionPort,
        ) as T
    }
}
