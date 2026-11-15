package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.UpdatePreflightRuntimeExecutionResult
import com.velumtegra.xuimobile.runtime.*
import java.time.Instant
import java.util.UUID

data class UpdatePreflightPointer(val operationId: String, val accessId: String)
data class UpdatePreflightStatus(
    val text: String,
    val terminal: Boolean = false,
    val snapshot: UpdatePreflightSnapshot? = null,
    val attemptEnded: Boolean = false,
)
sealed interface UpdatePreflightStart {
    data class Registered(val pointer: UpdatePreflightPointer) : UpdatePreflightStart
    data class Blocked(val text: String) : UpdatePreflightStart
}
fun interface UpdatePreflightActionPort {
    suspend fun start(server: String, installation: String, access: String): UpdatePreflightStart
}
fun interface UpdatePreflightStatusPort {
    suspend fun read(server: String, installation: String, pointer: UpdatePreflightPointer): UpdatePreflightStatus
}

/** Bounded handoff of typed facts and non-secret record metadata; the journal is the durable truth. */
internal class UpdatePreflightResultRegistry {
    private val lock = Any()
    private val values = linkedMapOf<OperationId, UpdatePreflightProcessResult?>()
    fun begin(id: OperationId) = synchronized(lock) {
        values[id] = null
        while (values.size > 8) values.remove(values.keys.first())
    }
    fun publish(id: OperationId, result: UpdatePreflightProcessResult) = synchronized(lock) {
        if (id in values && !(result is UpdatePreflightProcessResult.Ended &&
            (values[id] is UpdatePreflightProcessResult.Completed || values[id] is UpdatePreflightProcessResult.Failed))) values[id] = result
    }
    fun latest(id: OperationId): UpdatePreflightProcessResult? = synchronized(lock) { values[id] }
}
internal sealed interface UpdatePreflightProcessResult {
    data class Completed(val snapshot: UpdatePreflightSnapshot, val revision: OperationRevision,
        val installationRecord: VersionedRecord<XuiInstallation>, val access: ServerAccess) : UpdatePreflightProcessResult
    data class Failed(val kind: UpdatePreflightFailure, val revision: OperationRevision) : UpdatePreflightProcessResult
    data class Ended(val notice: UpdatePreflightNotice) : UpdatePreflightProcessResult
}
internal enum class UpdatePreflightNotice { HOST_REJECTED, HOST_ENDED, INTERRUPTED, WAITING_FOR_NETWORK, CONNECTION_FAILED, OWNERSHIP_CHANGED }

internal fun ExactOperationHostTransportSequenceResult.toUpdatePreflightProcessResult(): UpdatePreflightProcessResult = when (this) {
    is ExactOperationHostTransportSequenceResult.UpdatePreflightEnded -> when (val result = preflight) {
        is UpdatePreflightRuntimeExecutionResult.Completed -> UpdatePreflightProcessResult.Completed(result.snapshot, result.committedRevision, result.installationRecord, result.access)
        is UpdatePreflightRuntimeExecutionResult.ReadbackFailed -> UpdatePreflightProcessResult.Failed(result.kind, result.committedRevision)
        else -> UpdatePreflightProcessResult.Ended(UpdatePreflightNotice.OWNERSHIP_CHANGED)
    }
    is ExactOperationHostTransportSequenceResult.Ended -> UpdatePreflightProcessResult.Ended(when (transportResult) {
        ExactOperationHostTransportResult.WaitForNetwork -> UpdatePreflightNotice.WAITING_FOR_NETWORK
        is ExactOperationHostTransportResult.Failed, is ExactOperationHostTransportResult.RecoveryBlocked,
        is ExactOperationHostTransportResult.PreparationFailed -> UpdatePreflightNotice.CONNECTION_FAILED
        else -> UpdatePreflightNotice.HOST_ENDED
    })
    else -> UpdatePreflightProcessResult.Ended(UpdatePreflightNotice.HOST_ENDED)
}

internal class JournalUpdatePreflightStatusPort(
    private val journal: OperationJournal,
    private val registry: UpdatePreflightResultRegistry,
    private val installations: XuiInstallationRepository? = null,
    private val accesses: ServerAccessRepository? = null,
    private val management: ManagementAccessRepository? = null,
) : UpdatePreflightStatusPort {
    override suspend fun read(server: String, installation: String, pointer: UpdatePreflightPointer): UpdatePreflightStatus {
        if (listOf(server, installation, pointer.accessId, pointer.operationId).any { it.isBlank() }) return unavailable()
        val current = (journal.get(OperationId(pointer.operationId)) as? OperationJournalResult.Success)?.value ?: return unavailable()
        val s = current.snapshot
        val t = s.target as? OperationTarget.InstallationTarget ?: return unavailable()
        if (s.operationId.value != pointer.operationId || s.type != OperationType.UPDATE_PREFLIGHT ||
            t.serverId.value != server || t.installationId.value != installation || t.serverAccessId.value != pointer.accessId)
            return unavailable()
        val detail = registry.latest(s.operationId)
        val terminal = s.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        if (terminal || s.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            if (s.checkpoint.semantics != CheckpointSemantics.TERMINAL || !terminal) return unavailable()
            return when {
                s.status == OperationStatus.SUCCEEDED && s.checkpoint.phaseName == "UPDATE_PREFLIGHT_RESULT" -> {
                    val d = detail as? UpdatePreflightProcessResult.Completed
                    val scope = d?.snapshot?.scope
                    if (d != null && scope != null && d.revision == current.revision && scope.operationId == s.operationId &&
                        scope.serverId == t.serverId && scope.installationId == t.installationId && scope.serverAccessId == t.serverAccessId)
                    {
                        val installationNow = (installations?.get(t.installationId) as? RepositoryResult.Success)?.value
                        val accessNow = (accesses?.get(t.serverAccessId) as? RepositoryResult.Success)?.value
                        val relation = (management?.get(t.installationId, t.serverAccessId) as? RepositoryResult.Success)?.value
                        val journalNow = (journal.get(s.operationId) as? OperationJournalResult.Success)?.value
                        if (installationNow == null || accessNow == null || relation == null ||
                            installationNow != d.installationRecord || installationNow.value.id != t.installationId ||
                            installationNow.value.serverId != t.serverId || accessNow != d.access ||
                            accessNow.id != t.serverAccessId || accessNow.serverId != t.serverId ||
                            relation.installationId != t.installationId || relation.serverAccessId != t.serverAccessId || journalNow != current)
                            UpdatePreflightStatus("Сохранённая установка или SSH-доступ изменились. Предыдущая проверка завершена; для текущих сведений нужен новый запрос.", true)
                        else UpdatePreflightStatus("Проверка установки завершена. Обновление не запускалось.", true, d.snapshot)
                    }
                    else UpdatePreflightStatus("Проверка завершена. Детали не сохранены в памяти; для свежего отчёта нужен новый явный запрос.", true)
                }
                s.status == OperationStatus.FAILED && s.checkpoint.phaseName == "UPDATE_PREFLIGHT_FAILED" -> {
                    val d = detail as? UpdatePreflightProcessResult.Failed
                    UpdatePreflightStatus(if (d != null && d.revision == current.revision) updatePreflightFailureText(d.kind)
                        else "Проверка завершилась ошибкой. Подробности этого запроса недоступны.", true)
                }
                s.status == OperationStatus.CANCELLED -> UpdatePreflightStatus("Запрос отменён.", true)
                else -> unavailable()
            }
        }
        if (s.checkpoint.semantics != CheckpointSemantics.READ_ONLY) return unavailable()
        val notice = (detail as? UpdatePreflightProcessResult.Ended)?.notice
        return UpdatePreflightStatus(when (notice) {
            UpdatePreflightNotice.HOST_REJECTED -> "Android не принял запуск. Запрос зарегистрирован, чтение не подтверждено."
            UpdatePreflightNotice.WAITING_FOR_NETWORK -> "Сеть недоступна. Чтение не выполнено; автоматического запуска не будет."
            UpdatePreflightNotice.CONNECTION_FAILED -> "Подключение не выполнено. Проверьте SSH-доступ, ключ хоста и сеть."
            UpdatePreflightNotice.INTERRUPTED -> "Выполнение прервано. Завершение чтения не подтверждено."
            UpdatePreflightNotice.OWNERSHIP_CHANGED -> "Цель или владение запросом изменились. Результат скрыт."
            UpdatePreflightNotice.HOST_ENDED -> "Выполнение завершилось без подтверждённого результата."
            null -> "Запрос зарегистрирован. Подтверждённого результата пока нет."
        }, attemptEnded = notice != null)
    }
    private fun unavailable() = UpdatePreflightStatus("Не удалось подтвердить точную запись журнала. Результат недоступен.", attemptEnded = true)
}

/** Visible action only. Never relaunches an old operation or stores Activity in presentation state. */
internal class ProductionUpdatePreflightActionPort(
    private val local: ManagementLocalReviewPort,
    private val journal: OperationJournal,
    private val registry: UpdatePreflightResultRegistry,
    private val host: (OperationId) -> ExactOperationHostStartResult,
    private val now: () -> Instant = Instant::now,
    private val idFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) },
) : UpdatePreflightActionPort {
    constructor(activity: Activity, local: ManagementLocalReviewPort, journal: OperationJournal,
        registry: UpdatePreflightResultRegistry) : this(local, journal, registry, { VisibleExactOperationHostLauncher(activity).start(it) })

    override suspend fun start(server: String, installation: String, access: String): UpdatePreflightStart {
        val review = local.readExact(server, installation)
        if (!inspectionReviewMatches(review, server, installation, access))
            return UpdatePreflightStart.Blocked("Привязка установки или SSH-доступа изменилась. Обновите сведения.")
        val id = idFactory()
        if (id.value.isBlank()) return UpdatePreflightStart.Blocked("Не удалось зарегистрировать запрос.")
        val at = now()
        val snapshot = OperationSnapshot(id, OperationType.UPDATE_PREFLIGHT,
            OperationTarget.InstallationTarget(ServerId(server), ServerAccessId(access), XuiInstallationId(installation)),
            OperationStatus.RUNNING, OperationCheckpoint("UPDATE_PREFLIGHT", CheckpointSemantics.READ_ONLY, at), at, at)
        if (journal.create(snapshot) !is OperationJournalResult.Success)
            return UpdatePreflightStart.Blocked("Локальный журнал не принял запрос. Подключение не запускалось.")
        registry.begin(id)
        try {
            if (host(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
                registry.publish(id, UpdatePreflightProcessResult.Ended(UpdatePreflightNotice.HOST_REJECTED))
        } catch (_: Exception) {
            registry.publish(id, UpdatePreflightProcessResult.Ended(UpdatePreflightNotice.HOST_REJECTED))
        }
        return UpdatePreflightStart.Registered(UpdatePreflightPointer(id.value, access))
    }
}

internal fun updatePreflightFailureText(kind: UpdatePreflightFailure): String = when (kind) {
    UpdatePreflightFailure.TARGET_NOT_VERIFIED -> "Идентичность установки не подтверждена. Проверка остановлена."
    UpdatePreflightFailure.READBACK_UNAVAILABLE -> "Не удалось получить полный безопасный отчёт. Обновление не запускалось."
    UpdatePreflightFailure.TRANSPORT_UNCERTAIN -> "Связь прервалась. Завершение проверки не подтверждено."
    UpdatePreflightFailure.INTERNAL_CONTRACT -> "Цель или границы проверки не подтверждены. Результат скрыт."
}
