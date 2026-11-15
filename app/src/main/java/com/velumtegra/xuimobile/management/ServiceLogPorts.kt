package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.ServiceLogRuntimeExecutionResult
import com.velumtegra.xuimobile.runtime.*
import java.time.Instant
import java.util.UUID

data class ServiceLogPointer(val operationId: String, val accessId: String)
data class ServiceLogStatus(
    val text: String,
    val terminal: Boolean = false,
    val snapshot: ServiceLogSnapshot? = null,
    val attemptEnded: Boolean = false,
)
sealed interface ServiceLogStart {
    data class Registered(val pointer: ServiceLogPointer) : ServiceLogStart
    data class Blocked(val text: String) : ServiceLogStart
}
fun interface ServiceLogActionPort {
    suspend fun start(server: String, installation: String, access: String): ServiceLogStart
}
fun interface ServiceLogStatusPort {
    suspend fun read(server: String, installation: String, pointer: ServiceLogPointer): ServiceLogStatus
}

/** Bounded ephemeral handoff of already-redacted facts. OperationJournal is the only durable truth. */
internal class ServiceLogResultRegistry {
    private val lock = Any()
    private val values = linkedMapOf<OperationId, ServiceLogProcessResult?>()
    fun begin(id: OperationId) = synchronized(lock) {
        values[id] = null
        while (values.size > 8) values.remove(values.keys.first())
    }
    fun publish(id: OperationId, result: ServiceLogProcessResult) = synchronized(lock) {
        if (id in values && !(result is ServiceLogProcessResult.Ended &&
            (values[id] is ServiceLogProcessResult.Completed || values[id] is ServiceLogProcessResult.Failed))) values[id] = result
    }
    fun latest(id: OperationId): ServiceLogProcessResult? = synchronized(lock) { values[id] }
}
internal sealed interface ServiceLogProcessResult {
    data class Completed(val snapshot: ServiceLogSnapshot, val revision: OperationRevision) : ServiceLogProcessResult
    data class Failed(val kind: ServiceLogFailure, val revision: OperationRevision) : ServiceLogProcessResult
    data class Ended(val notice: ServiceLogNotice) : ServiceLogProcessResult
}
internal enum class ServiceLogNotice { HOST_REJECTED, HOST_ENDED, INTERRUPTED, WAITING_FOR_NETWORK, CONNECTION_FAILED, OWNERSHIP_CHANGED }

internal fun ExactOperationHostTransportSequenceResult.toServiceLogProcessResult(): ServiceLogProcessResult = when (this) {
    is ExactOperationHostTransportSequenceResult.ServiceLogsEnded -> when (val result = logs) {
        is ServiceLogRuntimeExecutionResult.Completed -> ServiceLogProcessResult.Completed(result.snapshot, result.committedRevision)
        is ServiceLogRuntimeExecutionResult.ReadbackFailed -> ServiceLogProcessResult.Failed(result.kind, result.committedRevision)
        else -> ServiceLogProcessResult.Ended(ServiceLogNotice.OWNERSHIP_CHANGED)
    }
    is ExactOperationHostTransportSequenceResult.Ended -> ServiceLogProcessResult.Ended(when (transportResult) {
        ExactOperationHostTransportResult.WaitForNetwork -> ServiceLogNotice.WAITING_FOR_NETWORK
        is ExactOperationHostTransportResult.Failed, is ExactOperationHostTransportResult.RecoveryBlocked,
        is ExactOperationHostTransportResult.PreparationFailed -> ServiceLogNotice.CONNECTION_FAILED
        else -> ServiceLogNotice.HOST_ENDED
    })
    else -> ServiceLogProcessResult.Ended(ServiceLogNotice.HOST_ENDED)
}

internal class JournalServiceLogStatusPort(
    private val journal: OperationJournal,
    private val registry: ServiceLogResultRegistry,
) : ServiceLogStatusPort {
    override suspend fun read(server: String, installation: String, pointer: ServiceLogPointer): ServiceLogStatus {
        if (listOf(server, installation, pointer.accessId, pointer.operationId).any { it.isBlank() }) return unavailable()
        val current = (journal.get(OperationId(pointer.operationId)) as? OperationJournalResult.Success)?.value ?: return unavailable()
        val s = current.snapshot
        val t = s.target as? OperationTarget.InstallationTarget ?: return unavailable()
        if (s.operationId.value != pointer.operationId || s.type != OperationType.SERVICE_LOG_READ ||
            t.serverId.value != server || t.installationId.value != installation || t.serverAccessId.value != pointer.accessId)
            return unavailable()
        val detail = registry.latest(s.operationId)
        val terminal = s.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        if (terminal || s.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            if (s.checkpoint.semantics != CheckpointSemantics.TERMINAL || !terminal) return unavailable()
            return when {
                s.status == OperationStatus.SUCCEEDED && s.checkpoint.phaseName == "SERVICE_LOG_READ_RESULT" -> {
                    val d = detail as? ServiceLogProcessResult.Completed
                    val scope = d?.snapshot?.scope
                    if (d != null && scope != null && d.revision == current.revision && scope.operationId == s.operationId &&
                        scope.serverId == t.serverId && scope.installationId == t.installationId && scope.serverAccessId == t.serverAccessId)
                        ServiceLogStatus("События получены. Это разовый снимок журнала службы.", true, d.snapshot)
                    else ServiceLogStatus("Запрос завершён. Детали не сохранены в памяти; для свежих событий нужен новый явный запрос.", true)
                }
                s.status == OperationStatus.FAILED && s.checkpoint.phaseName == "SERVICE_LOG_READ_FAILED" -> {
                    val d = detail as? ServiceLogProcessResult.Failed
                    ServiceLogStatus(if (d != null && d.revision == current.revision) serviceLogFailureText(d.kind)
                        else "Чтение завершилось ошибкой. Подробности этого запроса недоступны.", true)
                }
                s.status == OperationStatus.CANCELLED -> ServiceLogStatus("Запрос отменён.", true)
                else -> unavailable()
            }
        }
        if (s.checkpoint.semantics != CheckpointSemantics.READ_ONLY) return unavailable()
        val notice = (detail as? ServiceLogProcessResult.Ended)?.notice
        return ServiceLogStatus(when (notice) {
            ServiceLogNotice.HOST_REJECTED -> "Android не принял запуск. Запрос зарегистрирован, чтение не подтверждено."
            ServiceLogNotice.WAITING_FOR_NETWORK -> "Сеть недоступна. Чтение не выполнено; автоматического запуска не будет."
            ServiceLogNotice.CONNECTION_FAILED -> "Подключение не выполнено. Проверьте SSH-доступ, ключ хоста и сеть."
            ServiceLogNotice.INTERRUPTED -> "Выполнение прервано. Завершение чтения не подтверждено."
            ServiceLogNotice.OWNERSHIP_CHANGED -> "Цель или владение запросом изменились. Результат скрыт."
            ServiceLogNotice.HOST_ENDED -> "Выполнение завершилось без подтверждённого результата."
            null -> "Запрос зарегистрирован. Подтверждённого результата пока нет."
        }, attemptEnded = notice != null)
    }
    private fun unavailable() = ServiceLogStatus("Не удалось подтвердить точную запись журнала. Результат недоступен.", attemptEnded = true)
}

/** Visible action only. Never relaunches an old operation or stores Activity in presentation state. */
internal class ProductionServiceLogActionPort(
    private val local: ManagementLocalReviewPort,
    private val journal: OperationJournal,
    private val registry: ServiceLogResultRegistry,
    private val host: (OperationId) -> ExactOperationHostStartResult,
    private val now: () -> Instant = Instant::now,
    private val idFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) },
) : ServiceLogActionPort {
    constructor(activity: Activity, local: ManagementLocalReviewPort, journal: OperationJournal,
        registry: ServiceLogResultRegistry) : this(local, journal, registry, { VisibleExactOperationHostLauncher(activity).start(it) })

    override suspend fun start(server: String, installation: String, access: String): ServiceLogStart {
        val review = local.readExact(server, installation)
        if (!inspectionReviewMatches(review, server, installation, access))
            return ServiceLogStart.Blocked("Привязка установки или SSH-доступа изменилась. Обновите сведения.")
        val id = idFactory()
        if (id.value.isBlank()) return ServiceLogStart.Blocked("Не удалось зарегистрировать запрос.")
        val at = now()
        val snapshot = OperationSnapshot(id, OperationType.SERVICE_LOG_READ,
            OperationTarget.InstallationTarget(ServerId(server), ServerAccessId(access), XuiInstallationId(installation)),
            OperationStatus.RUNNING, OperationCheckpoint("SERVICE_LOG_READ", CheckpointSemantics.READ_ONLY, at), at, at)
        if (journal.create(snapshot) !is OperationJournalResult.Success)
            return ServiceLogStart.Blocked("Локальный журнал не принял запрос. Подключение не запускалось.")
        registry.begin(id)
        try {
            if (host(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
                registry.publish(id, ServiceLogProcessResult.Ended(ServiceLogNotice.HOST_REJECTED))
        } catch (_: Exception) {
            registry.publish(id, ServiceLogProcessResult.Ended(ServiceLogNotice.HOST_REJECTED))
        }
        return ServiceLogStart.Registered(ServiceLogPointer(id.value, access))
    }
}

internal fun serviceLogFailureText(kind: ServiceLogFailure): String = when (kind) {
    ServiceLogFailure.TARGET_NOT_VERIFIED -> "Идентичность установки не подтверждена. Логи не прочитаны."
    ServiceLogFailure.COMMAND_UNAVAILABLE -> "На сервере недоступно чтение системного журнала."
    ServiceLogFailure.COMMAND_FAILED -> "Сервер отклонил чтение журнала службы."
    ServiceLogFailure.TRANSPORT_UNCERTAIN -> "Связь прервалась. Полный результат чтения не подтверждён."
    ServiceLogFailure.OUTPUT_LIMIT -> "Вывод превысил безопасный лимит. Частичный журнал не показан."
    ServiceLogFailure.MALFORMED_OUTPUT -> "Формат журнала не подтверждён. Сырой вывод скрыт."
    ServiceLogFailure.INCOMPLETE_ACCESS -> "Доступ к журналу может быть неполным. Результат скрыт."
    ServiceLogFailure.INTERNAL_CONTRACT -> "Не удалось подтвердить границы чтения. Результат скрыт."
}
