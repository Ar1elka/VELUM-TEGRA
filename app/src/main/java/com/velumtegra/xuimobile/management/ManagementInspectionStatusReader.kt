package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.time.Instant
import kotlinx.coroutines.CancellationException

data class UnfinishedManagementInspection(
    val operationId: String,
    val kind: InspectionKind,
    val serverId: String,
    val installationId: String,
    val accessId: String,
    val startedAt: Instant,
)

interface ManagementInspectionStatusPort {
    suspend fun status(
        kind: InspectionKind, operationId: String, serverId: String,
        installationId: String, serverAccessId: String,
    ): InspectionStatus

    /** Local journal inventory. The operator chooses an exact operation; nothing is resumed here. */
    suspend fun unfinishedExact(serverId: String, installationId: String): List<UnfinishedManagementInspection>
}

/** Activity-free projection of the existing journal and process-local result registries. */
internal class ManagementInspectionStatusReader(
    private val quickResults: ManagementResultProjector,
    private val deepResults: DeepDiagnosticResultProjector,
    private val journal: OperationJournal? = null,
) : ManagementInspectionStatusPort {
    override suspend fun unfinishedExact(
        serverId: String, installationId: String,
    ): List<UnfinishedManagementInspection> {
        if (serverId.isBlank() || installationId.isBlank()) return emptyList()
        val records = when (val read = journal?.listNonTerminal()) {
            is OperationJournalResult.Success -> read.value
            null -> return emptyList()
            else -> throw IllegalStateException("Operation journal is unavailable")
        }
        val matching = records.mapNotNull { record ->
            val snapshot = record.snapshot
            val target = snapshot.target as? OperationTarget.InstallationTarget ?: return@mapNotNull null
            if (target.serverId.value != serverId || target.installationId.value != installationId)
                return@mapNotNull null
            val kind = when (snapshot.type) {
                OperationType.QUICK_INSPECT -> InspectionKind.QUICK_INSPECT
                OperationType.DEEP_DIAGNOSTIC -> InspectionKind.DEEP_DIAGNOSTIC
                else -> return@mapNotNull null
            }
            if (snapshot.operationId.value.isBlank() || target.serverAccessId.value.isBlank())
                throw IllegalStateException("Malformed operation scope")
            UnfinishedManagementInspection(
                snapshot.operationId.value, kind, serverId, installationId,
                target.serverAccessId.value, snapshot.startedAt,
            )
        }
        if (matching.map { it.operationId }.distinct().size != matching.size)
            throw IllegalStateException("Ambiguous operation inventory")
        return matching.sortedBy { it.startedAt }
    }

    override suspend fun status(
        kind: InspectionKind, operationId: String, serverId: String,
        installationId: String, serverAccessId: String,
    ): InspectionStatus {
        if (listOf(operationId, serverId, installationId, serverAccessId).any { it.isBlank() })
            return InspectionStatus("Не выбрана точная операция.", true)
        fun matches(operation: String, server: String, installation: String, access: String) =
            operation == operationId && server == serverId && installation == installationId && access == serverAccessId
        fun foreign() = InspectionStatus("Не удалось подтвердить точную проверку, установку или SSH-доступ.", true)
        return try {
            when (kind) {
                InspectionKind.QUICK_INSPECT -> when (val response = quickResults.read(OperationId(operationId))) {
                    is ManagementReadResult.InProgress -> if (matches(
                        response.scope.operationId.value, response.scope.serverId.value, response.scope.installationId.value,
                        response.scope.serverAccessId.value,
                    )) InspectionStatus(operationStatusLabel(response.status), false) else foreign()
                    is ManagementReadResult.Detailed -> if (matches(
                        response.snapshot.scope.operationId.value, response.snapshot.scope.serverId.value, response.snapshot.scope.installationId.value,
                        response.snapshot.scope.serverAccessId.value,
                    )) {
                        val snapshot = response.snapshot
                        InspectionStatus(
                            text = "Состояние службы и установки получено с VPS.",
                            terminal = true, succeeded = true,
                            serviceState = snapshot.serviceState,
                            identity = identityLabel(snapshot.identityStatus),
                            configuration = baselineLabel(snapshot.baselineStatus),
                            observedAt = snapshot.observedAt,
                            detail = InspectionReportDetail(snapshot.identityStatus, snapshot.baselineStatus, snapshot.observedAt),
                        )
                    } else foreign()
                    is ManagementReadResult.DetailedFailure -> if (matches(
                        response.scope.operationId.value, response.scope.serverId.value, response.scope.installationId.value,
                        response.scope.serverAccessId.value,
                    )) InspectionStatus("Проверка не завершена: " + inspectionFailureLabel(response.kind.name), true,
                        completedAt = response.completedAt)
                    else foreign()
                    is ManagementReadResult.DurableTerminal -> if (matches(
                        response.summary.scope.operationId.value, response.summary.scope.serverId.value, response.summary.scope.installationId.value,
                        response.summary.scope.serverAccessId.value,
                    )) InspectionStatus(
                        if (response.summary.kind == ManagementTerminalKind.RESULT)
                            "Проверка завершена; подробности предыдущего процесса недоступны."
                        else "Проверка завершилась ошибкой; подробности предыдущего процесса недоступны.",
                        true, completedAt = response.summary.completedAt,
                    ) else foreign()
                    else -> InspectionStatus("Достоверный результат пока недоступен. Можно перечитать журнал.", false)
                }
                InspectionKind.DEEP_DIAGNOSTIC -> when (val response = deepResults.read(OperationId(operationId))) {
                    is DeepDiagnosticReadResult.InProgress -> if (matches(
                        response.scope.operationId.value, response.scope.serverId.value, response.scope.installationId.value,
                        response.scope.serverAccessId.value,
                    )) InspectionStatus(operationStatusLabel(response.status), false) else foreign()
                    is DeepDiagnosticReadResult.Detailed -> if (matches(
                        response.snapshot.scope.operationId.value, response.snapshot.scope.serverId.value, response.snapshot.scope.installationId.value,
                        response.snapshot.scope.serverAccessId.value,
                    )) {
                        val snapshot = response.snapshot
                        InspectionStatus(
                            text = "Диагностика завершена. Замечаний: " + snapshot.findings.size + ".",
                            terminal = true, succeeded = true,
                            serviceState = snapshot.managementSnapshot.serviceState,
                            identity = identityLabel(snapshot.managementSnapshot.identityStatus),
                            configuration = baselineLabel(snapshot.managementSnapshot.baselineStatus),
                            observedAt = snapshot.managementSnapshot.observedAt,
                            findingsCount = snapshot.findings.size,
                            detail = InspectionReportDetail(snapshot.managementSnapshot.identityStatus,
                                snapshot.managementSnapshot.baselineStatus, snapshot.observedAt,
                                snapshot.overallStatus, snapshot.findings.toList()),
                        )
                    } else foreign()
                    is DeepDiagnosticReadResult.DetailedFailure -> if (matches(
                        response.scope.operationId.value, response.scope.serverId.value, response.scope.installationId.value,
                        response.scope.serverAccessId.value,
                    )) InspectionStatus("Диагностика не завершена: " + inspectionFailureLabel(response.kind.name), true,
                        completedAt = response.completedAt)
                    else foreign()
                    is DeepDiagnosticReadResult.DurableTerminal -> if (matches(
                        response.summary.scope.operationId.value, response.summary.scope.serverId.value, response.summary.scope.installationId.value,
                        response.summary.scope.serverAccessId.value,
                    )) InspectionStatus(if (response.summary.kind == DeepDiagnosticTerminalKind.RESULT)
                        "Диагностика завершена; подробности предыдущего процесса недоступны."
                        else "Диагностика завершилась ошибкой; подробности предыдущего процесса недоступны.", true,
                        completedAt = response.summary.completedAt)
                    else foreign()
                    else -> InspectionStatus("Состояние диагностики пока недоступно. Можно перечитать журнал.", false)
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            InspectionStatus("Не удалось прочитать результат. Выполнение операции не повторялось.", false)
        }
    }
}

internal fun serviceStateLabel(state: ManagementServiceState?): String = when (state) {
    null -> "Ещё не проверена"
    ManagementServiceState.ACTIVE -> "Работает"
    ManagementServiceState.INACTIVE -> "Остановлена"
    ManagementServiceState.FAILED -> "Ошибка службы"
    ManagementServiceState.ACTIVATING -> "Запускается"
    ManagementServiceState.DEACTIVATING -> "Останавливается"
    ManagementServiceState.RELOADING -> "Перезагружает настройки"
    ManagementServiceState.UNKNOWN -> "Не удалось определить"
}

private fun operationStatusLabel(status: OperationStatus): String = when (status) {
    OperationStatus.PENDING -> "Проверка ожидает выполнения."
    OperationStatus.RUNNING -> "Читаем состояние 3x-ui с VPS…"
    OperationStatus.WAITING -> "Ожидаем доступного соединения."
    OperationStatus.RECONCILIATION_REQUIRED -> "Связь прервана. Требуется проверить результат операции."
    OperationStatus.SUCCEEDED -> "Проверка завершена."
    OperationStatus.FAILED -> "Проверка завершилась ошибкой."
    OperationStatus.CANCELLED -> "Проверка отменена."
}

private fun identityLabel(status: ManagementIdentityStatus): String = when (status) {
    ManagementIdentityStatus.Matched -> "Установка подтверждена"
    is ManagementIdentityStatus.Drift -> "Установка изменилась"
    is ManagementIdentityStatus.Insufficient -> "Недостаточно данных"
}

private fun baselineLabel(status: ManagementBaselineStatus): String = when (status) {
    ManagementBaselineStatus.Matched -> "Совпадает с сохранённой"
    is ManagementBaselineStatus.Drift -> "Есть изменения на VPS"
    is ManagementBaselineStatus.Insufficient -> "Недостаточно данных"
}

private fun inspectionFailureLabel(name: String): String = when (name) {
    "EXACT_ACCESS_UNAVAILABLE" -> "SSH-профиль недоступен."
    "SECRET_UNAVAILABLE" -> "Не удалось открыть сохранённые реквизиты."
    "HOST_IDENTITY_MISMATCH" -> "Ключ SSH-сервера изменился."
    "AUTHENTICATION_REJECTED" -> "Сервер отклонил вход по SSH."
    "TRANSPORT_UNAVAILABLE", "TRANSPORT_TIMEOUT" -> "SSH-соединение недоступно."
    "MALFORMED_READBACK" -> "Ответ сервера не удалось подтвердить."
    else -> "Результат не подтверждён."
}
