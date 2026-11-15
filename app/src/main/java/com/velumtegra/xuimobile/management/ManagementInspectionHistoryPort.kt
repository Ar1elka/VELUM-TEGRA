package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.InstallationInspectionInventory
import com.velumtegra.xuimobile.core.domain.OperationJournalContractPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationSnapshotValidation
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant
import kotlinx.coroutines.CancellationException

data class InspectionHistoryEntry(
    val operationId: String,
    val serverId: String,
    val installationId: String,
    val accessId: String,
    val kind: InspectionKind,
    val status: OperationStatus,
    val startedAt: Instant,
    val updatedAt: Instant,
) {
    val pointer: ActiveManagementInspection get() = ActiveManagementInspection(kind, operationId, accessId)
}

sealed interface InspectionHistoryRead {
    data class Page(val entries: List<InspectionHistoryEntry>, val hasOlder: Boolean = false) : InspectionHistoryRead
    data object Unavailable : InspectionHistoryRead
}

/** Has no launch/connect/replay methods. */
fun interface ManagementInspectionHistoryPort {
    suspend fun readExact(serverId: String, installationId: String): InspectionHistoryRead
}

internal class JournalManagementInspectionHistoryPort(
    private val inventory: InstallationInspectionInventory,
) : ManagementInspectionHistoryPort {
    override suspend fun readExact(serverId: String, installationId: String): InspectionHistoryRead {
        if (serverId.isBlank() || installationId.isBlank()) return InspectionHistoryRead.Unavailable
        return try {
            val rows = when (val read = inventory.recentInspections(ServerId(serverId), XuiInstallationId(installationId))) {
                is OperationJournalResult.Success -> read.value
                else -> return InspectionHistoryRead.Unavailable
            }
            if (rows.size > 51 || rows.map { it.snapshot.operationId }.distinct().size != rows.size)
                return InspectionHistoryRead.Unavailable
            val entries = rows.map { row ->
                val snapshot = row.snapshot
                val target = snapshot.target as? OperationTarget.InstallationTarget
                    ?: return InspectionHistoryRead.Unavailable
                if (target.serverId.value != serverId || target.installationId.value != installationId ||
                    snapshot.operationId.value.isBlank() || target.serverAccessId.value.isBlank() ||
                    OperationJournalContractPolicy.validateInitial(snapshot) != OperationSnapshotValidation.Valid)
                    return InspectionHistoryRead.Unavailable
                val kind = when (snapshot.type) {
                    OperationType.QUICK_INSPECT -> InspectionKind.QUICK_INSPECT
                    OperationType.DEEP_DIAGNOSTIC -> InspectionKind.DEEP_DIAGNOSTIC
                    else -> return InspectionHistoryRead.Unavailable
                }
                if (snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
                    val expectedStatus = when (kind) {
                        InspectionKind.QUICK_INSPECT -> ManagementTerminalKind.fromPhaseName(snapshot.checkpoint.phaseName)?.operationStatus
                        InspectionKind.DEEP_DIAGNOSTIC -> DeepDiagnosticTerminalKind.fromPhaseName(snapshot.checkpoint.phaseName)?.operationStatus
                    }
                    if (snapshot.status != expectedStatus || snapshot.updatedAt != snapshot.checkpoint.recordedAt)
                        return InspectionHistoryRead.Unavailable
                } else if (snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
                    return InspectionHistoryRead.Unavailable
                }
                InspectionHistoryEntry(snapshot.operationId.value, serverId, installationId,
                    target.serverAccessId.value, kind, snapshot.status, snapshot.startedAt, snapshot.updatedAt)
            }.sortedWith(compareByDescending<InspectionHistoryEntry> { it.startedAt }.thenBy { it.operationId })
            InspectionHistoryRead.Page(entries.take(50), entries.size > 50)
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            InspectionHistoryRead.Unavailable
        }
    }
}

internal fun inspectionKindLabel(kind: InspectionKind): String = when (kind) {
    InspectionKind.QUICK_INSPECT -> "Состояние 3x-ui"
    InspectionKind.DEEP_DIAGNOSTIC -> "Глубокая диагностика"
}

internal fun inspectionHistoryStatusLabel(status: OperationStatus): String = when (status) {
    OperationStatus.PENDING -> "Ожидает выполнения"
    OperationStatus.RUNNING -> "Проверка выполняется"
    OperationStatus.WAITING -> "Ожидает соединения"
    OperationStatus.RECONCILIATION_REQUIRED -> "Требует уточнения результата"
    OperationStatus.SUCCEEDED -> "Проверка завершена"
    OperationStatus.FAILED -> "Проверка завершилась ошибкой"
    OperationStatus.CANCELLED -> "Проверка отменена"
}
