package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.enrollment.EnrollmentInputPolicy

/** Local-only exact-target card mutations. This never opens SSH or changes a VPS. */
sealed interface ServerCardActionResult {
    data object Done : ServerCardActionResult
    data class Blocked(val explanation: String) : ServerCardActionResult
}

class LocalServerCardActions(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
    private val installations: XuiInstallationRepository,
) {
    suspend fun rename(exactServerId: String, displayedName: String, requestedName: String): ServerCardActionResult {
        EnrollmentInputPolicy.validateName(requestedName)?.let { return ServerCardActionResult.Blocked(it) }
        val current = freshRecord(exactServerId, displayedName)
        if (current !is FreshRecord.Ready) return ServerCardActionResult.Blocked((current as FreshRecord.Blocked).reason)
        val nextName = requestedName.trim()
        if (current.record.value.displayName == nextName) return ServerCardActionResult.Blocked("Название не изменилось.")
        return when (servers.update(current.record.value.copy(displayName = nextName), current.record.revision)) {
            is RepositoryResult.Success -> ServerCardActionResult.Done
            else -> ServerCardActionResult.Blocked("Не удалось переименовать: запись изменена или недоступна. Обновите список.")
        }
    }

    suspend fun deleteEmpty(exactServerId: String, displayedName: String): ServerCardActionResult {
        val current = freshRecord(exactServerId, displayedName)
        if (current !is FreshRecord.Ready) return ServerCardActionResult.Blocked((current as FreshRecord.Blocked).reason)
        val id = ServerId(exactServerId)
        val ssh = accesses.listForServer(id)
        if (ssh !is RepositoryResult.Success) return ServerCardActionResult.Blocked("Не удалось проверить SSH-доступы. Удаление отменено.")
        if (ssh.value.any { it.serverId != id }) return ServerCardActionResult.Blocked("Обнаружена неправильная связь SSH. Удаление отменено.")
        val xui = installations.listForServer(id)
        if (xui !is RepositoryResult.Success) return ServerCardActionResult.Blocked("Не удалось проверить установки X-UI. Удаление отменено.")
        if (xui.value.any { it.value.serverId != id }) return ServerCardActionResult.Blocked("Обнаружена неправильная связь X-UI. Удаление отменено.")
        if (ssh.value.isNotEmpty() || xui.value.isNotEmpty()) {
            return ServerCardActionResult.Blocked("У сервера есть SSH-доступы или установки X-UI. Сначала нужен отдельный мастер удаления связанных данных.")
        }
        // DB foreign keys RESTRICT + revision CAS are the final transactional fence if a relation appears meanwhile.
        return when (servers.delete(id, current.record.revision)) {
            is RepositoryResult.Success -> ServerCardActionResult.Done
            else -> ServerCardActionResult.Blocked("Сервер изменился или появился связанный профиль. Удаление отменено; обновите список.")
        }
    }

    /** Server with SSH profiles/installations: everything local goes in one transaction; refused while busy. */
    suspend fun deleteWithLocalRecords(
        exactServerId: String,
        displayedName: String,
        purge: suspend (ServerId, com.velumtegra.xuimobile.core.domain.RecordRevision) -> RepositoryResult<List<String>>,
    ): ServerCardActionResult {
        val current = freshRecord(exactServerId, displayedName)
        if (current !is FreshRecord.Ready) return ServerCardActionResult.Blocked((current as FreshRecord.Blocked).reason)
        return when (val result = purge(ServerId(exactServerId), current.record.revision)) {
            is RepositoryResult.Success -> ServerCardActionResult.Done
            is RepositoryResult.ConstraintConflict -> ServerCardActionResult.Blocked(
                "С сервером выполняется незавершённая операция. Дождитесь её окончания и повторите.",
            )
            else -> ServerCardActionResult.Blocked("Сервер изменился или хранилище недоступно. Ничего не удалено; обновите список.")
        }
    }

    private sealed interface FreshRecord {
        data class Ready(val record: com.velumtegra.xuimobile.core.domain.VersionedRecord<com.velumtegra.xuimobile.core.model.Server>) : FreshRecord
        data class Blocked(val reason: String) : FreshRecord
    }

    private suspend fun freshRecord(id: String, displayedName: String): FreshRecord {
        if (id.isBlank() || displayedName.isBlank()) return FreshRecord.Blocked("Нет точной идентификации сервера. Обновите список.")
        val serverId = ServerId(id)
        val result = servers.get(serverId)
        if (result !is RepositoryResult.Success) return FreshRecord.Blocked("Сервер не найден. Обновите список.")
        if (result.value.value.id != serverId || result.value.value.displayName != displayedName) {
            return FreshRecord.Blocked("Карточка сервера устарела. Обновите список перед изменением.")
        }
        return FreshRecord.Ready(result.value)
    }
}
