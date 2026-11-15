package com.velumtegra.xuimobile.profiles

import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessPolicy
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Metadata only. Never returns SecretId, secret bytes, a live session or a remote-command capability. */
data class SshProfileReview(
    val serverId: String,
    val metadata: LocalSshAccessSummary,
    val managementLinks: Int,
    val webPanelTunnelLinks: Int,
) {
    val hasLinks: Boolean get() = managementLinks != 0 || webPanelTunnelLinks != 0
}

sealed interface SshProfileReviewResult {
    data class Ready(val review: SshProfileReview) : SshProfileReviewResult
    data class Blocked(val message: String) : SshProfileReviewResult
}

sealed interface SshProfileDeleteResult {
    data object Removed : SshProfileDeleteResult
    data class Blocked(val message: String) : SshProfileDeleteResult
}

interface SshProfileManagementPort {
    suspend fun reviewExact(serverId: String, accessId: String): SshProfileReviewResult
    suspend fun deleteUnused(
        serverId: String, accessId: String, reviewed: SshProfileReview,
        repeatedTarget: String, explicitConsent: Boolean,
    ): SshProfileDeleteResult
}

/** Pure policy; no approval can survive a change of endpoint, pin, credential reference or links. */
object SshProfileDeletionPolicy {
    fun reject(
        serverId: String, accessId: String, reviewed: SshProfileReview,
        fresh: SshProfileReviewResult, repeatedTarget: String, explicitConsent: Boolean,
    ): String? {
        if (!explicitConsent) return "Подтвердите удаление только локального SSH-профиля."
        if (serverId.isBlank() || accessId.isBlank() || reviewed.serverId != serverId ||
            reviewed.metadata.accessId != accessId) return "Неверно выбран SSH-профиль."
        val current = (fresh as? SshProfileReviewResult.Ready)?.review
            ?: return "SSH-профиль недоступен. Обновите сведения."
        if (current != reviewed) return "SSH-профиль или его связи изменились. Повторите проверку."
        if (current.metadata.credentialRefDigest.isBlank()) return "Не подтверждена ссылка на защищённые реквизиты."
        if (repeatedTarget != LiveSshConnectionPolicy.exactTarget(current.metadata)) {
            return "Повторите точную SSH-цель без изменений."
        }
        if (current.hasLinks) return "Есть связи X-UI или WebPanel. Удаление SSH-доступа запрещено."
        return null
    }
}

/** Local-only exact-ID deletion via the existing transactional credential service; FK/operation
 * blockers are rechecked by Room within its write transaction. Physical secret GC is deferred.
 */
class RepositorySshProfileManagementPort(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
    private val management: ManagementAccessRepository,
    private val webPanels: WebPanelAccessRepository,
    private val removeCredentialReference: suspend (ServerAccessId) -> CredentialTransactionResult<Unit>,
) : SshProfileManagementPort {
    override suspend fun reviewExact(serverId: String, accessId: String): SshProfileReviewResult =
        withContext(Dispatchers.IO) {
            try {
                if (serverId.isBlank() || accessId.isBlank()) return@withContext blocked("Выберите точный VPS и SSH-доступ.")
                val owning = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value
                    ?: return@withContext blocked("Выбранный VPS удалён или недоступен.")
                if (owning.id.value != serverId) return@withContext blocked("Получена запись другого VPS.")
                val id = ServerAccessId(accessId)
                val access = (accesses.get(id) as? RepositoryResult.Success)?.value
                    ?: return@withContext blocked("SSH-доступ больше не существует.")
                val summary = (LocalSshReadinessPolicy.inspect(serverId, accessId, access)
                    as? LocalSshReadinessResult.MetadataPresent)?.summary
                    ?: return@withContext blocked("SSH-доступ не принадлежит VPS или имеет некорректные метаданные.")
                val linked = (management.listForServerAccess(id) as? RepositoryResult.Success)?.value
                    ?: return@withContext blocked("Не удалось проверить зависимости X-UI.")
                if (linked.any { it.serverAccessId != id }) return@withContext blocked("Нарушена связь доступа X-UI.")
                val panels = (webPanels.list() as? RepositoryResult.Success)?.value
                    ?: return@withContext blocked("Не удалось проверить зависимости WebPanel.")
                val tunnels = panels.count { record ->
                    (record.value.route as? WebPanelRoute.SshTunnel)?.serverAccessId == id
                }
                SshProfileReviewResult.Ready(SshProfileReview(serverId, summary, linked.size, tunnels))
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                blocked("Локальные зависимости не прочитаны. Удаление недоступно.")
            }
        }

    override suspend fun deleteUnused(
        serverId: String, accessId: String, reviewed: SshProfileReview,
        repeatedTarget: String, explicitConsent: Boolean,
    ): SshProfileDeleteResult = withContext(Dispatchers.IO) {
        try {
            if (!explicitConsent || serverId.isBlank() || accessId.isBlank() ||
                reviewed.serverId != serverId || reviewed.metadata.accessId != accessId ||
                repeatedTarget != LiveSshConnectionPolicy.exactTarget(reviewed.metadata)) {
                return@withContext SshProfileDeleteResult.Blocked("Укажите точный профиль, цель и явное согласие.")
            }
            val fresh = reviewExact(serverId, accessId)
            SshProfileDeletionPolicy.reject(serverId, accessId, reviewed, fresh, repeatedTarget, explicitConsent)
                ?.let { return@withContext SshProfileDeleteResult.Blocked(it) }
            when (removeCredentialReference(ServerAccessId(accessId))) {
                is CredentialTransactionResult.Success -> SshProfileDeleteResult.Removed
                else -> SshProfileDeleteResult.Blocked(
                    "Локальный SSH-доступ не удалён: возможно, осталась операция или связь. Обновите список.",
                )
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            SshProfileDeleteResult.Blocked("Ошибка локального удаления. VPS не затронут.")
        }
    }

    private fun blocked(message: String) = SshProfileReviewResult.Blocked(message)
}
