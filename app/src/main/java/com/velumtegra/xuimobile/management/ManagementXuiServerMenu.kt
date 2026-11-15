package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.runtime.DurableServerMutationBarrierPolicy
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.ServerMutationBarrierDecision
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.XuiServerMenuChannel
import com.velumtegra.xuimobile.core.ssh.XuiServerMenuSession
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class ManagementXuiServerMenu(
    private val local: ManagementRestartLocalPort,
    private val factory: SshConnectionFactory,
    private val journal: OperationJournal,
    private val runtime: OperationRuntimeCoordinator,
) {
    suspend fun review(server: String, installation: String, access: String): ManagementRestartReview? {
        val ready = local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready
        return ready?.review?.takeIf { it.matches(server, installation, access) }
    }

    suspend fun open(
        selected: ManagementRestartReview,
        useMenu: suspend (XuiServerMenuChannel) -> Unit,
    ): String = withContext(Dispatchers.IO) {
        val serverId = selected.installation.serverId
        try {
            runtime.withExclusiveServerMaintenanceLease(serverId, OperationId(UUID.randomUUID().toString())) {
                val unfinished = journal.listNonTerminal() as? OperationJournalResult.Success
                    ?: return@withExclusiveServerMaintenanceLease "Не удалось проверить журнал операций."
                val barrier = DurableServerMutationBarrierPolicy.evaluate(serverId, unfinished.value.map { it.snapshot })
                if (barrier != ServerMutationBarrierDecision.Allowed) {
                    return@withExclusiveServerMaintenanceLease "У VPS есть незавершённое изменение. Сначала проверьте его результат."
                }
                if (!isCurrent(selected)) return@withExclusiveServerMaintenanceLease "SSH-профиль изменился. Откройте меню заново."

                val owner = SessionOwner.Management(selected.installation.id, selected.access.id)
                val result = factory.connect(selected.access, owner) as? SshConnectResult.Connected
                    ?: return@withExclusiveServerMaintenanceLease "Не удалось подключиться по выбранному SSH-профилю."
                result.handle.use { session ->
                    if (session.binding.owner != owner || session.binding.serverAccessId != selected.access.id ||
                        !isCurrent(selected)
                    ) return@withExclusiveServerMaintenanceLease "SSH-профиль изменился. Откройте меню заново."

                    val menu = (session as? XuiServerMenuSession)?.openXuiServerMenu()
                        ?: return@withExclusiveServerMaintenanceLease "Не удалось запустить меню x-ui."
                    menu.use { useMenu(it) }
                    "Сеанс x-ui завершён."
                }
            } ?: "На VPS уже выполняется другая операция."
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            "Связь с меню x-ui прервана. Проверьте ответ сервера перед повтором команды."
        }
    }

    private suspend fun isCurrent(selected: ManagementRestartReview): Boolean =
        review(selected.serverId, selected.installationId, selected.accessId) == selected
}
