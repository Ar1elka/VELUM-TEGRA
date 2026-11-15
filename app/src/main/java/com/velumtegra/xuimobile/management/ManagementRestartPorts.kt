package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.DurableServerMutationBarrierPolicy
import com.velumtegra.xuimobile.core.runtime.ServerMutationBarrierDecision
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Non-secret local metadata, never a serialized permission or retained SSH session. */
data class ManagementRestartReview(val serverName: String, val installation: XuiInstallation, val access: ServerAccess) {
    val serverId get() = installation.serverId.value
    val installationId get() = installation.id.value
    val accessId get() = access.id.value
    val sshLabel get() = access.username + "@" + (if (':' in access.endpoint.host) "[" + access.endpoint.host + "]" else access.endpoint.host) + ":" + access.endpoint.port
    fun matches(server: String, installation: String, access: String): Boolean = serverId == server &&
        installationId == installation && accessId == access && this.access.serverId.value == server &&
        this.installation.identity.serviceUnit == "x-ui.service"
}
sealed interface ManagementRestartLocalReview {
    data class Ready(val review: ManagementRestartReview) : ManagementRestartLocalReview
    data class Unavailable(val message: String) : ManagementRestartLocalReview
}
fun interface ManagementRestartLocalPort {
    suspend fun readExact(serverId: String, installationId: String, accessId: String): ManagementRestartLocalReview
}
internal class RepositoryManagementRestartLocalPort(private val servers: ServerRepository,
    private val installations: XuiInstallationRepository, private val accesses: ServerAccessRepository,
    private val management: ManagementAccessRepository) : ManagementRestartLocalPort {
    override suspend fun readExact(serverId: String, installationId: String, accessId: String): ManagementRestartLocalReview = withContext(Dispatchers.IO) {
        fun unavailable() = ManagementRestartLocalReview.Unavailable("Установка или SSH-профиль управления недоступны. Выберите цель заново.")
        if (serverId.isBlank() || installationId.isBlank() || accessId.isBlank()) return@withContext unavailable()
        val s = servers.get(ServerId(serverId)); val i = installations.get(XuiInstallationId(installationId)); val a = accesses.get(ServerAccessId(accessId))
        if (s !is RepositoryResult.Success || i !is RepositoryResult.Success || a !is RepositoryResult.Success) return@withContext unavailable()
        val server = s.value.value; val installation = i.value.value; val access = a.value
        val link = management.get(installation.id, access.id)
        if (server.id.value != serverId || installation.id.value != installationId || installation.serverId != server.id ||
            access.id.value != accessId || access.serverId != server.id || link !is RepositoryResult.Success ||
            link.value.installationId != installation.id || link.value.serverAccessId != access.id ||
            !isSafeLocalPanelPath(installation.baseline.webBasePath)) return@withContext unavailable()
        val identity = installation.identity
        if (identity.serviceUnit != "x-ui.service" || identity.binaryPath != "/usr/local/x-ui/x-ui" ||
            identity.rootPath != "/usr/local/x-ui" || identity.databasePath != "/etc/x-ui/x-ui.db")
            return@withContext ManagementRestartLocalReview.Unavailable("Команды службы доступны для стандартной установки 3x-ui под systemd.")
        ManagementRestartLocalReview.Ready(ManagementRestartReview(server.displayName, installation, access))
    }
}
data class ManagementRestartObservation(val operationId: String, val text: String, val terminal: Boolean,
    val succeeded: Boolean = false, val mayCheckReadOnly: Boolean = false, val mayCancelBeforeDispatch: Boolean = false,
    val observedAt: Instant? = null)
data class UnfinishedManagementRestart(val operationId: String, val startedAt: Instant)
interface ManagementRestartStatusPort {
    suspend fun readExact(operationId: String, serverId: String, installationId: String, accessId: String): ManagementRestartObservation?
    suspend fun unfinishedExact(serverId: String, installationId: String, accessId: String): List<UnfinishedManagementRestart>
}
internal class JournalManagementRestartStatusPort(private val journal: OperationJournal) : ManagementRestartStatusPort {
    override suspend fun readExact(operationId: String, serverId: String, installationId: String, accessId: String): ManagementRestartObservation? {
        if (operationId.isBlank()) return null
        val r = journal.get(OperationId(operationId)); if (r !is OperationJournalResult.Success) return null
        val s = r.value.snapshot
        if (s.operationId.value != operationId || !matches(s, serverId, installationId, accessId)) return null
        val cp = s.checkpoint.semantics
        val phase = s.checkpoint.phaseName.substringBefore('#')
        val action = ExistingInstallationServiceAction.fromPhaseName(phase)
        val preflightPrefix = action.phaseName("RESTART_PREFLIGHT_")
        val succeeded = s.status == OperationStatus.SUCCEEDED && cp == CheckpointSemantics.TERMINAL &&
            phase == action.phaseName("RESTART_SUCCEEDED")
        val terminal = s.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        val unsafe = cp in setOf(CheckpointSemantics.RESTART_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED, CheckpointSemantics.COMMIT_VERIFIED)
        val text = when {
            succeeded -> when (action) {
                ExistingInstallationServiceAction.START -> "3x-ui запущена. Служба и порт панели проверены."
                ExistingInstallationServiceAction.STOP -> "3x-ui остановлена. Состояние службы и закрытие порта проверены."
                ExistingInstallationServiceAction.XRAY_RESTART -> "Xray перезапущен. Новый процесс Xray и работа панели подтверждены."
                ExistingInstallationServiceAction.ENABLE_AUTOSTART -> "Автозапуск 3x-ui включён. Настройка проверена."
                ExistingInstallationServiceAction.DISABLE_AUTOSTART -> "Автозапуск 3x-ui выключен. Настройка проверена."
                ExistingInstallationServiceAction.RESTART -> "Перезапуск завершён. Установка, работа службы и порт панели подтверждены новым подключением."
            }
            s.status == OperationStatus.CANCELLED -> "Запрос отменён до отправки команды."
            phase.startsWith(preflightPrefix) -> preflightMessage(phase.removePrefix(preflightPrefix), action)
            phase == action.phaseName("RESTART_HOST_NOT_STARTED") -> "Android не принял запуск. Команда не отправлена."
            terminal -> "Операция завершена без подтверждённого успешного результата. Проверьте диагностику."
            cp == CheckpointSemantics.COMMIT_VERIFIED -> "Состояние службы подтверждено; завершите локальную запись результата кнопкой проверки."
            unsafe -> if (action == ExistingInstallationServiceAction.RESTART) {
                "Команда могла быть отправлена. Проверьте результат новым подключением; повторный перезапуск не отправляется."
            } else "Команда могла быть отправлена. Проверьте состояние службы."
            else -> "Запрос зарегистрирован. Подтверждённого результата пока нет."
        }
        return ManagementRestartObservation(s.operationId.value, text, terminal, succeeded, unsafe && !terminal,
            !terminal && cp == CheckpointSemantics.MUTATION_NOT_STARTED, s.updatedAt)
    }
    override suspend fun unfinishedExact(serverId: String, installationId: String, accessId: String): List<UnfinishedManagementRestart> {
        val r = journal.listNonTerminal(); if (r !is OperationJournalResult.Success) return emptyList()
        return r.value.filter { matches(it.snapshot, serverId, installationId, accessId) }
            .map { UnfinishedManagementRestart(it.snapshot.operationId.value, it.snapshot.startedAt) }
    }
    private fun matches(s: OperationSnapshot, server: String, installation: String, access: String): Boolean {
        val t = s.target as? OperationTarget.InstallationTarget ?: return false
        return s.type == OperationType.RESTART && t.serverId.value == server && t.installationId.value == installation &&
            t.serverAccessId.value == access && server.isNotBlank() && installation.isNotBlank() && access.isNotBlank()
    }
    private fun preflightMessage(reason: String, action: ExistingInstallationServiceAction): String {
        if (action != ExistingInstallationServiceAction.RESTART) return when (reason) {
            "DIRECT_ROOT_REQUIRED" -> "У SSH-профиля нет прав root. Команда не отправлена."
            "XRAY_RELOAD_UNCONFIRMED" -> "Не удалось подтвердить отдельный перезапуск Xray для этой установки."
            "IDENTITY_MISMATCH", "PANEL_SETTINGS_CHANGED", "LOCAL_METADATA_CHANGED" ->
                "Сохранённая установка изменилась. Обновите её сведения."
            else -> "Не удалось подтвердить установку перед отправкой команды."
        }
        return when (reason) {
            "DIRECT_ROOT_REQUIRED" -> "У SSH-профиля нет прав root. Перезапуск не выполнялся."
            "IDENTITY_MISMATCH" -> "Служба запускает другой файл. Перезапуск заблокирован."
            "PANEL_SETTINGS_CHANGED" -> "Настройки панели изменились на VPS. Перезапуск не отправлен; обновите сведения."
            "MANAGED_MARKER_UNCONFIRMED" -> "Не подтверждена установка, созданная приложением. Перезапуск не отправлен."
            "STANDARD_LAYOUT_REQUIRED" -> "Расположение файлов не поддерживает принятый сценарий перезапуска."
            "LOCAL_METADATA_CHANGED" -> "Сохранённая цель или SSH-профиль изменились. Перезапуск не отправлен."
            "CONFIRMATION_EXPIRED" -> "Время подтверждения истекло. Перезапуск не отправлен."
            else -> "Предварительная проверка не завершена. Перезапуск не отправлен."
        }
    }
}
sealed interface ManagementRestartStart {
    data class Recorded(val operationId: String) : ManagementRestartStart
    data class Blocked(val message: String) : ManagementRestartStart
}
interface ManagementRestartActionPort {
    suspend fun startConfirmed(review: ManagementRestartReview): ManagementRestartStart
    suspend fun runServiceActionConfirmed(
        review: ManagementRestartReview,
        action: ExistingInstallationServiceAction,
    ): ManagementRestartStart = if (action == ExistingInstallationServiceAction.RESTART) startConfirmed(review)
        else ManagementRestartStart.Blocked("Команда службы недоступна.")
    suspend fun checkResultConfirmed(operationId: String, review: ManagementRestartReview): String?
    suspend fun cancelBeforeDispatch(operationId: String, review: ManagementRestartReview): String?
}
internal class ProductionManagementRestartActionPort(private val local: ManagementRestartLocalPort,
    private val journal: OperationJournal, private val runtime: OperationRuntimeCoordinator,
    private val hostStart: suspend (OperationId) -> ExactOperationHostStartResult,
    private val now: () -> Instant = Instant::now,
    private val operationIdFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) }) : ManagementRestartActionPort {
    constructor(activity: Activity, local: ManagementRestartLocalPort, journal: OperationJournal, runtime: OperationRuntimeCoordinator) :
        this(local, journal, runtime, { id -> VisibleExactOperationHostLauncher(activity).start(id) })
    override suspend fun startConfirmed(review: ManagementRestartReview): ManagementRestartStart =
        runServiceActionConfirmed(review, ExistingInstallationServiceAction.RESTART)

    override suspend fun runServiceActionConfirmed(
        review: ManagementRestartReview,
        action: ExistingInstallationServiceAction,
    ): ManagementRestartStart {
        if (!freshMatches(review)) return ManagementRestartStart.Blocked("Цель изменилась. Подтвердите её заново.")
        val unfinished = journal.listNonTerminal()
        if (unfinished !is OperationJournalResult.Success) return ManagementRestartStart.Blocked("Не удалось проверить журнал операций.")
        if (DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId, unfinished.value.map { it.snapshot })
            is ServerMutationBarrierDecision.BlockedByUncertainMutation)
            return ManagementRestartStart.Blocked("У VPS есть неподтверждённое изменение. Сначала проверьте его результат.")
        val blockers = unfinished.value.filter { it.snapshot.type == OperationType.RESTART &&
            (it.snapshot.target as? OperationTarget.InstallationTarget)?.let { t -> t.serverId.value == review.serverId && t.installationId.value == review.installationId } == true }
        if (blockers.isNotEmpty()) return ManagementRestartStart.Blocked("У установки есть незавершённая команда службы. Откройте её через тот же SSH-профиль.")
        val id = operationIdFactory(); val at = now()
        if (id.value.isBlank()) return ManagementRestartStart.Blocked("Не удалось создать идентификатор операции.")
        val s = OperationSnapshot(id, OperationType.RESTART, OperationTarget.InstallationTarget(review.installation.serverId, review.access.id, review.installation.id),
            OperationStatus.RUNNING, OperationCheckpoint(action.phaseName("RESTART_USER_CONFIRMED"), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at)
        val created = journal.create(s)
        if (created !is OperationJournalResult.Success) return ManagementRestartStart.Blocked("Не удалось записать запрос. Перезапуск не отправлен.")
        try {
            val c = ExistingInstallationRestartConfirmationPolicy.confirm(created.value, review.installation, review.access, at)
            if (c !is ExistingInstallationRestartConfirmationResult.Confirmed || !runtime.registerExistingInstallationRestartConfirmation(c.confirmation)) {
                failBeforeDispatch(created.value); return ManagementRestartStart.Recorded(id.value)
            }
            if (!freshMatches(review) || hostStart(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED) {
                runtime.discardExistingInstallationRestartPreflight(id); failBeforeDispatch(created.value)
            }
        } catch (cancel: CancellationException) {
            withContext(NonCancellable) { runtime.discardExistingInstallationRestartPreflight(id); failBeforeDispatch(created.value) }
            throw cancel
        } catch (_: Exception) { runtime.discardExistingInstallationRestartPreflight(id); failBeforeDispatch(created.value) }
        return ManagementRestartStart.Recorded(id.value)
    }
    override suspend fun checkResultConfirmed(operationId: String, review: ManagementRestartReview): String? {
        if (!freshMatches(review)) return "Цель изменилась. Обновите сведения."
        val c = exact(operationId, review) ?: return "Операция не соответствует выбранной цели."
        if (c.snapshot.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED) ||
            c.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.RESTART_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED, CheckpointSemantics.COMMIT_VERIFIED))
            return "Разрешена только проверка уже отправленной команды."
        return if (hostStart(c.snapshot.operationId) == ExactOperationHostStartResult.START_REQUEST_ACCEPTED) null
            else "Android не принял проверку результата. Состояние VPS пока не подтверждено."
    }
    override suspend fun cancelBeforeDispatch(operationId: String, review: ManagementRestartReview): String? {
        val c = exact(operationId, review) ?: return "Операция не соответствует выбранной цели."
        if (c.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED ||
            c.snapshot.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED))
            return "Команда могла быть отправлена. Используйте проверку результата."
        val at = now(); if (at.isBefore(c.snapshot.updatedAt)) return "Не удалось подтвердить время отмены."
        val next = c.snapshot.copy(status = OperationStatus.CANCELLED,
            checkpoint = OperationCheckpoint(servicePhase(c, "RESTART_CANCELLED_BEFORE_DISPATCH"), CheckpointSemantics.TERMINAL, at), updatedAt = at)
        if (journal.advance(c.snapshot.operationId, c.revision, next) !is OperationJournalResult.Success)
            return "Состояние операции изменилось. Обновите результат."
        runtime.discardExistingInstallationRestartPreflight(c.snapshot.operationId)
        return null
    }
    private suspend fun freshMatches(r: ManagementRestartReview) = (local.readExact(r.serverId, r.installationId, r.accessId)
        as? ManagementRestartLocalReview.Ready)?.review == r
    private suspend fun exact(id: String, r: ManagementRestartReview): VersionedOperationSnapshot? {
        if (id.isBlank()) return null
        val read = journal.get(OperationId(id)); if (read !is OperationJournalResult.Success) return null
        return read.value.takeIf { it.snapshot.operationId.value == id && it.snapshot.type == OperationType.RESTART &&
            it.snapshot.target == OperationTarget.InstallationTarget(r.installation.serverId, r.access.id, r.installation.id) }
    }
    private fun servicePhase(current: VersionedOperationSnapshot, restartPhaseName: String): String =
        ExistingInstallationServiceAction.fromPhaseName(current.snapshot.checkpoint.phaseName).phaseName(restartPhaseName)

    private suspend fun failBeforeDispatch(c: VersionedOperationSnapshot) {
        val at = now(); if (at.isBefore(c.snapshot.updatedAt)) return
        journal.advance(c.snapshot.operationId, c.revision, c.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = OperationCheckpoint(servicePhase(c, "RESTART_HOST_NOT_STARTED"), CheckpointSemantics.TERMINAL, at), updatedAt = at))
    }
}
