package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.runtime.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

data class RestoreCheckSourceReview(val operationId: String, val binding: InstallationBackupBinding, val verifiedAt: Instant)
data class RestoreCheckObservation(val operationId: String, val sourceOperationId: String, val text: String, val terminal: Boolean,
    val mayRestore: Boolean = false, val mayCheck: Boolean = false, val mayCancel: Boolean = false,
    val mayInspect: Boolean = false, val sourceProof: RestoreCheckBinding? = null, val receipt: RestoreCheckReceipt? = null, val mayCompare: Boolean = false)
interface RestoreCheckStatusPort {
    suspend fun source(server: String, installation: String, access: String, source: String): RestoreCheckSourceReview?
    suspend fun read(server: String, installation: String, access: String, operation: String): RestoreCheckObservation?
    suspend fun unfinished(server: String, installation: String, access: String, source: String): List<String>
    /** Like [unfinished] but null when the journal could not be read, so a read error is never mistaken for "none". */
    suspend fun unfinishedChecked(server: String, installation: String, access: String, source: String): List<String>? =
        unfinished(server, installation, access, source)
    /** Local journal only: newest exactly bound VERIFIED restore check of this archive, or null. Never starts SSH. */
    suspend fun latestVerified(server: String, installation: String, access: String, source: String): String? = null
}
sealed interface RestoreCheckStart {
    data class Recorded(val operationId: String) : RestoreCheckStart
    data class Blocked(val text: String) : RestoreCheckStart
}
interface RestoreCheckActionPort {
    suspend fun inspectConfirmed(review: ManagementRestartReview, source: String): RestoreCheckStart
    suspend fun inspectCurrentConfirmed(review: ManagementRestartReview, operation: String): String?
    suspend fun restoreConfirmed(review: ManagementRestartReview, operation: String, reviewedSource: RestoreCheckBinding): String?
    suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String?
    suspend fun cancelPending(review: ManagementRestartReview, operation: String): String?
}
internal class RestoreCheckResultRegistry {
    private val values = linkedMapOf<OperationId, RestoreCheckRuntimeResult?>()
    @Synchronized fun begin(id: OperationId) { values[id] = null; while (values.size > 8) values.remove(values.keys.first()) }
    @Synchronized fun publish(id: OperationId, value: RestoreCheckRuntimeResult?) {
        if (id in values && values[id] !is RestoreCheckRuntimeResult.Completed) values[id] = value
    }
    @Synchronized fun latest(id: OperationId): RestoreCheckRuntimeResult? = values[id]
}
internal fun ExactOperationHostTransportSequenceResult.restoreCheckResult(): RestoreCheckRuntimeResult? = when (this) {
    is ExactOperationHostTransportSequenceResult.RestoreCheckPrepared -> restore
    is ExactOperationHostTransportSequenceResult.RestoreCheckEnded -> restore
    else -> null
}

internal class JournalRestoreCheckStatusPort(private val journal: OperationJournal, private val local: ManagementRestartLocalPort,
    private val registry: RestoreCheckResultRegistry, private val now: () -> Instant = Instant::now,
    private val verified: RestoreCheckResultInventory? = null) : RestoreCheckStatusPort {
    override suspend fun source(server: String, installation: String, access: String, source: String): RestoreCheckSourceReview? {
        if (listOf(server, installation, access, source).any { it.isBlank() }) return null
        val review = ready(server, installation, access) ?: return null
        val parent = (journal.get(OperationId(source)) as? OperationJournalResult.Success)?.value ?: return null
        if (parent.snapshot.operationId.value != source || !RestoreCheckBindingPolicy.parentMatches(parent, review.installation, review.access)) return null
        val b = InstallationBackupBinding.parse(parent.snapshot.checkpoint.phaseName)?.second ?: return null
        if (ready(server, installation, access) != review || (journal.get(parent.snapshot.operationId) as? OperationJournalResult.Success)?.value != parent) return null
        return RestoreCheckSourceReview(source, b, parent.snapshot.updatedAt)
    }
    override suspend fun read(server: String, installation: String, access: String, operation: String): RestoreCheckObservation? {
        if (listOf(server, installation, access, operation).any { it.isBlank() }) return null
        val review = ready(server, installation, access) ?: return null
        val current = (journal.get(OperationId(operation)) as? OperationJournalResult.Success)?.value ?: return null
        if (current.snapshot.operationId.value != operation) return null
        val parsed = RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName) ?: return null
        val parent = (journal.get(parsed.second.sourceOperationId) as? OperationJournalResult.Success)?.value ?: return null
        if (!RestoreCheckBindingPolicy.matches(current, review.installation, review.access, parent)) return null
        val s = current.snapshot; val terminal = s.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        if (terminal != (s.checkpoint.semantics == CheckpointSemantics.TERMINAL)) return null
        val pending = !terminal && s.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED && parsed.first == RestoreCheckPhase.REVIEWED
        val inspecting = !terminal && s.checkpoint.semantics == CheckpointSemantics.READ_ONLY && parsed.first == RestoreCheckPhase.SOURCE_PENDING
        val check = !terminal && s.checkpoint.semantics in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED)
        val fresh = pending && !now().isBefore(s.updatedAt) && now().epochSecond - s.updatedAt.epochSecond < 300
        val done = registry.latest(s.operationId) as? RestoreCheckRuntimeResult.Completed
        val receipt = done?.takeIf { terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == RestoreCheckPhase.VERIFIED &&
            it.revision == current.revision && it.installation.value == review.installation && it.access == review.access &&
            it.receipt.binding == parsed.second && it.receipt.scope == ManagementScope(s.operationId, review.installation.serverId, review.access.id, review.installation.id) }?.receipt
        val text = when {
            terminal && s.status == OperationStatus.SUCCEEDED && receipt != null -> "Файлы и база восстановлены в отдельную закрытую папку и проверены по исходной копии. Проверка не заменяет файлы рабочей панели."
            terminal && s.status == OperationStatus.SUCCEEDED -> "Журнал подтверждает завершённую проверку пробного восстановления. Подробный результат не сохранился в памяти."
            terminal && s.status == OperationStatus.CANCELLED -> "Ожидающий запрос отменён до пробного копирования."
            terminal -> "Пробное восстановление не подтверждено. Незавершённая тестовая папка может занимать место на сервере."
            check -> "Пробное копирование завершилось или могло выполниться. Проверьте результат отдельно; повторного копирования не будет."
            fresh -> "Исходная копия проверена. Можно подтвердить одно пробное восстановление в отдельную папку."
            pending -> "Проверка источника устарела. Отмените ожидающий запрос и проверьте исходную копию заново."
            else -> "Запрос проверки источника зарегистрирован. Подтверждённых сведений о копии пока нет."
        }
        if (ready(server, installation, access) != review || (journal.get(s.operationId) as? OperationJournalResult.Success)?.value != current ||
            (journal.get(parent.snapshot.operationId) as? OperationJournalResult.Success)?.value != parent) return null
        return RestoreCheckObservation(operation, parsed.second.sourceOperationId.value, text, terminal, fresh, check, pending || inspecting, inspecting,
            parsed.second.takeIf { it.hasSourceProof }, receipt, terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == RestoreCheckPhase.VERIFIED)
    }
    override suspend fun unfinished(server: String, installation: String, access: String, source: String): List<String> {
        return unfinishedChecked(server, installation, access, source).orEmpty()
    }
    override suspend fun unfinishedChecked(server: String, installation: String, access: String, source: String): List<String>? {
        val review = ready(server, installation, access) ?: return null
        val parent = (journal.get(OperationId(source)) as? OperationJournalResult.Success)?.value ?: return null
        if (parent.snapshot.operationId.value != source || !RestoreCheckBindingPolicy.parentMatches(parent, review.installation, review.access)) return null
        val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: return null
        return all.filter { RestoreCheckBindingPolicy.matches(it, review.installation, review.access, parent) }
            .sortedByDescending { it.snapshot.startedAt }.take(20).map { it.snapshot.operationId.value }
    }
    override suspend fun latestVerified(server: String, installation: String, access: String, source: String): String? {
        val inventory = verified ?: return null
        if (listOf(server, installation, access, source).any { it.isBlank() }) return null
        val review = ready(server, installation, access) ?: return null
        val parent = (journal.get(OperationId(source)) as? OperationJournalResult.Success)?.value ?: return null
        if (parent.snapshot.operationId.value != source || !RestoreCheckBindingPolicy.parentMatches(parent, review.installation, review.access)) return null
        val b = InstallationBackupBinding.parse(parent.snapshot.checkpoint.phaseName)?.second ?: return null
        val prefix = listOf("RCB1_" + RestoreCheckPhase.VERIFIED.name, b.architecture.name, b.version,
            source, parent.revision.value.toString(), b.digest).joinToString(":", postfix = ":")
        val rows = (inventory.recentVerifiedRestoreChecks(ServerId(server), XuiInstallationId(installation), ServerAccessId(access), prefix)
            as? OperationJournalResult.Success)?.value?.takeIf { it.size <= 5 } ?: return null
        val match = rows.firstOrNull { RestoreCheckVerifiedPolicy.accepts(it, review, parent, prefix) } ?: return null
        if (ready(server, installation, access) != review ||
            (journal.get(parent.snapshot.operationId) as? OperationJournalResult.Success)?.value != parent) return null
        return match.snapshot.operationId.value
    }
    private suspend fun ready(server: String, installation: String, access: String) =
        (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review
            ?.takeIf { it.matches(server, installation, access) }
}

internal object RestoreCheckVerifiedPolicy {
    fun accepts(row: VersionedOperationSnapshot, review: ManagementRestartReview, parent: VersionedOperationSnapshot, prefix: String): Boolean {
        val s = row.snapshot
        return s.type == OperationType.INSTALLATION_RESTORE_CHECK && s.status == OperationStatus.SUCCEEDED &&
            s.checkpoint.semantics == CheckpointSemantics.TERMINAL && s.updatedAt == s.checkpoint.recordedAt &&
            s.checkpoint.phaseName.startsWith(prefix) &&
            RestoreCheckBinding.parse(s.checkpoint.phaseName)?.first == RestoreCheckPhase.VERIFIED &&
            RestoreCheckBindingPolicy.matches(row, review.installation, review.access, parent)
    }
}

internal class ProductionRestoreCheckActionPort(private val local: ManagementRestartLocalPort, private val journal: OperationJournal,
    private val runtime: OperationRuntimeCoordinator, private val registry: RestoreCheckResultRegistry,
    private val host: suspend (OperationId) -> ExactOperationHostStartResult, private val now: () -> Instant = Instant::now,
    private val idFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) }) : RestoreCheckActionPort {
    constructor(activity: Activity, local: ManagementRestartLocalPort, journal: OperationJournal,
        runtime: OperationRuntimeCoordinator, registry: RestoreCheckResultRegistry) :
        this(local, journal, runtime, registry, { VisibleExactOperationHostLauncher(activity).start(it) })
    override suspend fun inspectConfirmed(review: ManagementRestartReview, source: String): RestoreCheckStart {
        if (source.isBlank() || !fresh(review)) return blocked("Выбранная цель изменилась.")
        val parent = (journal.get(OperationId(source)) as? OperationJournalResult.Success)?.value ?: return blocked("Исходная копия не найдена в журнале.")
        if (!RestoreCheckBindingPolicy.parentMatches(parent, review.installation, review.access)) return blocked("Копия не соответствует выбранной установке и SSH-профилю.")
        val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: return blocked("Журнал недоступен.")
        if (DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId, all.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
            all.any { RestoreCheckBindingPolicy.matches(it, review.installation, review.access, parent) })
            return blocked("Есть незавершённая проверка. Обновите статус и завершите её отдельно.")
        val id = idFactory(); if (id.value.isBlank() || id == parent.snapshot.operationId) return blocked("Не удалось создать запрос.")
        val b = try { RestoreCheckBindingPolicy.bind(id, review.installation, review.access, parent) } catch (_: IllegalArgumentException) { return blocked("Источник не подходит для этой проверки.") }
        if (!fresh(review) || (journal.get(parent.snapshot.operationId) as? OperationJournalResult.Success)?.value != parent) return blocked("Источник изменился.")
        val at = now()
        val initial = OperationSnapshot(id, OperationType.INSTALLATION_RESTORE_CHECK, parent.snapshot.target, OperationStatus.RUNNING,
            OperationCheckpoint(b.phaseName(RestoreCheckPhase.SOURCE_PENDING), CheckpointSemantics.READ_ONLY, at), at, at)
        val created = (journal.create(initial) as? OperationJournalResult.Success)?.value ?: return blocked("Журнал не принял запрос.")
        registry.begin(id)
        try { if (!fresh(review) || host(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED) failSource(created, b) } catch (cancel: CancellationException) { withContext(NonCancellable) { failSource(created, b) }; throw cancel } catch (_: Exception) { failSource(created, b) }
        return RestoreCheckStart.Recorded(id.value)
    }
    override suspend fun inspectCurrentConfirmed(review: ManagementRestartReview, operation: String): String? {
        val current = exact(review, operation)?.first ?: return "Точная запись недоступна."
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY ||
            RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName)?.first != RestoreCheckPhase.SOURCE_PENDING) return "Проверка источника уже завершилась."
        return launch(current)
    }
    override suspend fun restoreConfirmed(review: ManagementRestartReview, operation: String, reviewedSource: RestoreCheckBinding): String? {
        val records = exact(review, operation) ?: return "Точная запись или источник недоступны."
        val current = records.first
        if (RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName)?.second != reviewedSource) return "Состав выбранной копии изменился. Просмотрите его заново."
        val confirmation = RestoreCheckConfirmationPolicy.confirm(current, review.installation, review.access, records.second, now())
            ?: return "Источнику нужна новая проверка. Пробное копирование не запущено."
        if (!runtime.registerRestoreCheckConfirmation(confirmation)) return "Подтверждение уже использовано или устарело."
        if (!fresh(review)) { runtime.discardRestoreCheckConfirmation(current.snapshot.operationId); return "Цель изменилась." }
        return try { launch(current).also { if (it != null) runtime.discardRestoreCheckConfirmation(current.snapshot.operationId) } } catch (cancel: CancellationException) { runtime.discardRestoreCheckConfirmation(current.snapshot.operationId); throw cancel } catch (_: Exception) { runtime.discardRestoreCheckConfirmation(current.snapshot.operationId); "Передача запроса не подтверждена. Обновите локальный статус." }
    }
    override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? {
        val current = exact(review, operation)?.first ?: return "Точная запись недоступна."
        if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED)) return "Ранее начатое копирование не найдено."
        return launch(current)
    }
    override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? {
        val current = exact(review, operation)?.first ?: return "Точная запись недоступна."
        val parsed = RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName) ?: return "Запись недоступна."
        if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.READ_ONLY, CheckpointSemantics.MUTATION_NOT_STARTED) ||
            parsed.first !in setOf(RestoreCheckPhase.SOURCE_PENDING, RestoreCheckPhase.REVIEWED)) return "Копирование могло начаться. Нужна проверка результата."
        val at = now(); if (at.isBefore(current.snapshot.updatedAt)) return "Время отмены не подтверждено."
        val result = journal.advance(current.snapshot.operationId, current.revision, current.snapshot.copy(status = OperationStatus.CANCELLED,
            checkpoint = OperationCheckpoint(parsed.second.phaseName(RestoreCheckPhase.CANCELLED), CheckpointSemantics.TERMINAL, at), updatedAt = at))
        if (result !is OperationJournalResult.Success) return "Состояние изменилось. Обновите статус."
        runtime.discardRestoreCheckConfirmation(current.snapshot.operationId); return null
    }
    private suspend fun launch(current: VersionedOperationSnapshot): String? {
        registry.begin(current.snapshot.operationId)
        return if (host(current.snapshot.operationId) == ExactOperationHostStartResult.START_REQUEST_ACCEPTED) null else "Android не принял запрос. Обновите локальный статус."
    }
    private suspend fun fresh(r: ManagementRestartReview) = (local.readExact(r.serverId, r.installationId, r.accessId) as? ManagementRestartLocalReview.Ready)?.review == r
    private suspend fun exact(r: ManagementRestartReview, operation: String): Pair<VersionedOperationSnapshot, VersionedOperationSnapshot>? {
        if (operation.isBlank() || !fresh(r)) return null
        val current = (journal.get(OperationId(operation)) as? OperationJournalResult.Success)?.value ?: return null
        val b = RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName)?.second ?: return null
        val parent = (journal.get(b.sourceOperationId) as? OperationJournalResult.Success)?.value ?: return null
        return (current to parent).takeIf { current.snapshot.operationId.value == operation && RestoreCheckBindingPolicy.matches(current, r.installation, r.access, parent) }
    }
    private suspend fun failSource(current: VersionedOperationSnapshot, b: RestoreCheckBinding) {
        val at = now(); if (at.isBefore(current.snapshot.updatedAt)) return
        journal.advance(current.snapshot.operationId, current.revision, current.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = OperationCheckpoint(b.phaseName(RestoreCheckPhase.FAILED), CheckpointSemantics.TERMINAL, at), updatedAt = at))
    }
    private fun blocked(text: String) = RestoreCheckStart.Blocked(text)
}
