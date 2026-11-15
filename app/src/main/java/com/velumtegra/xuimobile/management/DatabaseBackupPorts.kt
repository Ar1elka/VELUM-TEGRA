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

data class DatabaseBackupObservation(val operationId: String, val text: String, val terminal: Boolean,
    val mayCheck: Boolean = false, val mayCancel: Boolean = false, val receipt: DatabaseBackupReceipt? = null)
interface DatabaseBackupStatusPort {
    suspend fun read(server: String, installation: String, access: String, operation: String): DatabaseBackupObservation?
    suspend fun unfinished(server: String, installation: String, access: String): List<String>
    /** Local in-memory observation only; never starts SSH. */
    fun slots(review: ManagementRestartReview): com.velumtegra.xuimobile.core.model.BackupSlotInventory? = null
}
sealed interface DatabaseBackupStart {
    data class Recorded(val operationId: String) : DatabaseBackupStart
    data class Blocked(val text: String) : DatabaseBackupStart
}
interface DatabaseBackupActionPort {
    suspend fun createConfirmed(review: ManagementRestartReview, source: UpdatePreflightPointer): DatabaseBackupStart
    suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String?
    suspend fun cancelPending(review: ManagementRestartReview, operation: String): String?
}

internal class DatabaseBackupResultRegistry {
    private val values = linkedMapOf<OperationId, DatabaseBackupRuntimeResult?>()
    @Synchronized fun begin(id: OperationId) { values[id] = null; while (values.size > 8) values.remove(values.keys.first()) }
    @Synchronized fun publish(id: OperationId, result: DatabaseBackupRuntimeResult?) {
        if (id in values && values[id] !is DatabaseBackupRuntimeResult.Completed) values[id] = result
    }
    @Synchronized fun latest(id: OperationId): DatabaseBackupRuntimeResult? = values[id]
}
internal fun ExactOperationHostTransportSequenceResult.databaseBackupResult(): DatabaseBackupRuntimeResult? = when (this) {
    is ExactOperationHostTransportSequenceResult.DatabaseBackupEnded -> backup
    is ExactOperationHostTransportSequenceResult.DatabaseBackupPrepared -> backup
    else -> null
}

internal class JournalDatabaseBackupStatusPort(private val journal: OperationJournal,
    private val local: ManagementRestartLocalPort, private val registry: DatabaseBackupResultRegistry,
    private val slotSource: (ServerId, ServerAccess) -> BackupSlotInventory? = { _, _ -> null }) : DatabaseBackupStatusPort {
    override fun slots(review: ManagementRestartReview): BackupSlotInventory? =
        if (review.serverId.isBlank() || review.access.serverId.value != review.serverId) null else slotSource(ServerId(review.serverId), review.access)
    override suspend fun read(server: String, installation: String, access: String, operation: String): DatabaseBackupObservation? {
        if (listOf(server, installation, access, operation).any { it.isBlank() }) return null
        val current = (journal.get(OperationId(operation)) as? OperationJournalResult.Success)?.value ?: return null
        val review = (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review ?: return null
        val s = current.snapshot
        if (s.operationId.value != operation || !DatabaseBackupBindingPolicy.matches(current, review.installation, review.access)) return null
        val parsed = DatabaseBackupBinding.parse(s.checkpoint.phaseName) ?: return null
        val terminal = s.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        if (terminal != (s.checkpoint.semantics == CheckpointSemantics.TERMINAL)) return null
        val d = registry.latest(s.operationId) as? DatabaseBackupRuntimeResult.Completed
        val candidate = d?.takeIf { it.revision == current.revision && it.installation.value == review.installation &&
            it.access == review.access && it.receipt.scope.operationId == s.operationId && it.receipt.binding == parsed.second &&
            it.receipt.scope.serverId.value == server && it.receipt.scope.installationId.value == installation &&
            it.receipt.scope.serverAccessId.value == access }?.receipt
        val receipt = candidate?.takeIf {
            (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review == review &&
                (journal.get(s.operationId) as? OperationJournalResult.Success)?.value == current
        }
        val pending = !terminal && parsed.first == DatabaseBackupPhase.PENDING && s.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED
        val check = !terminal && s.checkpoint.semantics in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED)
        val text = when {
            terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == DatabaseBackupPhase.VERIFIED && receipt != null ->
                "Копия базы создана и проверена: SHA-256 и целостность SQLite подтверждены. Хранится на выбранном сервере."
            terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == DatabaseBackupPhase.VERIFIED ->
                "Журнал подтверждает завершённую проверку копии базы. Размер и SHA-256 этого результата не сохранились в памяти."
            terminal && s.status == OperationStatus.CANCELLED -> "Ожидающий запрос отменён до отправки копирования."
            terminal -> "Копия базы не подтверждена. Запрос завершён; приватные незавершённые файлы могут занимать место на сервере."
            check -> "Создание могло выполниться. Разрешена отдельная проверка существующей копии; повторное создание не отправляется."
            pending -> "Запрос зарегистрирован. Начало копирования в журнале ещё не отмечено; подтверждённого результата нет. Ожидающий запрос можно отменить."
            else -> "Точное состояние запроса не подтверждено."
        }
        return DatabaseBackupObservation(operation, text, terminal, check, pending, receipt)
    }
    override suspend fun unfinished(server: String, installation: String, access: String): List<String> {
        val review = (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review ?: return emptyList()
        val list = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: return emptyList()
        return list.filter { DatabaseBackupBindingPolicy.matches(it, review.installation, review.access) }
            .sortedByDescending { it.snapshot.startedAt }.take(20).map { it.snapshot.operationId.value }
    }
}

internal class ProductionDatabaseBackupActionPort(private val local: ManagementRestartLocalPort,
    private val sourceStatus: UpdatePreflightStatusPort, private val journal: OperationJournal,
    private val runtime: OperationRuntimeCoordinator, private val registry: DatabaseBackupResultRegistry,
    private val host: suspend (OperationId) -> ExactOperationHostStartResult,
    private val now: () -> Instant = Instant::now,
    private val idFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) }) : DatabaseBackupActionPort {
    constructor(activity: Activity, local: ManagementRestartLocalPort, sourceStatus: UpdatePreflightStatusPort,
        journal: OperationJournal, runtime: OperationRuntimeCoordinator, registry: DatabaseBackupResultRegistry) :
        this(local, sourceStatus, journal, runtime, registry, { VisibleExactOperationHostLauncher(activity).start(it) })
    override suspend fun createConfirmed(review: ManagementRestartReview, source: UpdatePreflightPointer): DatabaseBackupStart {
        if (source.accessId != review.accessId || !fresh(review)) return blocked("Цель изменилась. Обновите сведения.")
        val report = sourceStatus.read(review.serverId, review.installationId, source).snapshot
            ?: return blocked("Источник копии не подтверждён. Выполните новую проверку установки.")
        if (UpdateRecoveryReadinessPolicy.review(report, now()) !is UpdateRecoveryPlanReview.Draft)
            return blocked("Отчёт устарел или содержит замечания. Нужна новая проверка установки.")
        val nonTerminal = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
            ?: return blocked("Журнал недоступен.")
        if (DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId, nonTerminal.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
            nonTerminal.any { it.snapshot.type == OperationType.DATABASE_BACKUP &&
                (it.snapshot.target as? OperationTarget.InstallationTarget)?.installationId == review.installation.id })
            return blocked("Есть незавершённая операция. Сначала проверьте её результат или отмените ожидающий запрос.")
        val id = idFactory(); if (id.value.isBlank()) return blocked("Не удалось создать запрос.")
        val b = DatabaseBackupBindingPolicy.bind(id, review.installation, review.access,
            report.currentVersion ?: return blocked("Версия не подтверждена."),
            report.architecture ?: return blocked("Архитектура не подтверждена."))
        if (!fresh(review)) return blocked("Сохранённая цель изменилась.")
        val at = now()
        val initial = OperationSnapshot(id, OperationType.DATABASE_BACKUP,
            OperationTarget.InstallationTarget(review.installation.serverId, review.access.id, review.installation.id),
            OperationStatus.RUNNING, OperationCheckpoint(b.phaseName(DatabaseBackupPhase.PENDING), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at)
        val created = (journal.create(initial) as? OperationJournalResult.Success)?.value ?: return blocked("Журнал не принял запрос.")
        registry.begin(id)
        try {
            val c = DatabaseBackupConfirmationPolicy.confirm(created, review.installation, review.access, report, now())
            if (c == null || !runtime.registerDatabaseBackupConfirmation(c) || !fresh(review) ||
                host(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED) failPending(created, b)
        } catch (cancel: CancellationException) {
            withContext(NonCancellable) { failPending(created, b) }; throw cancel
        } catch (_: Exception) { failPending(created, b) }
        return DatabaseBackupStart.Recorded(id.value)
    }
    override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? {
        if (!fresh(review)) return "Точная цель изменилась. Проверка не запущена."
        val current = exact(review, operation) ?: return "Запись не соответствует выбранной цели."
        if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED) ||
            current.snapshot.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED))
            return "Разрешена только проверка ранее начатого копирования."
        registry.begin(current.snapshot.operationId)
        return if (host(current.snapshot.operationId) == ExactOperationHostStartResult.START_REQUEST_ACCEPTED) null else "Android не принял проверку. Повторного создания не будет."
    }
    override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? {
        val current = exact(review, operation) ?: return "Точная запись недоступна."
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) return "Копирование могло начаться. Используйте проверку результата."
        val b = DatabaseBackupBinding.parse(current.snapshot.checkpoint.phaseName)?.second ?: return "Запись недоступна."
        val at = now(); if (at.isBefore(current.snapshot.updatedAt)) return "Время отмены не подтверждено."
        val result = journal.advance(current.snapshot.operationId, current.revision, current.snapshot.copy(status = OperationStatus.CANCELLED,
            checkpoint = OperationCheckpoint(b.phaseName(DatabaseBackupPhase.CANCELLED), CheckpointSemantics.TERMINAL, at), updatedAt = at))
        if (result !is OperationJournalResult.Success) return "Состояние изменилось. Обновите статус."
        runtime.discardDatabaseBackupConfirmation(current.snapshot.operationId)
        return null
    }
    private suspend fun fresh(r: ManagementRestartReview) =
        (local.readExact(r.serverId, r.installationId, r.accessId) as? ManagementRestartLocalReview.Ready)?.review == r
    private suspend fun exact(r: ManagementRestartReview, operation: String): VersionedOperationSnapshot? {
        if (operation.isBlank() || !fresh(r)) return null
        return (journal.get(OperationId(operation)) as? OperationJournalResult.Success)?.value
            ?.takeIf { it.snapshot.operationId.value == operation && DatabaseBackupBindingPolicy.matches(it, r.installation, r.access) }
    }
    private suspend fun failPending(current: VersionedOperationSnapshot, b: DatabaseBackupBinding) {
        runtime.discardDatabaseBackupConfirmation(current.snapshot.operationId)
        val at = now(); if (at.isBefore(current.snapshot.updatedAt)) return
        journal.advance(current.snapshot.operationId, current.revision, current.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = OperationCheckpoint(b.phaseName(DatabaseBackupPhase.FAILED), CheckpointSemantics.TERMINAL, at), updatedAt = at))
    }
    private fun blocked(text: String) = DatabaseBackupStart.Blocked(text)
}
