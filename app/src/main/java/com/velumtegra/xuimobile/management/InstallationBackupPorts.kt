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

data class InstallationBackupObservation(val operationId: String, val text: String, val terminal: Boolean,
    val mayCheck: Boolean = false, val mayCancel: Boolean = false, val receipt: InstallationBackupReceipt? = null, val mayReviewRestore: Boolean = false)
interface InstallationBackupStatusPort {
    suspend fun read(server: String, installation: String, access: String, operation: String): InstallationBackupObservation?
    suspend fun unfinished(server: String, installation: String, access: String): List<String>
    /** Local in-memory observation only; never starts SSH. */
    fun slots(review: ManagementRestartReview): com.velumtegra.xuimobile.core.model.BackupSlotInventory? = null
}
sealed interface InstallationBackupStart {
    data class Recorded(val operationId: String) : InstallationBackupStart
    data class Blocked(val text: String) : InstallationBackupStart
}
interface InstallationBackupActionPort {
    suspend fun createConfirmed(review: ManagementRestartReview, source: UpdatePreflightPointer): InstallationBackupStart
    suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String?
    suspend fun cancelPending(review: ManagementRestartReview, operation: String): String?
}

internal class InstallationBackupResultRegistry {
    private val values = linkedMapOf<OperationId, InstallationBackupRuntimeResult?>()
    @Synchronized fun begin(id: OperationId) { values[id] = null; while (values.size > 8) values.remove(values.keys.first()) }
    @Synchronized fun publish(id: OperationId, result: InstallationBackupRuntimeResult?) {
        if (id in values && values[id] !is InstallationBackupRuntimeResult.Completed) values[id] = result
    }
    @Synchronized fun latest(id: OperationId): InstallationBackupRuntimeResult? = values[id]
}
internal fun ExactOperationHostTransportSequenceResult.installationBackupResult(): InstallationBackupRuntimeResult? = when (this) {
    is ExactOperationHostTransportSequenceResult.InstallationBackupEnded -> backup
    is ExactOperationHostTransportSequenceResult.InstallationBackupPrepared -> backup
    else -> null
}

internal class JournalInstallationBackupStatusPort(private val journal: OperationJournal,
    private val local: ManagementRestartLocalPort, private val registry: InstallationBackupResultRegistry,
    private val slotSource: (ServerId, ServerAccess) -> BackupSlotInventory? = { _, _ -> null }) : InstallationBackupStatusPort {
    override fun slots(review: ManagementRestartReview): BackupSlotInventory? =
        if (review.serverId.isBlank() || review.access.serverId.value != review.serverId) null else slotSource(ServerId(review.serverId), review.access)
    override suspend fun read(server: String, installation: String, access: String, operation: String): InstallationBackupObservation? {
        if (listOf(server, installation, access, operation).any { it.isBlank() }) return null
        val current = (journal.get(OperationId(operation)) as? OperationJournalResult.Success)?.value ?: return null
        val review = (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review ?: return null
        val s = current.snapshot
        if (s.operationId.value != operation || !InstallationBackupBindingPolicy.matches(current, review.installation, review.access)) return null
        val parsed = InstallationBackupBinding.parse(s.checkpoint.phaseName) ?: return null
        val terminal = s.status in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        if (terminal != (s.checkpoint.semantics == CheckpointSemantics.TERMINAL)) return null
        val d = registry.latest(s.operationId) as? InstallationBackupRuntimeResult.Completed
        val candidate = d?.takeIf { it.revision == current.revision && it.installation.value == review.installation &&
            it.access == review.access && it.receipt.scope.operationId == s.operationId && it.receipt.binding == parsed.second &&
            it.receipt.scope.serverId.value == server && it.receipt.scope.installationId.value == installation &&
            it.receipt.scope.serverAccessId.value == access }?.receipt
        val receipt = candidate?.takeIf {
            (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review == review &&
                (journal.get(s.operationId) as? OperationJournalResult.Success)?.value == current
        }
        val pending = !terminal && parsed.first == InstallationBackupPhase.PENDING && s.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED
        val check = !terminal && s.checkpoint.semantics in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED)
        val text = when {
            terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == InstallationBackupPhase.VERIFIED && receipt != null ->
                "Архив известных файлов установки проверен: содержимое, SHA-256 и целостность включённой базы совпадают. Восстановление ещё не проверено."
            terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == InstallationBackupPhase.VERIFIED ->
                "Журнал подтверждает завершённую проверку архива. Размер, состав и SHA-256 этого результата не сохранились в памяти."
            terminal && s.status == OperationStatus.CANCELLED -> "Ожидающий запрос отменён до отправки копирования."
            terminal -> "Архив не подтверждён. Приватные незавершённые файлы могут занимать место на сервере."
            check -> "Создание завершилось или могло выполниться. Нужна отдельная проверка существующего архива; повторное создание не отправляется."
            pending -> "Запрос зарегистрирован. Начало копирования в журнале ещё не отмечено; подтверждённого результата нет. Ожидающий запрос можно отменить."
            else -> "Точное состояние запроса не подтверждено."
        }
        return InstallationBackupObservation(operation, text, terminal, check, pending, receipt,
            terminal && s.status == OperationStatus.SUCCEEDED && parsed.first == InstallationBackupPhase.VERIFIED)
    }
    override suspend fun unfinished(server: String, installation: String, access: String): List<String> {
        val review = (local.readExact(server, installation, access) as? ManagementRestartLocalReview.Ready)?.review ?: return emptyList()
        val list = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: return emptyList()
        return list.filter { InstallationBackupBindingPolicy.matches(it, review.installation, review.access) }
            .sortedByDescending { it.snapshot.startedAt }.take(20).map { it.snapshot.operationId.value }
    }
}

internal class ProductionInstallationBackupActionPort(private val local: ManagementRestartLocalPort,
    private val sourceStatus: UpdatePreflightStatusPort, private val journal: OperationJournal,
    private val runtime: OperationRuntimeCoordinator, private val registry: InstallationBackupResultRegistry,
    private val host: suspend (OperationId) -> ExactOperationHostStartResult,
    private val now: () -> Instant = Instant::now,
    private val idFactory: () -> OperationId = { OperationId(UUID.randomUUID().toString()) }) : InstallationBackupActionPort {
    constructor(activity: Activity, local: ManagementRestartLocalPort, sourceStatus: UpdatePreflightStatusPort,
        journal: OperationJournal, runtime: OperationRuntimeCoordinator, registry: InstallationBackupResultRegistry) :
        this(local, sourceStatus, journal, runtime, registry, { VisibleExactOperationHostLauncher(activity).start(it) })
    override suspend fun createConfirmed(review: ManagementRestartReview, source: UpdatePreflightPointer): InstallationBackupStart {
        if (source.accessId != review.accessId || !fresh(review)) return blocked("Цель изменилась. Обновите сведения.")
        val report = sourceStatus.read(review.serverId, review.installationId, source).snapshot
            ?: return blocked("Состав архива не подтверждён. Выполните новую проверку установки и файлов.")
        if (report.scope != ManagementScope(OperationId(source.operationId), review.installation.serverId, review.access.id, review.installation.id))
            return blocked("Отчёт не соответствует точной выбранной установке и SSH-профилю.")
        if (UpdateRecoveryReadinessPolicy.review(report, now()) !is UpdateRecoveryPlanReview.Draft ||
            RecoveryFileInventoryPolicy.review(report, now()) !is RecoveryFileInventoryReview.KnownSet || report.recoveryFiles?.sourceSetDigest == null)
            return blocked("Отчёт устарел или содержит замечания. Нужна новая проверка установки.")
        val nonTerminal = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
            ?: return blocked("Журнал недоступен.")
        if (DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId, nonTerminal.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
            nonTerminal.any { it.snapshot.type in setOf(OperationType.DATABASE_BACKUP, OperationType.INSTALLATION_BACKUP) &&
                (it.snapshot.target as? OperationTarget.InstallationTarget)?.installationId == review.installation.id })
            return blocked("Есть незавершённая операция. Сначала проверьте её результат или отмените ожидающий запрос.")
        val id = idFactory(); if (id.value.isBlank()) return blocked("Не удалось создать запрос.")
        val b = InstallationBackupBindingPolicy.bind(id, review.installation, review.access,
            report.currentVersion ?: return blocked("Версия не подтверждена."),
            report.architecture ?: return blocked("Архитектура не подтверждена."))
        if (!fresh(review)) return blocked("Сохранённая цель изменилась.")
        val at = now()
        val initial = OperationSnapshot(id, OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(review.installation.serverId, review.access.id, review.installation.id),
            OperationStatus.RUNNING, OperationCheckpoint(b.phaseName(InstallationBackupPhase.PENDING), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at)
        val created = (journal.create(initial) as? OperationJournalResult.Success)?.value ?: return blocked("Журнал не принял запрос.")
        registry.begin(id)
        try {
            val c = InstallationBackupConfirmationPolicy.confirm(created, review.installation, review.access, report, now())
            if (c == null || !runtime.registerInstallationBackupConfirmation(c) || !fresh(review) ||
                host(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED) failPending(created, b)
        } catch (cancel: CancellationException) {
            withContext(NonCancellable) { failPending(created, b) }; throw cancel
        } catch (_: Exception) { failPending(created, b) }
        return InstallationBackupStart.Recorded(id.value)
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
        val b = InstallationBackupBinding.parse(current.snapshot.checkpoint.phaseName)?.second ?: return "Запись недоступна."
        val at = now(); if (at.isBefore(current.snapshot.updatedAt)) return "Время отмены не подтверждено."
        val result = journal.advance(current.snapshot.operationId, current.revision, current.snapshot.copy(status = OperationStatus.CANCELLED,
            checkpoint = OperationCheckpoint(b.phaseName(InstallationBackupPhase.CANCELLED), CheckpointSemantics.TERMINAL, at), updatedAt = at))
        if (result !is OperationJournalResult.Success) return "Состояние изменилось. Обновите статус."
        runtime.discardInstallationBackupConfirmation(current.snapshot.operationId)
        return null
    }
    private suspend fun fresh(r: ManagementRestartReview) =
        (local.readExact(r.serverId, r.installationId, r.accessId) as? ManagementRestartLocalReview.Ready)?.review == r
    private suspend fun exact(r: ManagementRestartReview, operation: String): VersionedOperationSnapshot? {
        if (operation.isBlank() || !fresh(r)) return null
        return (journal.get(OperationId(operation)) as? OperationJournalResult.Success)?.value
            ?.takeIf { it.snapshot.operationId.value == operation && InstallationBackupBindingPolicy.matches(it, r.installation, r.access) }
    }
    private suspend fun failPending(current: VersionedOperationSnapshot, b: InstallationBackupBinding) {
        runtime.discardInstallationBackupConfirmation(current.snapshot.operationId)
        val at = now(); if (at.isBefore(current.snapshot.updatedAt)) return
        journal.advance(current.snapshot.operationId, current.revision, current.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = OperationCheckpoint(b.phaseName(InstallationBackupPhase.FAILED), CheckpointSemantics.TERMINAL, at), updatedAt = at))
    }
    private fun blocked(text: String) = InstallationBackupStart.Blocked(text)
}
