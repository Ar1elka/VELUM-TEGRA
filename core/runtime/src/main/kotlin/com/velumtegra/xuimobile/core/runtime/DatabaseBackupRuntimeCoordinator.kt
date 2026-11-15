package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface DatabaseBackupRuntimeResult {
    data object NotDatabaseBackupOperation : DatabaseBackupRuntimeResult
    data object TransportRequired : DatabaseBackupRuntimeResult
    data class Rejected(val failure: DatabaseBackupFailure) : DatabaseBackupRuntimeResult
    data class AwaitingVerification(val revision: OperationRevision) : DatabaseBackupRuntimeResult
    data class Failed(val revision: OperationRevision) : DatabaseBackupRuntimeResult
    data class Completed(val receipt: DatabaseBackupReceipt, val revision: OperationRevision,
        val installation: VersionedRecord<XuiInstallation>, val access: ServerAccess) : DatabaseBackupRuntimeResult
}

fun interface DatabaseBackupPreflightPort {
    suspend fun read(scope: ManagementScope, installation: XuiInstallation, session: SshSessionHandle): UpdatePreflightSnapshot?
}
fun interface DatabaseBackupStoragePort {
    suspend fun read(scope: ManagementScope, session: SshSessionHandle): DatabaseBackupStorageObservation?
}
fun interface DatabaseBackupCopyPort {
    suspend fun copy(dispatch: VerifiedDatabaseBackupDispatch, current: VersionedOperationSnapshot, session: SshSessionHandle): DatabaseBackupCopyResult
}
fun interface DatabaseBackupVerifyPort {
    suspend fun verify(scope: ManagementScope, binding: DatabaseBackupBinding, session: SshSessionHandle): DatabaseBackupReceipt?
}

/** One shared runtime consumer. Confirmation is bounded process state; truth stays in the existing journal. */
class DatabaseBackupRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installations: XuiInstallationRepository?,
    private val links: ManagementAccessRepository?,
    private val accesses: ServerAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessions: ExactSessionRegistry,
    private val mutations: ServerMutationLeaseRegistry,
    private val now: () -> Instant = Instant::now,
    private val preflight: DatabaseBackupPreflightPort = DatabaseBackupPreflightPort { scope, installation, session ->
        val run = ManagementSshProbeExecutor().executeQuickInspect(scope, installation, session)
        val evidence = (run as? ManagementSshProbeRunResult.Completed)?.evidence
        val management = evidence?.let { ManagementReadbackPolicy.quickInspect(installation, it,
            TargetProofId(UUID.randomUUID().toString()), Instant.now()) } ?: return@DatabaseBackupPreflightPort null
        if (management.identityStatus != ManagementIdentityStatus.Matched) null else
            (UpdatePreflightSshReader().read(scope, installation, session, management) as? UpdatePreflightSshResult.Completed)?.snapshot
    },
    private val storage: DatabaseBackupStoragePort = DatabaseBackupStoragePort { scope, session -> DatabaseBackupSshAdapter().storage(scope, session) },
    private val copy: DatabaseBackupCopyPort = DatabaseBackupCopyPort { dispatch, current, session -> DatabaseBackupSshAdapter().copy(dispatch, current, session) },
    private val verify: DatabaseBackupVerifyPort = DatabaseBackupVerifyPort { scope, binding, session -> DatabaseBackupSshAdapter().verify(scope, binding, session) },
    private val slots: BackupSlotInventoryRegistry = BackupSlotInventoryRegistry(),
) {
    private val confirmations = linkedMapOf<OperationId, DatabaseBackupConfirmation>()
    @Synchronized fun register(confirmation: DatabaseBackupConfirmation): Boolean {
        confirmations.entries.removeAll { !now().isBefore(it.value.validUntil) }
        if (confirmations.size >= 8 || confirmations.containsKey(confirmation.operationId) || !now().isBefore(confirmation.validUntil)) return false
        confirmations[confirmation.operationId] = confirmation
        return true
    }
    @Synchronized fun discard(operationId: OperationId): Boolean = confirmations.remove(operationId) != null
    @Synchronized private fun confirmation(current: VersionedOperationSnapshot, consume: Boolean): DatabaseBackupConfirmation? {
        val c = if (consume) confirmations.remove(current.snapshot.operationId) else confirmations[current.snapshot.operationId]
        return c?.takeIf { it.revision == current.revision && it.target == current.snapshot.target &&
            !now().isBefore(current.snapshot.updatedAt) && now().isBefore(it.validUntil) }
    }
    suspend fun prepare(admission: RecoveryRuntimeAdmission): DatabaseBackupRuntimeResult {
        val current = read(admission) ?: return reject(DatabaseBackupFailure.JOURNAL)
        if (current.snapshot.type != OperationType.DATABASE_BACKUP) return DatabaseBackupRuntimeResult.NotDatabaseBackupOperation
        val exact = exactRecords(current) ?: return reject(DatabaseBackupFailure.EXACT_TARGET)
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return reject(DatabaseBackupFailure.SESSION)
        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> if (confirmation(current, false)?.let {
                it.installation == exact.first.value && it.access == exact.second
            } == true) DatabaseBackupRuntimeResult.TransportRequired else reject(DatabaseBackupFailure.AUTHORITY_MISSING)
            CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED -> DatabaseBackupRuntimeResult.TransportRequired
            else -> reject(DatabaseBackupFailure.JOURNAL)
        }
    }

    suspend fun execute(admission: RecoveryRuntimeAdmission, binding: SessionBinding): DatabaseBackupRuntimeResult {
        var current = read(admission) ?: return reject(DatabaseBackupFailure.JOURNAL)
        if (current.snapshot.type != OperationType.DATABASE_BACKUP) return DatabaseBackupRuntimeResult.NotDatabaseBackupOperation
        val records = exactRecords(current) ?: return reject(DatabaseBackupFailure.EXACT_TARGET)
        val target = current.snapshot.target as OperationTarget.InstallationTarget
        val scope = ManagementScope(current.snapshot.operationId, target.serverId, target.serverAccessId, target.installationId)
        val parsed = DatabaseBackupBinding.parse(current.snapshot.checkpoint.phaseName) ?: return reject(DatabaseBackupFailure.JOURNAL)
        val session = sessions.find(SessionOwner.Operation(scope.operationId), scope.serverAccessId)
            ?.takeIf { it.isOpen && it.binding == binding } ?: return reject(DatabaseBackupFailure.SESSION)
        if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
        val acquisition = mutations.tryAcquire(scope.serverId, scope.operationId) as? ServerMutationAcquireResult.Acquired
            ?: return reject(DatabaseBackupFailure.PRECHECK)
        try {
            if (current.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) {
                val c = confirmation(current, true) ?: return reject(DatabaseBackupFailure.AUTHORITY_MISSING)
                val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(DatabaseBackupFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, all.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed)
                    return reject(DatabaseBackupFailure.PRECHECK)
                val fresh = preflight.read(scope, records.first.value, session) ?: return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
                val space = storage.read(scope, session)
                recordSlots(scope, records.second, space)
                if (space == null) return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
                val dispatch = DatabaseBackupDispatchPolicy.authorize(c, current, fresh, space, now())
                    ?: return failPending(current, parsed.second)
                val latestBarrier = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(DatabaseBackupFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, latestBarrier.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
                    !valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.PRECHECK)
                // CAS is durable before the first possible write; no recovery branch can dispatch again.
                current = advance(current, parsed.second, DatabaseBackupPhase.COPYING,
                    CheckpointSemantics.MUTATION_IN_FLIGHT, OperationStatus.RUNNING) ?: return reject(DatabaseBackupFailure.JOURNAL)
                if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
                val result = copy.copy(dispatch, current, session)
                if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
                val phase = when (result) {
                    DatabaseBackupCopyResult.FINISHED -> DatabaseBackupPhase.FINISHED
                    DatabaseBackupCopyResult.FAILED -> DatabaseBackupPhase.COMMAND_FAILED
                    DatabaseBackupCopyResult.REJECTED, DatabaseBackupCopyResult.UNCERTAIN -> DatabaseBackupPhase.UNCERTAIN
                }
                current = advance(current, parsed.second, phase, CheckpointSemantics.POST_VERIFY_REQUIRED,
                    OperationStatus.RECONCILIATION_REQUIRED) ?: return reject(DatabaseBackupFailure.JOURNAL)
                if (phase == DatabaseBackupPhase.UNCERTAIN) return DatabaseBackupRuntimeResult.AwaitingVerification(current.revision)
            } else if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,
                    CheckpointSemantics.POST_VERIFY_REQUIRED)) return reject(DatabaseBackupFailure.JOURNAL)
            // This branch is the ONLY resumption path. It holds no fresh copy authority.
            if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
            val receipt = verify.verify(scope, parsed.second, session)
            if (!valid(admission, current, records, session, binding)) return reject(DatabaseBackupFailure.EXACT_TARGET)
            if (receipt != null && receipt.scope == scope && receipt.binding == parsed.second &&
                !receipt.verifiedAt.isBefore(current.snapshot.updatedAt) && !receipt.verifiedAt.isAfter(now())) {
                val committed = advance(current, parsed.second, DatabaseBackupPhase.VERIFIED,
                    CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED) ?: return reject(DatabaseBackupFailure.JOURNAL)
                return DatabaseBackupRuntimeResult.Completed(receipt, committed.revision, records.first, records.second)
            }
            // Confirmed command failure may be closed. Absence after uncertain dispatch cannot be.
            if (DatabaseBackupBinding.parse(current.snapshot.checkpoint.phaseName)?.first == DatabaseBackupPhase.COMMAND_FAILED) {
                val failed = advance(current, parsed.second, DatabaseBackupPhase.FAILED,
                    CheckpointSemantics.TERMINAL, OperationStatus.FAILED) ?: return reject(DatabaseBackupFailure.JOURNAL)
                return DatabaseBackupRuntimeResult.Failed(failed.revision)
            }
            return DatabaseBackupRuntimeResult.AwaitingVerification(current.revision)
        } finally { mutations.release(acquisition.lease) }
    }

    /** Latest read-only slot observation for display. Never authorizes anything. */
    fun slotInventory(serverId: ServerId, profile: ServerAccess): BackupSlotInventory? = slots.latest(serverId, profile)
    private fun recordSlots(scope: ManagementScope, profile: ServerAccess, observation: DatabaseBackupStorageObservation?) {
        val at = now()
        slots.record(scope.serverId, profile, observation?.takeIf { it.scope == scope }?.let {
            BackupSlotInventory.Known(it.slotsUsed, DatabaseBackupBinding.MAX_SLOTS, it.observedAt) } ?: BackupSlotInventory.Unavailable(at))
    }
    private suspend fun failPending(current: VersionedOperationSnapshot, b: DatabaseBackupBinding): DatabaseBackupRuntimeResult {
        val failed = advance(current, b, DatabaseBackupPhase.FAILED, CheckpointSemantics.TERMINAL, OperationStatus.FAILED)
            ?: return reject(DatabaseBackupFailure.JOURNAL)
        return DatabaseBackupRuntimeResult.Failed(failed.revision)
    }
    private suspend fun read(admission: RecoveryRuntimeAdmission): VersionedOperationSnapshot? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return null
        val current = (journal.get(admission.plan.operationId) as? OperationJournalResult.Success)?.value ?: return null
        return current.takeIf { it.revision == admission.plan.expectedRevision && it.snapshot.target == admission.plan.target }
    }
    private suspend fun exactRecords(current: VersionedOperationSnapshot): Pair<VersionedRecord<XuiInstallation>, ServerAccess>? {
        val s = current.snapshot
        if (s.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)) return null
        val t = s.target as? OperationTarget.InstallationTarget ?: return null
        val installation = (installations?.get(t.installationId) as? RepositoryResult.Success)?.value ?: return null
        val access = (accesses.get(t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        val link = (links?.get(t.installationId, t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        if (link.installationId != t.installationId || link.serverAccessId != t.serverAccessId ||
            !DatabaseBackupBindingPolicy.matches(current, installation.value, access)) return null
        return installation to access
    }
    private suspend fun valid(admission: RecoveryRuntimeAdmission, current: VersionedOperationSnapshot,
        records: Pair<VersionedRecord<XuiInstallation>, ServerAccess>, session: SshSessionHandle, binding: SessionBinding): Boolean {
        currentCoroutineContext().ensureActive()
        if (!runtimeRegistry.isCurrent(admission.runtimeLease) || !session.isOpen || session.binding != binding ||
            binding.owner != SessionOwner.Operation(current.snapshot.operationId) ||
            binding.serverAccessId != current.snapshot.target.serverAccessId ||
            sessions.find(binding.owner, binding.serverAccessId) !== session) return false
        val latest = (journal.get(current.snapshot.operationId) as? OperationJournalResult.Success)?.value ?: return false
        return latest == current && exactRecords(current) == records
    }
    private suspend fun advance(current: VersionedOperationSnapshot, b: DatabaseBackupBinding, phase: DatabaseBackupPhase,
        semantics: CheckpointSemantics, status: OperationStatus): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(status = status, checkpoint = OperationCheckpoint(b.phaseName(phase), semantics, at), updatedAt = at)
        return (journal.advance(current.snapshot.operationId, current.revision, next) as? OperationJournalResult.Success)?.value
    }
    private fun reject(failure: DatabaseBackupFailure) = DatabaseBackupRuntimeResult.Rejected(failure)
}
