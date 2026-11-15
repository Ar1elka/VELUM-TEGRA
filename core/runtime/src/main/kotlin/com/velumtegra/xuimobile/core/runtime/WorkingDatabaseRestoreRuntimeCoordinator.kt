package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface WorkingDatabaseRestoreRuntimeResult {
    data object NotWorkingDatabaseRestoreOperation : WorkingDatabaseRestoreRuntimeResult
    data object TransportRequired : WorkingDatabaseRestoreRuntimeResult
    data class Rejected(val failure: WorkingDatabaseRestoreFailure) : WorkingDatabaseRestoreRuntimeResult
    data class AwaitingVerification(val revision: OperationRevision) : WorkingDatabaseRestoreRuntimeResult
    data class Reviewed(val binding: WorkingDatabaseRestoreBinding, val revision: OperationRevision) : WorkingDatabaseRestoreRuntimeResult
    data class Failed(val revision: OperationRevision) : WorkingDatabaseRestoreRuntimeResult
    data class Completed(val receipt: WorkingDatabaseRestoreReceipt, val revision: OperationRevision,
        val installation: VersionedRecord<XuiInstallation>, val access: ServerAccess) : WorkingDatabaseRestoreRuntimeResult
}

fun interface WorkingDatabaseRestoreStoragePort {
    suspend fun read(scope: ManagementScope, binding: WorkingDatabaseRestoreBinding, session: SshSessionHandle): InstallationBackupStorageObservation?
}
fun interface WorkingDatabaseRestoreCopyPort {
    suspend fun copy(dispatch: VerifiedWorkingDatabaseRestoreDispatch, current: VersionedOperationSnapshot, session: SshSessionHandle): WorkingDatabaseRestoreCopyResult
}
fun interface WorkingDatabaseRestoreVerifyPort {
    suspend fun verify(scope: ManagementScope, binding: WorkingDatabaseRestoreBinding, session: SshSessionHandle): WorkingDatabaseRestoreReceipt?
}

/** One shared runtime consumer. Confirmation is bounded process state; truth stays in the existing journal. */
class WorkingDatabaseRestoreRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installations: XuiInstallationRepository?,
    private val links: ManagementAccessRepository?,
    private val accesses: ServerAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessions: ExactSessionRegistry,
    private val mutations: ServerMutationLeaseRegistry,
    private val now: () -> Instant = Instant::now,
    private val storage: WorkingDatabaseRestoreStoragePort = WorkingDatabaseRestoreStoragePort { scope, binding, session -> WorkingDatabaseRestoreSshAdapter().storage(scope, binding, session) },
    private val copy: WorkingDatabaseRestoreCopyPort = WorkingDatabaseRestoreCopyPort { dispatch, current, session -> WorkingDatabaseRestoreSshAdapter().copy(dispatch, current, session) },
    private val verify: WorkingDatabaseRestoreVerifyPort = WorkingDatabaseRestoreVerifyPort { scope, binding, session -> WorkingDatabaseRestoreSshAdapter().verify(scope, binding, session) },
) {
    private val confirmations = linkedMapOf<OperationId, WorkingDatabaseRestoreConfirmation>()
    @Synchronized fun register(confirmation: WorkingDatabaseRestoreConfirmation): Boolean {
        confirmations.entries.removeAll { !now().isBefore(it.value.validUntil) }
        if (confirmations.size >= 8 || confirmations.containsKey(confirmation.operationId) || !now().isBefore(confirmation.validUntil)) return false
        confirmations[confirmation.operationId] = confirmation
        return true
    }
    @Synchronized fun discard(operationId: OperationId): Boolean = confirmations.remove(operationId) != null
    @Synchronized private fun confirmation(current: VersionedOperationSnapshot, consume: Boolean): WorkingDatabaseRestoreConfirmation? {
        val c = if (consume) confirmations.remove(current.snapshot.operationId) else confirmations[current.snapshot.operationId]
        return c?.takeIf { it.revision == current.revision && it.target == current.snapshot.target &&
            !now().isBefore(current.snapshot.updatedAt) && now().isBefore(it.validUntil) }
    }
    suspend fun prepare(admission: RecoveryRuntimeAdmission): WorkingDatabaseRestoreRuntimeResult {
        val current = read(admission) ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
        if (current.snapshot.type != OperationType.WORKING_DATABASE_RESTORE) return WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation
        val exact = exactRecords(current) ?: return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return reject(WorkingDatabaseRestoreFailure.SESSION)
        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> if (confirmation(current, false)?.let {
                it.installation == exact.first.value && it.access == exact.second
            } == true) WorkingDatabaseRestoreRuntimeResult.TransportRequired else reject(WorkingDatabaseRestoreFailure.AUTHORITY_MISSING)
            CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED -> WorkingDatabaseRestoreRuntimeResult.TransportRequired
            else -> reject(WorkingDatabaseRestoreFailure.JOURNAL)
        }
    }

    suspend fun execute(admission: RecoveryRuntimeAdmission, binding: SessionBinding): WorkingDatabaseRestoreRuntimeResult {
        var current = read(admission) ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
        if (current.snapshot.type != OperationType.WORKING_DATABASE_RESTORE) return WorkingDatabaseRestoreRuntimeResult.NotWorkingDatabaseRestoreOperation
        val records = exactRecords(current) ?: return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
        val target = current.snapshot.target as OperationTarget.InstallationTarget
        val scope = ManagementScope(current.snapshot.operationId, target.serverId, target.serverAccessId, target.installationId)
        val parsed = WorkingDatabaseRestoreBinding.parse(current.snapshot.checkpoint.phaseName) ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
        val session = sessions.find(SessionOwner.Operation(scope.operationId), scope.serverAccessId)
            ?.takeIf { it.isOpen && it.binding == binding } ?: return reject(WorkingDatabaseRestoreFailure.SESSION)
        if (!valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
        val acquisition = mutations.tryAcquire(scope.serverId, scope.operationId) as? ServerMutationAcquireResult.Acquired
            ?: return reject(WorkingDatabaseRestoreFailure.PRECHECK)
        try {
            if (current.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) {
                val c = confirmation(current, true) ?: return reject(WorkingDatabaseRestoreFailure.AUTHORITY_MISSING)
                val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, all.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed)
                    return reject(WorkingDatabaseRestoreFailure.PRECHECK)
                val space = storage.read(scope, parsed.second, session) ?: return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
                val dispatch = WorkingDatabaseRestoreDispatchPolicy.authorize(c, current, space, now())
                    ?: return failPending(current, parsed.second)
                val latestBarrier = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, latestBarrier.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
                    !valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.PRECHECK)
                // CAS is durable before the first possible write; no recovery branch can dispatch again.
                current = advance(current, parsed.second, WorkingDatabaseRestorePhase.RESTORING,
                    CheckpointSemantics.MUTATION_IN_FLIGHT, OperationStatus.RUNNING) ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
                if (!valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
                val result = copy.copy(dispatch, current, session)
                if (!valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
                if(result==WorkingDatabaseRestoreCopyResult.NOT_STARTED)return failPending(current,parsed.second)
                val phase = when (result) {
                    WorkingDatabaseRestoreCopyResult.FINISHED -> WorkingDatabaseRestorePhase.FINISHED
                    WorkingDatabaseRestoreCopyResult.NOT_STARTED, WorkingDatabaseRestoreCopyResult.FAILED -> WorkingDatabaseRestorePhase.UNCERTAIN
                    WorkingDatabaseRestoreCopyResult.REJECTED, WorkingDatabaseRestoreCopyResult.UNCERTAIN -> WorkingDatabaseRestorePhase.UNCERTAIN
                }
                current = advance(current, parsed.second, phase, CheckpointSemantics.POST_VERIFY_REQUIRED,
                    OperationStatus.RECONCILIATION_REQUIRED) ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
                return WorkingDatabaseRestoreRuntimeResult.AwaitingVerification(current.revision)
            } else if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,
                    CheckpointSemantics.POST_VERIFY_REQUIRED)) return reject(WorkingDatabaseRestoreFailure.JOURNAL)
            // This branch is the ONLY resumption path. It holds no fresh copy authority.
            if (!valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
            val receipt = verify.verify(scope, parsed.second, session)
            if (!valid(admission, current, records, session, binding)) return reject(WorkingDatabaseRestoreFailure.EXACT_TARGET)
            if (receipt != null && receipt.scope == scope && receipt.binding == parsed.second &&
                !receipt.verifiedAt.isBefore(current.snapshot.updatedAt) && !receipt.verifiedAt.isAfter(now())) {
                val committed = advance(current, parsed.second, WorkingDatabaseRestorePhase.VERIFIED,
                    CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED) ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
                return WorkingDatabaseRestoreRuntimeResult.Completed(receipt, committed.revision, records.first, records.second)
            }
            // A confirmed command failure can follow service stop or a committed DB transaction.
            // No absent/partial manifest may clear the durable mutation barrier.
            return WorkingDatabaseRestoreRuntimeResult.AwaitingVerification(current.revision)
        } finally { mutations.release(acquisition.lease) }
    }

    private suspend fun failPending(current: VersionedOperationSnapshot, b: WorkingDatabaseRestoreBinding): WorkingDatabaseRestoreRuntimeResult {
        val failed = advance(current, b, WorkingDatabaseRestorePhase.FAILED, CheckpointSemantics.TERMINAL, OperationStatus.FAILED)
            ?: return reject(WorkingDatabaseRestoreFailure.JOURNAL)
        return WorkingDatabaseRestoreRuntimeResult.Failed(failed.revision)
    }
    private suspend fun read(admission: RecoveryRuntimeAdmission): VersionedOperationSnapshot? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return null
        val current = (journal.get(admission.plan.operationId) as? OperationJournalResult.Success)?.value ?: return null
        return current.takeIf { it.revision == admission.plan.expectedRevision && it.snapshot.target == admission.plan.target }
    }
    private suspend fun exactRecords(current: VersionedOperationSnapshot): Records? {
        val s = current.snapshot
        if (s.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)) return null
        val phase=WorkingDatabaseRestoreBinding.parse(s.checkpoint.phaseName)?.first?:return null
        if(!when(s.checkpoint.semantics){
            CheckpointSemantics.MUTATION_NOT_STARTED->s.status==OperationStatus.RUNNING && phase==WorkingDatabaseRestorePhase.PENDING
            CheckpointSemantics.MUTATION_IN_FLIGHT->s.status==OperationStatus.RUNNING && phase==WorkingDatabaseRestorePhase.RESTORING
            CheckpointSemantics.POST_VERIFY_REQUIRED->s.status==OperationStatus.RECONCILIATION_REQUIRED && phase in setOf(WorkingDatabaseRestorePhase.FINISHED,WorkingDatabaseRestorePhase.UNCERTAIN)
            else->false})return null
        val t = s.target as? OperationTarget.InstallationTarget ?: return null
        val installation = (installations?.get(t.installationId) as? RepositoryResult.Success)?.value ?: return null
        val access = (accesses.get(t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        val binding = WorkingDatabaseRestoreBinding.parse(s.checkpoint.phaseName)?.second ?: return null
        val parent = (journal.get(binding.comparisonOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val check = (journal.get(binding.comparison.checkOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val backup = (journal.get(binding.source.sourceOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val link = (links?.get(t.installationId, t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        if (link.installationId != t.installationId || link.serverAccessId != t.serverAccessId ||
            !WorkingDatabaseRestoreBindingPolicy.matches(current, installation.value, access, parent, check, backup)) return null
        return Records(installation, access, parent, check, backup)
    }
    private data class Records(val first:VersionedRecord<XuiInstallation>,val second:ServerAccess,val third:VersionedOperationSnapshot,
        val check:VersionedOperationSnapshot,val backup:VersionedOperationSnapshot)

    private suspend fun valid(admission: RecoveryRuntimeAdmission, current: VersionedOperationSnapshot,
        records: Records, session: SshSessionHandle, binding: SessionBinding): Boolean {
        currentCoroutineContext().ensureActive()
        if (!runtimeRegistry.isCurrent(admission.runtimeLease) || !session.isOpen || session.binding != binding ||
            binding.owner != SessionOwner.Operation(current.snapshot.operationId) ||
            binding.serverAccessId != current.snapshot.target.serverAccessId ||
            sessions.find(binding.owner, binding.serverAccessId) !== session) return false
        val latest = (journal.get(current.snapshot.operationId) as? OperationJournalResult.Success)?.value ?: return false
        return latest == current && exactRecords(current) == records
    }
    private suspend fun advance(current: VersionedOperationSnapshot, b: WorkingDatabaseRestoreBinding, phase: WorkingDatabaseRestorePhase,
        semantics: CheckpointSemantics, status: OperationStatus): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(status = status, checkpoint = OperationCheckpoint(b.phaseName(phase), semantics, at), updatedAt = at)
        return (journal.advance(current.snapshot.operationId, current.revision, next) as? OperationJournalResult.Success)?.value
    }
    private fun reject(failure: WorkingDatabaseRestoreFailure) = WorkingDatabaseRestoreRuntimeResult.Rejected(failure)
}
