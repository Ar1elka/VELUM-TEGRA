package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface RestoredPanelStartRuntimeResult {
    data object NotRestoredPanelStartOperation : RestoredPanelStartRuntimeResult
    data object TransportRequired : RestoredPanelStartRuntimeResult
    data class Rejected(val failure: RestoredPanelStartFailure) : RestoredPanelStartRuntimeResult
    data class AwaitingVerification(val revision: OperationRevision) : RestoredPanelStartRuntimeResult
    data class Reviewed(val binding: RestoredPanelStartBinding, val revision: OperationRevision) : RestoredPanelStartRuntimeResult
    data class Failed(val revision: OperationRevision) : RestoredPanelStartRuntimeResult
    data class Completed(val receipt: RestoredPanelStartReceipt, val revision: OperationRevision,
        val installation: VersionedRecord<XuiInstallation>, val access: ServerAccess) : RestoredPanelStartRuntimeResult
}

fun interface RestoredPanelStartPreflightPort {
    suspend fun read(scope: ManagementScope, binding: RestoredPanelStartBinding, session: SshSessionHandle): RestoredPanelStartReady?
}
fun interface RestoredPanelStartCopyPort {
    suspend fun copy(dispatch: VerifiedRestoredPanelStartDispatch, current: VersionedOperationSnapshot, session: SshSessionHandle): RestoredPanelStartCopyResult
}
fun interface RestoredPanelStartVerifyPort {
    suspend fun verify(scope: ManagementScope, binding: RestoredPanelStartBinding, session: SshSessionHandle): RestoredPanelStartReceipt?
}

/** One shared runtime consumer. Confirmation is bounded process state; truth stays in the existing journal. */
class RestoredPanelStartRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installations: XuiInstallationRepository?,
    private val links: ManagementAccessRepository?,
    private val accesses: ServerAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessions: ExactSessionRegistry,
    private val mutations: ServerMutationLeaseRegistry,
    private val now: () -> Instant = Instant::now,
    private val preflight: RestoredPanelStartPreflightPort = RestoredPanelStartPreflightPort { scope, binding, session -> RestoredPanelStartSshAdapter().preflight(scope, binding, session) },
    private val copy: RestoredPanelStartCopyPort = RestoredPanelStartCopyPort { dispatch, current, session -> RestoredPanelStartSshAdapter().copy(dispatch, current, session) },
    private val verify: RestoredPanelStartVerifyPort = RestoredPanelStartVerifyPort { scope, binding, session -> RestoredPanelStartSshAdapter().verify(scope, binding, session) },
) {
    private val confirmations = linkedMapOf<OperationId, RestoredPanelStartConfirmation>()
    @Synchronized fun register(confirmation: RestoredPanelStartConfirmation): Boolean {
        confirmations.entries.removeAll { !now().isBefore(it.value.validUntil) }
        if (confirmations.size >= 8 || confirmations.containsKey(confirmation.operationId) || !now().isBefore(confirmation.validUntil)) return false
        confirmations[confirmation.operationId] = confirmation
        return true
    }
    @Synchronized fun discard(operationId: OperationId): Boolean = confirmations.remove(operationId) != null
    @Synchronized private fun confirmation(current: VersionedOperationSnapshot, consume: Boolean): RestoredPanelStartConfirmation? {
        val c = if (consume) confirmations.remove(current.snapshot.operationId) else confirmations[current.snapshot.operationId]
        return c?.takeIf { it.revision == current.revision && it.target == current.snapshot.target &&
            !now().isBefore(current.snapshot.updatedAt) && now().isBefore(it.validUntil) }
    }
    suspend fun prepare(admission: RecoveryRuntimeAdmission): RestoredPanelStartRuntimeResult {
        val current = read(admission) ?: return reject(RestoredPanelStartFailure.JOURNAL)
        if (current.snapshot.type != OperationType.RESTORED_PANEL_START) return RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation
        val exact = exactRecords(current) ?: return reject(RestoredPanelStartFailure.EXACT_TARGET)
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return reject(RestoredPanelStartFailure.SESSION)
        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> if (confirmation(current, false)?.let {
                it.installation == exact.first.value && it.access == exact.second
            } == true) RestoredPanelStartRuntimeResult.TransportRequired else reject(RestoredPanelStartFailure.AUTHORITY_MISSING)
            CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED -> RestoredPanelStartRuntimeResult.TransportRequired
            else -> reject(RestoredPanelStartFailure.JOURNAL)
        }
    }

    suspend fun execute(admission: RecoveryRuntimeAdmission, binding: SessionBinding): RestoredPanelStartRuntimeResult {
        var current = read(admission) ?: return reject(RestoredPanelStartFailure.JOURNAL)
        if (current.snapshot.type != OperationType.RESTORED_PANEL_START) return RestoredPanelStartRuntimeResult.NotRestoredPanelStartOperation
        val records = exactRecords(current) ?: return reject(RestoredPanelStartFailure.EXACT_TARGET)
        val target = current.snapshot.target as OperationTarget.InstallationTarget
        val scope = ManagementScope(current.snapshot.operationId, target.serverId, target.serverAccessId, target.installationId)
        val parsed = RestoredPanelStartBinding.parse(current.snapshot.checkpoint.phaseName) ?: return reject(RestoredPanelStartFailure.JOURNAL)
        val session = sessions.find(SessionOwner.Operation(scope.operationId), scope.serverAccessId)
            ?.takeIf { it.isOpen && it.binding == binding } ?: return reject(RestoredPanelStartFailure.SESSION)
        if (!valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.EXACT_TARGET)
        val acquisition = mutations.tryAcquire(scope.serverId, scope.operationId) as? ServerMutationAcquireResult.Acquired
            ?: return reject(RestoredPanelStartFailure.PRECHECK)
        try {
            if (current.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) {
                val c = confirmation(current, true) ?: return reject(RestoredPanelStartFailure.AUTHORITY_MISSING)
                val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(RestoredPanelStartFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, all.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed)
                    return reject(RestoredPanelStartFailure.PRECHECK)
                val ready = preflight.read(scope, parsed.second, session) ?: return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.EXACT_TARGET)
                val dispatch = RestoredPanelStartDispatchPolicy.authorize(c, current, ready, now())
                    ?: return failPending(current, parsed.second)
                val latestBarrier = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(RestoredPanelStartFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, latestBarrier.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
                    !valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.PRECHECK)
                // CAS is durable before possible service activation; no recovery branch can dispatch again.
                current = advance(current, parsed.second, RestoredPanelStartPhase.STARTING,
                    CheckpointSemantics.MUTATION_IN_FLIGHT, OperationStatus.RUNNING) ?: return reject(RestoredPanelStartFailure.JOURNAL)
                if (!valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.EXACT_TARGET)
                val result = copy.copy(dispatch, current, session)
                if (!valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.EXACT_TARGET)
                if(result==RestoredPanelStartCopyResult.NOT_STARTED)return failPending(current,parsed.second)
                val phase = when (result) {
                    RestoredPanelStartCopyResult.FINISHED -> RestoredPanelStartPhase.FINISHED
                    RestoredPanelStartCopyResult.NOT_STARTED, RestoredPanelStartCopyResult.FAILED -> RestoredPanelStartPhase.UNCERTAIN
                    RestoredPanelStartCopyResult.REJECTED, RestoredPanelStartCopyResult.UNCERTAIN -> RestoredPanelStartPhase.UNCERTAIN
                }
                current = advance(current, parsed.second, phase, CheckpointSemantics.POST_VERIFY_REQUIRED,
                    OperationStatus.RECONCILIATION_REQUIRED) ?: return reject(RestoredPanelStartFailure.JOURNAL)
                return RestoredPanelStartRuntimeResult.AwaitingVerification(current.revision)
            } else if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,
                    CheckpointSemantics.POST_VERIFY_REQUIRED)) return reject(RestoredPanelStartFailure.JOURNAL)
            // This branch is the ONLY resumption path. It holds no fresh start authority.
            if (!valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.EXACT_TARGET)
            val receipt = verify.verify(scope, parsed.second, session)
            if (!valid(admission, current, records, session, binding)) return reject(RestoredPanelStartFailure.EXACT_TARGET)
            if (receipt != null && receipt.scope == scope && receipt.binding == parsed.second &&
                !receipt.observedAt.isBefore(current.snapshot.updatedAt) && !receipt.observedAt.isAfter(now())) {
                val committed = advance(current, parsed.second, RestoredPanelStartPhase.VERIFIED,
                    CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED) ?: return reject(RestoredPanelStartFailure.JOURNAL)
                return RestoredPanelStartRuntimeResult.Completed(receipt, committed.revision, records.first, records.second)
            }
            // A confirmed command failure can follow a dispatched service start.
            // No absent/partial manifest may clear the durable mutation barrier.
            return RestoredPanelStartRuntimeResult.AwaitingVerification(current.revision)
        } finally { mutations.release(acquisition.lease) }
    }

    private suspend fun failPending(current: VersionedOperationSnapshot, b: RestoredPanelStartBinding): RestoredPanelStartRuntimeResult {
        val failed = advance(current, b, RestoredPanelStartPhase.FAILED, CheckpointSemantics.TERMINAL, OperationStatus.FAILED)
            ?: return reject(RestoredPanelStartFailure.JOURNAL)
        return RestoredPanelStartRuntimeResult.Failed(failed.revision)
    }
    private suspend fun read(admission: RecoveryRuntimeAdmission): VersionedOperationSnapshot? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return null
        val current = (journal.get(admission.plan.operationId) as? OperationJournalResult.Success)?.value ?: return null
        return current.takeIf { it.revision == admission.plan.expectedRevision && it.snapshot.target == admission.plan.target }
    }
    private suspend fun exactRecords(current: VersionedOperationSnapshot): Records? {
        val s = current.snapshot
        if (s.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)) return null
        val phase=RestoredPanelStartBinding.parse(s.checkpoint.phaseName)?.first?:return null
        if(!when(s.checkpoint.semantics){
            CheckpointSemantics.MUTATION_NOT_STARTED->s.status==OperationStatus.RUNNING && phase==RestoredPanelStartPhase.PENDING
            CheckpointSemantics.MUTATION_IN_FLIGHT->s.status==OperationStatus.RUNNING && phase==RestoredPanelStartPhase.STARTING
            CheckpointSemantics.POST_VERIFY_REQUIRED->s.status==OperationStatus.RECONCILIATION_REQUIRED && phase in setOf(RestoredPanelStartPhase.FINISHED,RestoredPanelStartPhase.UNCERTAIN)
            else->false})return null
        val t = s.target as? OperationTarget.InstallationTarget ?: return null
        val installation = (installations?.get(t.installationId) as? RepositoryResult.Success)?.value ?: return null
        val access = (accesses.get(t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        val binding = RestoredPanelStartBinding.parse(s.checkpoint.phaseName)?.second ?: return null
        val restore = (journal.get(binding.restoreOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val parent = (journal.get(binding.restored.comparisonOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val check = (journal.get(binding.restored.comparison.checkOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val backup = (journal.get(binding.source.sourceOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val link = (links?.get(t.installationId, t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        if (link.installationId != t.installationId || link.serverAccessId != t.serverAccessId ||
            !RestoredPanelStartBindingPolicy.matches(current, installation.value, access, restore, parent, check, backup)) return null
        return Records(installation, access, restore, parent, check, backup)
    }
    private data class Records(val first:VersionedRecord<XuiInstallation>,val second:ServerAccess,val restore:VersionedOperationSnapshot,val third:VersionedOperationSnapshot,
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
    private suspend fun advance(current: VersionedOperationSnapshot, b: RestoredPanelStartBinding, phase: RestoredPanelStartPhase,
        semantics: CheckpointSemantics, status: OperationStatus): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(status = status, checkpoint = OperationCheckpoint(b.phaseName(phase), semantics, at), updatedAt = at)
        return (journal.advance(current.snapshot.operationId, current.revision, next) as? OperationJournalResult.Success)?.value
    }
    private fun reject(failure: RestoredPanelStartFailure) = RestoredPanelStartRuntimeResult.Rejected(failure)
}
