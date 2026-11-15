package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface RestoreCheckRuntimeResult {
    data object NotRestoreCheckOperation : RestoreCheckRuntimeResult
    data object TransportRequired : RestoreCheckRuntimeResult
    data class Rejected(val failure: RestoreCheckFailure) : RestoreCheckRuntimeResult
    data class AwaitingVerification(val revision: OperationRevision) : RestoreCheckRuntimeResult
    data class Reviewed(val binding: RestoreCheckBinding, val revision: OperationRevision) : RestoreCheckRuntimeResult
    data class Failed(val revision: OperationRevision) : RestoreCheckRuntimeResult
    data class Completed(val receipt: RestoreCheckReceipt, val revision: OperationRevision,
        val installation: VersionedRecord<XuiInstallation>, val access: ServerAccess) : RestoreCheckRuntimeResult
}

fun interface RestoreCheckSourcePort {
    suspend fun read(scope: ManagementScope, binding: InstallationBackupBinding, session: SshSessionHandle): InstallationBackupReceipt?
}
fun interface RestoreCheckStoragePort {
    suspend fun read(scope: ManagementScope, binding: RestoreCheckBinding, session: SshSessionHandle): InstallationBackupStorageObservation?
}
fun interface RestoreCheckCopyPort {
    suspend fun copy(dispatch: VerifiedRestoreCheckDispatch, current: VersionedOperationSnapshot, session: SshSessionHandle): RestoreCheckCopyResult
}
fun interface RestoreCheckVerifyPort {
    suspend fun verify(scope: ManagementScope, binding: RestoreCheckBinding, session: SshSessionHandle): RestoreCheckReceipt?
}

/** One shared runtime consumer. Confirmation is bounded process state; truth stays in the existing journal. */
class RestoreCheckRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installations: XuiInstallationRepository?,
    private val links: ManagementAccessRepository?,
    private val accesses: ServerAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessions: ExactSessionRegistry,
    private val mutations: ServerMutationLeaseRegistry,
    private val now: () -> Instant = Instant::now,
    private val source: RestoreCheckSourcePort = RestoreCheckSourcePort { scope, binding, session -> InstallationBackupSshAdapter().verify(scope, binding, session) },
    private val storage: RestoreCheckStoragePort = RestoreCheckStoragePort { scope, binding, session -> RestoreCheckSshAdapter().storage(scope, binding, session) },
    private val copy: RestoreCheckCopyPort = RestoreCheckCopyPort { dispatch, current, session -> RestoreCheckSshAdapter().copy(dispatch, current, session) },
    private val verify: RestoreCheckVerifyPort = RestoreCheckVerifyPort { scope, binding, session -> RestoreCheckSshAdapter().verify(scope, binding, session) },
) {
    private val confirmations = linkedMapOf<OperationId, RestoreCheckConfirmation>()
    @Synchronized fun register(confirmation: RestoreCheckConfirmation): Boolean {
        confirmations.entries.removeAll { !now().isBefore(it.value.validUntil) }
        if (confirmations.size >= 8 || confirmations.containsKey(confirmation.operationId) || !now().isBefore(confirmation.validUntil)) return false
        confirmations[confirmation.operationId] = confirmation
        return true
    }
    @Synchronized fun discard(operationId: OperationId): Boolean = confirmations.remove(operationId) != null
    @Synchronized private fun confirmation(current: VersionedOperationSnapshot, consume: Boolean): RestoreCheckConfirmation? {
        val c = if (consume) confirmations.remove(current.snapshot.operationId) else confirmations[current.snapshot.operationId]
        return c?.takeIf { it.revision == current.revision && it.target == current.snapshot.target &&
            !now().isBefore(current.snapshot.updatedAt) && now().isBefore(it.validUntil) }
    }
    suspend fun prepare(admission: RecoveryRuntimeAdmission): RestoreCheckRuntimeResult {
        val current = read(admission) ?: return reject(RestoreCheckFailure.JOURNAL)
        if (current.snapshot.type != OperationType.INSTALLATION_RESTORE_CHECK) return RestoreCheckRuntimeResult.NotRestoreCheckOperation
        val exact = exactRecords(current) ?: return reject(RestoreCheckFailure.EXACT_TARGET)
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return reject(RestoreCheckFailure.SESSION)
        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.READ_ONLY -> if (RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName)?.first == RestoreCheckPhase.SOURCE_PENDING)
                RestoreCheckRuntimeResult.TransportRequired else reject(RestoreCheckFailure.JOURNAL)
            CheckpointSemantics.MUTATION_NOT_STARTED -> if (confirmation(current, false)?.let {
                it.installation == exact.first.value && it.access == exact.second
            } == true) RestoreCheckRuntimeResult.TransportRequired else reject(RestoreCheckFailure.AUTHORITY_MISSING)
            CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED -> RestoreCheckRuntimeResult.TransportRequired
            else -> reject(RestoreCheckFailure.JOURNAL)
        }
    }

    suspend fun execute(admission: RecoveryRuntimeAdmission, binding: SessionBinding): RestoreCheckRuntimeResult {
        var current = read(admission) ?: return reject(RestoreCheckFailure.JOURNAL)
        if (current.snapshot.type != OperationType.INSTALLATION_RESTORE_CHECK) return RestoreCheckRuntimeResult.NotRestoreCheckOperation
        val records = exactRecords(current) ?: return reject(RestoreCheckFailure.EXACT_TARGET)
        val target = current.snapshot.target as OperationTarget.InstallationTarget
        val scope = ManagementScope(current.snapshot.operationId, target.serverId, target.serverAccessId, target.installationId)
        val parsed = RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName) ?: return reject(RestoreCheckFailure.JOURNAL)
        val session = sessions.find(SessionOwner.Operation(scope.operationId), scope.serverAccessId)
            ?.takeIf { it.isOpen && it.binding == binding } ?: return reject(RestoreCheckFailure.SESSION)
        if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
        val acquisition = mutations.tryAcquire(scope.serverId, scope.operationId) as? ServerMutationAcquireResult.Acquired
            ?: return reject(RestoreCheckFailure.PRECHECK)
        try {
            if (parsed.first == RestoreCheckPhase.SOURCE_PENDING && current.snapshot.checkpoint.semantics == CheckpointSemantics.READ_ONLY) {
                val barriers = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(RestoreCheckFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, barriers.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed)
                    return reject(RestoreCheckFailure.PRECHECK)
                val receipt = source.read(scope, parsed.second.source, session)
                if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
                if (receipt == null || receipt.scope != scope || receipt.binding != parsed.second.source ||
                    receipt.verifiedAt.isBefore(current.snapshot.updatedAt) || receipt.verifiedAt.isAfter(now())) return failPending(current, parsed.second)
                val reviewed = RestoreCheckBindingPolicy.bind(scope.operationId, records.first.value, records.second, records.third,
                    receipt.sha256, receipt.databaseSha256, receipt.inventorySha256, receipt.sizeBytes, receipt.fileCount)
                current = advance(current, reviewed, RestoreCheckPhase.REVIEWED, CheckpointSemantics.MUTATION_NOT_STARTED,
                    OperationStatus.RUNNING) ?: return reject(RestoreCheckFailure.JOURNAL)
                return RestoreCheckRuntimeResult.Reviewed(reviewed, current.revision)
            }
            if (current.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) {
                val c = confirmation(current, true) ?: return reject(RestoreCheckFailure.AUTHORITY_MISSING)
                val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(RestoreCheckFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, all.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed)
                    return reject(RestoreCheckFailure.PRECHECK)
                val space = storage.read(scope, parsed.second, session) ?: return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
                val dispatch = RestoreCheckDispatchPolicy.authorize(c, current, space, now())
                    ?: return failPending(current, parsed.second)
                val latestBarrier = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(RestoreCheckFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, latestBarrier.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
                    !valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.PRECHECK)
                // CAS is durable before the first possible write; no recovery branch can dispatch again.
                current = advance(current, parsed.second, RestoreCheckPhase.COPYING,
                    CheckpointSemantics.MUTATION_IN_FLIGHT, OperationStatus.RUNNING) ?: return reject(RestoreCheckFailure.JOURNAL)
                if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
                val result = copy.copy(dispatch, current, session)
                if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
                val phase = when (result) {
                    RestoreCheckCopyResult.FINISHED -> RestoreCheckPhase.FINISHED
                    RestoreCheckCopyResult.FAILED -> RestoreCheckPhase.COMMAND_FAILED
                    RestoreCheckCopyResult.REJECTED, RestoreCheckCopyResult.UNCERTAIN -> RestoreCheckPhase.UNCERTAIN
                }
                current = advance(current, parsed.second, phase, CheckpointSemantics.POST_VERIFY_REQUIRED,
                    OperationStatus.RECONCILIATION_REQUIRED) ?: return reject(RestoreCheckFailure.JOURNAL)
                return RestoreCheckRuntimeResult.AwaitingVerification(current.revision)
            } else if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,
                    CheckpointSemantics.POST_VERIFY_REQUIRED)) return reject(RestoreCheckFailure.JOURNAL)
            // This branch is the ONLY resumption path. It holds no fresh copy authority.
            if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
            val receipt = verify.verify(scope, parsed.second, session)
            if (!valid(admission, current, records, session, binding)) return reject(RestoreCheckFailure.EXACT_TARGET)
            if (receipt != null && receipt.scope == scope && receipt.binding == parsed.second &&
                !receipt.verifiedAt.isBefore(current.snapshot.updatedAt) && !receipt.verifiedAt.isAfter(now())) {
                val committed = advance(current, parsed.second, RestoreCheckPhase.VERIFIED,
                    CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED) ?: return reject(RestoreCheckFailure.JOURNAL)
                return RestoreCheckRuntimeResult.Completed(receipt, committed.revision, records.first, records.second)
            }
            // Confirmed command failure may be closed. Absence after uncertain dispatch cannot be.
            if (RestoreCheckBinding.parse(current.snapshot.checkpoint.phaseName)?.first == RestoreCheckPhase.COMMAND_FAILED) {
                val failed = advance(current, parsed.second, RestoreCheckPhase.FAILED,
                    CheckpointSemantics.TERMINAL, OperationStatus.FAILED) ?: return reject(RestoreCheckFailure.JOURNAL)
                return RestoreCheckRuntimeResult.Failed(failed.revision)
            }
            return RestoreCheckRuntimeResult.AwaitingVerification(current.revision)
        } finally { mutations.release(acquisition.lease) }
    }

    private suspend fun failPending(current: VersionedOperationSnapshot, b: RestoreCheckBinding): RestoreCheckRuntimeResult {
        val failed = advance(current, b, RestoreCheckPhase.FAILED, CheckpointSemantics.TERMINAL, OperationStatus.FAILED)
            ?: return reject(RestoreCheckFailure.JOURNAL)
        return RestoreCheckRuntimeResult.Failed(failed.revision)
    }
    private suspend fun read(admission: RecoveryRuntimeAdmission): VersionedOperationSnapshot? {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return null
        val current = (journal.get(admission.plan.operationId) as? OperationJournalResult.Success)?.value ?: return null
        return current.takeIf { it.revision == admission.plan.expectedRevision && it.snapshot.target == admission.plan.target }
    }
    private suspend fun exactRecords(current: VersionedOperationSnapshot): Triple<VersionedRecord<XuiInstallation>, ServerAccess, VersionedOperationSnapshot>? {
        val s = current.snapshot
        if (s.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)) return null
        val t = s.target as? OperationTarget.InstallationTarget ?: return null
        val installation = (installations?.get(t.installationId) as? RepositoryResult.Success)?.value ?: return null
        val access = (accesses.get(t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        val binding = RestoreCheckBinding.parse(s.checkpoint.phaseName)?.second ?: return null
        val parent = (journal.get(binding.sourceOperationId) as? OperationJournalResult.Success)?.value ?: return null
        val link = (links?.get(t.installationId, t.serverAccessId) as? RepositoryResult.Success)?.value ?: return null
        if (link.installationId != t.installationId || link.serverAccessId != t.serverAccessId ||
            !RestoreCheckBindingPolicy.matches(current, installation.value, access, parent)) return null
        return Triple(installation, access, parent)
    }
    private suspend fun valid(admission: RecoveryRuntimeAdmission, current: VersionedOperationSnapshot,
        records: Triple<VersionedRecord<XuiInstallation>, ServerAccess, VersionedOperationSnapshot>, session: SshSessionHandle, binding: SessionBinding): Boolean {
        currentCoroutineContext().ensureActive()
        if (!runtimeRegistry.isCurrent(admission.runtimeLease) || !session.isOpen || session.binding != binding ||
            binding.owner != SessionOwner.Operation(current.snapshot.operationId) ||
            binding.serverAccessId != current.snapshot.target.serverAccessId ||
            sessions.find(binding.owner, binding.serverAccessId) !== session) return false
        val latest = (journal.get(current.snapshot.operationId) as? OperationJournalResult.Success)?.value ?: return false
        return latest == current && exactRecords(current) == records
    }
    private suspend fun advance(current: VersionedOperationSnapshot, b: RestoreCheckBinding, phase: RestoreCheckPhase,
        semantics: CheckpointSemantics, status: OperationStatus): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(status = status, checkpoint = OperationCheckpoint(b.phaseName(phase), semantics, at), updatedAt = at)
        return (journal.advance(current.snapshot.operationId, current.revision, next) as? OperationJournalResult.Success)?.value
    }
    private fun reject(failure: RestoreCheckFailure) = RestoreCheckRuntimeResult.Rejected(failure)
}
