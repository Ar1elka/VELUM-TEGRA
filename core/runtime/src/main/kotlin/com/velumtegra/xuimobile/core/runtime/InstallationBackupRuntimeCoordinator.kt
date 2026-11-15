package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface InstallationBackupRuntimeResult {
    data object NotInstallationBackupOperation : InstallationBackupRuntimeResult
    data object TransportRequired : InstallationBackupRuntimeResult
    data class Rejected(val failure: InstallationBackupFailure) : InstallationBackupRuntimeResult
    data class AwaitingVerification(val revision: OperationRevision) : InstallationBackupRuntimeResult
    data class Failed(val revision: OperationRevision) : InstallationBackupRuntimeResult
    data class Completed(val receipt: InstallationBackupReceipt, val revision: OperationRevision,
        val installation: VersionedRecord<XuiInstallation>, val access: ServerAccess) : InstallationBackupRuntimeResult
}

fun interface InstallationBackupPreflightPort {
    suspend fun read(scope: ManagementScope, installation: XuiInstallation, session: SshSessionHandle): UpdatePreflightSnapshot?
}
fun interface InstallationBackupStoragePort {
    suspend fun read(scope: ManagementScope, session: SshSessionHandle): InstallationBackupStorageObservation?
}
fun interface InstallationBackupCopyPort {
    suspend fun copy(dispatch: VerifiedInstallationBackupDispatch, current: VersionedOperationSnapshot, session: SshSessionHandle): InstallationBackupCopyResult
}
fun interface InstallationBackupVerifyPort {
    suspend fun verify(scope: ManagementScope, binding: InstallationBackupBinding, session: SshSessionHandle): InstallationBackupReceipt?
}

/** One shared runtime consumer. Confirmation is bounded process state; truth stays in the existing journal. */
class InstallationBackupRuntimeCoordinator(
    private val journal: OperationJournal,
    private val installations: XuiInstallationRepository?,
    private val links: ManagementAccessRepository?,
    private val accesses: ServerAccessRepository,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessions: ExactSessionRegistry,
    private val mutations: ServerMutationLeaseRegistry,
    private val now: () -> Instant = Instant::now,
    private val preflight: InstallationBackupPreflightPort = InstallationBackupPreflightPort { scope, installation, session ->
        val run = ManagementSshProbeExecutor().executeQuickInspect(scope, installation, session)
        val evidence = (run as? ManagementSshProbeRunResult.Completed)?.evidence
        val management = evidence?.let { ManagementReadbackPolicy.quickInspect(installation, it,
            TargetProofId(UUID.randomUUID().toString()), Instant.now()) } ?: return@InstallationBackupPreflightPort null
        if (management.identityStatus != ManagementIdentityStatus.Matched) null else
            (UpdatePreflightSshReader().read(scope, installation, session, management, includeRecoveryFiles = true) as? UpdatePreflightSshResult.Completed)?.snapshot
    },
    private val storage: InstallationBackupStoragePort = InstallationBackupStoragePort { scope, session -> InstallationBackupSshAdapter().storage(scope, session) },
    private val copy: InstallationBackupCopyPort = InstallationBackupCopyPort { dispatch, current, session -> InstallationBackupSshAdapter().copy(dispatch, current, session) },
    private val verify: InstallationBackupVerifyPort = InstallationBackupVerifyPort { scope, binding, session -> InstallationBackupSshAdapter().verify(scope, binding, session) },
    private val slots: BackupSlotInventoryRegistry = BackupSlotInventoryRegistry(),
) {
    private val confirmations = linkedMapOf<OperationId, InstallationBackupConfirmation>()
    @Synchronized fun register(confirmation: InstallationBackupConfirmation): Boolean {
        confirmations.entries.removeAll { !now().isBefore(it.value.validUntil) }
        if (confirmations.size >= 8 || confirmations.containsKey(confirmation.operationId) || !now().isBefore(confirmation.validUntil)) return false
        confirmations[confirmation.operationId] = confirmation
        return true
    }
    @Synchronized fun discard(operationId: OperationId): Boolean = confirmations.remove(operationId) != null
    @Synchronized private fun confirmation(current: VersionedOperationSnapshot, consume: Boolean): InstallationBackupConfirmation? {
        val c = if (consume) confirmations.remove(current.snapshot.operationId) else confirmations[current.snapshot.operationId]
        return c?.takeIf { it.revision == current.revision && it.target == current.snapshot.target &&
            !now().isBefore(current.snapshot.updatedAt) && now().isBefore(it.validUntil) }
    }
    suspend fun prepare(admission: RecoveryRuntimeAdmission): InstallationBackupRuntimeResult {
        val current = read(admission) ?: return reject(InstallationBackupFailure.JOURNAL)
        if (current.snapshot.type != OperationType.INSTALLATION_BACKUP) return InstallationBackupRuntimeResult.NotInstallationBackupOperation
        val exact = exactRecords(current) ?: return reject(InstallationBackupFailure.EXACT_TARGET)
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return reject(InstallationBackupFailure.SESSION)
        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> if (confirmation(current, false)?.let {
                it.installation == exact.first.value && it.access == exact.second
            } == true) InstallationBackupRuntimeResult.TransportRequired else reject(InstallationBackupFailure.AUTHORITY_MISSING)
            CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED -> InstallationBackupRuntimeResult.TransportRequired
            else -> reject(InstallationBackupFailure.JOURNAL)
        }
    }

    suspend fun execute(admission: RecoveryRuntimeAdmission, binding: SessionBinding): InstallationBackupRuntimeResult {
        var current = read(admission) ?: return reject(InstallationBackupFailure.JOURNAL)
        if (current.snapshot.type != OperationType.INSTALLATION_BACKUP) return InstallationBackupRuntimeResult.NotInstallationBackupOperation
        val records = exactRecords(current) ?: return reject(InstallationBackupFailure.EXACT_TARGET)
        val target = current.snapshot.target as OperationTarget.InstallationTarget
        val scope = ManagementScope(current.snapshot.operationId, target.serverId, target.serverAccessId, target.installationId)
        val parsed = InstallationBackupBinding.parse(current.snapshot.checkpoint.phaseName) ?: return reject(InstallationBackupFailure.JOURNAL)
        val session = sessions.find(SessionOwner.Operation(scope.operationId), scope.serverAccessId)
            ?.takeIf { it.isOpen && it.binding == binding } ?: return reject(InstallationBackupFailure.SESSION)
        if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
        val acquisition = mutations.tryAcquire(scope.serverId, scope.operationId) as? ServerMutationAcquireResult.Acquired
            ?: return reject(InstallationBackupFailure.PRECHECK)
        try {
            if (current.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) {
                val c = confirmation(current, true) ?: return reject(InstallationBackupFailure.AUTHORITY_MISSING)
                val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(InstallationBackupFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, all.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed)
                    return reject(InstallationBackupFailure.PRECHECK)
                val fresh = preflight.read(scope, records.first.value, session) ?: return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
                val space = storage.read(scope, session)
                recordSlots(scope, records.second, space)
                if (space == null) return failPending(current, parsed.second)
                if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
                val dispatch = InstallationBackupDispatchPolicy.authorize(c, current, fresh, space, now())
                    ?: return failPending(current, parsed.second)
                val latestBarrier = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: return reject(InstallationBackupFailure.JOURNAL)
                if (DurableServerMutationBarrierPolicy.evaluate(scope.serverId, latestBarrier.map { it.snapshot }) != ServerMutationBarrierDecision.Allowed ||
                    !valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.PRECHECK)
                // CAS is durable before the first possible write; no recovery branch can dispatch again.
                current = advance(current, parsed.second, InstallationBackupPhase.COPYING,
                    CheckpointSemantics.MUTATION_IN_FLIGHT, OperationStatus.RUNNING) ?: return reject(InstallationBackupFailure.JOURNAL)
                if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
                val result = copy.copy(dispatch, current, session)
                if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
                val phase = when (result) {
                    InstallationBackupCopyResult.FINISHED -> InstallationBackupPhase.FINISHED
                    InstallationBackupCopyResult.FAILED -> InstallationBackupPhase.COMMAND_FAILED
                    InstallationBackupCopyResult.REJECTED, InstallationBackupCopyResult.UNCERTAIN -> InstallationBackupPhase.UNCERTAIN
                }
                current = advance(current, parsed.second, phase, CheckpointSemantics.POST_VERIFY_REQUIRED,
                    OperationStatus.RECONCILIATION_REQUIRED) ?: return reject(InstallationBackupFailure.JOURNAL)
                return InstallationBackupRuntimeResult.AwaitingVerification(current.revision)
            } else if (current.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,
                    CheckpointSemantics.POST_VERIFY_REQUIRED)) return reject(InstallationBackupFailure.JOURNAL)
            // This branch is the ONLY resumption path. It holds no fresh copy authority.
            if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
            val receipt = verify.verify(scope, parsed.second, session)
            if (!valid(admission, current, records, session, binding)) return reject(InstallationBackupFailure.EXACT_TARGET)
            if (receipt != null && receipt.scope == scope && receipt.binding == parsed.second &&
                !receipt.verifiedAt.isBefore(current.snapshot.updatedAt) && !receipt.verifiedAt.isAfter(now())) {
                val committed = advance(current, parsed.second, InstallationBackupPhase.VERIFIED,
                    CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED) ?: return reject(InstallationBackupFailure.JOURNAL)
                return InstallationBackupRuntimeResult.Completed(receipt, committed.revision, records.first, records.second)
            }
            // Confirmed command failure may be closed. Absence after uncertain dispatch cannot be.
            if (InstallationBackupBinding.parse(current.snapshot.checkpoint.phaseName)?.first == InstallationBackupPhase.COMMAND_FAILED) {
                val failed = advance(current, parsed.second, InstallationBackupPhase.FAILED,
                    CheckpointSemantics.TERMINAL, OperationStatus.FAILED) ?: return reject(InstallationBackupFailure.JOURNAL)
                return InstallationBackupRuntimeResult.Failed(failed.revision)
            }
            return InstallationBackupRuntimeResult.AwaitingVerification(current.revision)
        } finally { mutations.release(acquisition.lease) }
    }

    /** Latest read-only slot observation for display. Never authorizes anything. */
    fun slotInventory(serverId: ServerId, profile: ServerAccess): BackupSlotInventory? = slots.latest(serverId, profile)
    private fun recordSlots(scope: ManagementScope, profile: ServerAccess, observation: InstallationBackupStorageObservation?) {
        val at = now()
        slots.record(scope.serverId, profile, observation?.takeIf { it.scope == scope }?.let {
            BackupSlotInventory.Known(it.slotsUsed, InstallationBackupBinding.MAX_SLOTS, it.observedAt) } ?: BackupSlotInventory.Unavailable(at))
    }
    private suspend fun failPending(current: VersionedOperationSnapshot, b: InstallationBackupBinding): InstallationBackupRuntimeResult {
        val failed = advance(current, b, InstallationBackupPhase.FAILED, CheckpointSemantics.TERMINAL, OperationStatus.FAILED)
            ?: return reject(InstallationBackupFailure.JOURNAL)
        return InstallationBackupRuntimeResult.Failed(failed.revision)
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
            !InstallationBackupBindingPolicy.matches(current, installation.value, access)) return null
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
    private suspend fun advance(current: VersionedOperationSnapshot, b: InstallationBackupBinding, phase: InstallationBackupPhase,
        semantics: CheckpointSemantics, status: OperationStatus): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(status = status, checkpoint = OperationCheckpoint(b.phaseName(phase), semantics, at), updatedAt = at)
        return (journal.advance(current.snapshot.operationId, current.revision, next) as? OperationJournalResult.Success)?.value
    }
    private fun reject(failure: InstallationBackupFailure) = InstallationBackupRuntimeResult.Rejected(failure)
}
