package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallVerificationDecision
import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteFailure
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteReconciliation
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteVerificationResult
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteVerifier
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.time.Instant

/**
 * Phase 8.5 local coordinator. Remote work reachable here is read-only verification only.
 * `XuiInstallation + ManagementAccess` publication is delegated to one atomic publisher boundary;
 * no WebPanelAccess is created and no installer command can be replayed from this component.
 */
class InstallerPostInstallCoordinator(
    private val remoteVerifier: InstallerPostInstallRemoteVerifier,
    private val publisher: ManagementEnrollmentPublisher,
    private val journal: OperationJournal,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun reconcileAndPublish(
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerPostInstallCoordinatorResult {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.ServerTarget
            ?: return InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.ScopeTargetMismatch,
            )
        if (snapshot.type != OperationType.INSTALL) {
            return InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.ScopeTargetMismatch,
            )
        }

        if (snapshot.checkpoint.semantics == CheckpointSemantics.COMMIT_VERIFIED) {
            return finishCommitted(current)
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.POST_VERIFY_REQUIRED ||
            snapshot.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)
        ) {
            return InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.NotAtPostVerifyBoundary,
            )
        }

        val scope = InstallerWorkerScope(
            operationId = snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            managedInstallId = ManagedInstallIdentityPolicy.forOperation(snapshot.operationId),
        )

        when (val remote = remoteVerifier.verify(scope, session)) {
            is InstallerPostInstallRemoteVerificationResult.WorkerStillRunning -> {
                return InstallerPostInstallCoordinatorResult.AwaitingWorker(current)
            }
            is InstallerPostInstallRemoteVerificationResult.Rejected -> {
                val reason = when (remote.failure) {
                    InstallerPostInstallRemoteFailure.ExactSessionBindingMismatch ->
                        InstallerPostInstallReconciliationReason.EXACT_SESSION_BINDING_MISMATCH
                    InstallerPostInstallRemoteFailure.SessionClosed ->
                        InstallerPostInstallReconciliationReason.SESSION_CLOSED
                }
                return recordReconciliation(current, reason)
            }
            is InstallerPostInstallRemoteVerificationResult.ReconciliationRequired -> {
                val reason = when (remote.reason) {
                    InstallerPostInstallRemoteReconciliation.WORKER_EVIDENCE_UNREADABLE ->
                        InstallerPostInstallReconciliationReason.WORKER_EVIDENCE_UNREADABLE
                    InstallerPostInstallRemoteReconciliation.WORKER_TERMINAL_FAILURE ->
                        InstallerPostInstallReconciliationReason.WORKER_TERMINAL_FAILURE
                    InstallerPostInstallRemoteReconciliation.WORKER_DIED_WITHOUT_SUCCESS ->
                        InstallerPostInstallReconciliationReason.WORKER_DIED_WITHOUT_SUCCESS
                    InstallerPostInstallRemoteReconciliation.WORKER_STATE_UNKNOWN ->
                        InstallerPostInstallReconciliationReason.WORKER_STATE_UNKNOWN
                    InstallerPostInstallRemoteReconciliation.MANAGED_MARKER_UNREADABLE ->
                        InstallerPostInstallReconciliationReason.MANAGED_MARKER_UNREADABLE
                    InstallerPostInstallRemoteReconciliation.INSTALLATION_FACTS_UNREADABLE ->
                        InstallerPostInstallReconciliationReason.INSTALLATION_FACTS_UNREADABLE
                }
                return recordReconciliation(current, reason)
            }
            is InstallerPostInstallRemoteVerificationResult.Verified -> {
                val decision = InstallerPostInstallPolicy.verify(scope, remote.facts)
                val request = when (decision) {
                    is InstallerPostInstallVerificationDecision.Verified -> decision.request
                    is InstallerPostInstallVerificationDecision.Rejected -> {
                        return recordReconciliation(
                            current,
                            InstallerPostInstallReconciliationReason.REMOTE_FACTS_REJECTED,
                        )
                    }
                }

                when (val publication = publisher.publishInstaller(request)) {
                    is ManagementEnrollmentPublicationResult.Published -> {
                        val committed = advanceCommitVerified(current)
                            ?: return recordReconciliation(
                                current,
                                InstallerPostInstallReconciliationReason.COMMIT_CHECKPOINT_FAILED,
                            )
                        return finishTerminal(
                            committed,
                            publication.installation.value.id,
                        )
                    }
                    is ManagementEnrollmentPublicationResult.Rejected -> {
                        return recordReconciliation(
                            current,
                            InstallerPostInstallReconciliationReason.LOCAL_PUBLICATION_REJECTED,
                        )
                    }
                    ManagementEnrollmentPublicationResult.Corruption -> {
                        return recordReconciliation(
                            current,
                            InstallerPostInstallReconciliationReason.LOCAL_PUBLICATION_CORRUPTION,
                        )
                    }
                    ManagementEnrollmentPublicationResult.StorageFailure -> {
                        return recordReconciliation(
                            current,
                            InstallerPostInstallReconciliationReason.LOCAL_PUBLICATION_STORAGE_FAILURE,
                        )
                    }
                }
            }
        }
    }

    /**
     * Finish the crash-safe local commit boundary without requiring an SSH session.
     *
     * Phase 8.5 already made COMMIT_VERIFIED authoritative local evidence. Phase 8.7 runtime
     * recovery calls this before transport so process death between publication and terminalization
     * never causes an unnecessary reconnect and can never replay the remote installer.
     */
    suspend fun finishCommitted(
        current: VersionedOperationSnapshot,
    ): InstallerPostInstallCoordinatorResult {
        val snapshot = current.snapshot
        if (snapshot.type != OperationType.INSTALL || snapshot.target !is OperationTarget.ServerTarget) {
            return InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.ScopeTargetMismatch,
            )
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.COMMIT_VERIFIED ||
            snapshot.status != OperationStatus.RUNNING
        ) {
            return InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.NotAtCommitBoundary,
            )
        }
        return finishTerminal(current)
    }

    private suspend fun advanceCommitVerified(
        current: VersionedOperationSnapshot,
    ): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "INSTALLER_COMMIT_VERIFIED",
                semantics = CheckpointSemantics.COMMIT_VERIFIED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val result = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> result.value
            else -> null
        }
    }

    private suspend fun finishTerminal(
        current: VersionedOperationSnapshot,
        installationId: XuiInstallationId? = null,
    ): InstallerPostInstallCoordinatorResult {
        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.COMMIT_VERIFIED) {
            return InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.NotAtCommitBoundary,
            )
        }
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return InstallerPostInstallCoordinatorResult.ReconciliationRequired(
                durable = current,
                reason = InstallerPostInstallReconciliationReason.TERMINAL_CHECKPOINT_FAILED,
                reconciliationCheckpointRecorded = false,
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.SUCCEEDED,
            checkpoint = OperationCheckpoint(
                phaseName = "INSTALLER_RESULT_SUCCESS",
                semantics = CheckpointSemantics.TERMINAL,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val result = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> InstallerPostInstallCoordinatorResult.Succeeded(
                durable = result.value,
                installationId = installationId ?: deterministicInstallationId(current),
            )
            else -> InstallerPostInstallCoordinatorResult.ReconciliationRequired(
                durable = current,
                reason = InstallerPostInstallReconciliationReason.TERMINAL_CHECKPOINT_FAILED,
                reconciliationCheckpointRecorded = false,
            )
        }
    }

    private fun deterministicInstallationId(current: VersionedOperationSnapshot): XuiInstallationId {
        val target = current.snapshot.target as OperationTarget.ServerTarget
        val scope = InstallerWorkerScope(
            operationId = current.snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            managedInstallId = ManagedInstallIdentityPolicy.forOperation(current.snapshot.operationId),
        )
        return InstallerPostInstallPolicy.installationIdFor(scope)
    }

    private suspend fun recordReconciliation(
        current: VersionedOperationSnapshot,
        reason: InstallerPostInstallReconciliationReason,
    ): InstallerPostInstallCoordinatorResult.ReconciliationRequired {
        val at = now()
        val next = if (at.isBefore(current.snapshot.updatedAt)) {
            null
        } else {
            current.snapshot.copy(
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(
                    phaseName = "INSTALLER_POST_VERIFY_RECONCILIATION_REQUIRED",
                    semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                    recordedAt = at,
                ),
                updatedAt = at,
            )
        }
        val recorded = if (next == null) {
            null
        } else {
            when (val result = journal.advance(current.snapshot.operationId, current.revision, next)) {
                is OperationJournalResult.Success -> result.value
                else -> null
            }
        }
        return InstallerPostInstallCoordinatorResult.ReconciliationRequired(
            durable = recorded ?: current,
            reason = reason,
            reconciliationCheckpointRecorded = recorded != null,
        )
    }
}

sealed interface InstallerPostInstallCoordinatorResult {
    data class Succeeded(
        val durable: VersionedOperationSnapshot,
        val installationId: XuiInstallationId,
    ) : InstallerPostInstallCoordinatorResult

    data class AwaitingWorker(
        val durable: VersionedOperationSnapshot,
    ) : InstallerPostInstallCoordinatorResult

    data class ReconciliationRequired(
        val durable: VersionedOperationSnapshot,
        val reason: InstallerPostInstallReconciliationReason,
        val reconciliationCheckpointRecorded: Boolean,
    ) : InstallerPostInstallCoordinatorResult

    data class Rejected(
        val failure: InstallerPostInstallCoordinatorFailure,
    ) : InstallerPostInstallCoordinatorResult
}

enum class InstallerPostInstallCoordinatorFailure {
    ScopeTargetMismatch,
    NotAtPostVerifyBoundary,
    NotAtCommitBoundary,
}

enum class InstallerPostInstallReconciliationReason {
    EXACT_SESSION_BINDING_MISMATCH,
    SESSION_CLOSED,
    WORKER_EVIDENCE_UNREADABLE,
    WORKER_TERMINAL_FAILURE,
    WORKER_DIED_WITHOUT_SUCCESS,
    WORKER_STATE_UNKNOWN,
    MANAGED_MARKER_UNREADABLE,
    INSTALLATION_FACTS_UNREADABLE,
    REMOTE_FACTS_REJECTED,
    LOCAL_PUBLICATION_REJECTED,
    LOCAL_PUBLICATION_CORRUPTION,
    LOCAL_PUBLICATION_STORAGE_FAILURE,
    COMMIT_CHECKPOINT_FAILED,
    TERMINAL_CHECKPOINT_FAILED,
}
