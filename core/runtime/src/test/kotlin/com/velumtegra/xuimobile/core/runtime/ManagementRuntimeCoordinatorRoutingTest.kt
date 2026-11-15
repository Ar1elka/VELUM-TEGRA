package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Test

class ManagementRuntimeCoordinatorRoutingTest {
    @Test
    fun `non quick inspect installer post verify checkpoint is typed not applicable before management checkpoint validation`() = runSuspend {
        val operationId = OperationId("management-routing-install")
        val serverId = ServerId("management-routing-server")
        val accessId = ServerAccessId("management-routing-access")
        val startedAt = Instant.parse("2026-09-12T10:00:00Z")
        val current = VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = operationId,
                type = OperationType.INSTALL,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(
                    phaseName = "POST_VERIFY",
                    semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            ),
            revision = OperationRevision(0),
        )
        val journal = SingleOperationJournal(current)
        val runtimeRegistry = OperationRuntimeLeaseRegistry()
        val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
        val admission = RecoveryRuntimeAdmission(
            plan = ColdStartRecoveryPlan(
                operationId = operationId,
                target = current.snapshot.target,
                expectedRevision = current.revision,
                action = RecoveryAction.RECONCILE_READ_ONLY,
                automaticAllowed = true,
            ),
            runtimeLease = lease,
        )
        val sessions = ExactSessionRegistry()
        val handle = NoCommandSession(
            SessionBinding(
                sessionId = SessionId("management-routing-session"),
                serverAccessId = accessId,
                owner = SessionOwner.Operation(operationId),
            ),
        )
        sessions.install(handle)
        val coordinator = ManagementRuntimeCoordinator(
            journal = journal,
            installationRepository = UnusedInstallationRepository,
            managementAccessRepository = UnusedManagementAccessRepository,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessions,
        )

        val result = coordinator.execute(admission, handle.binding)

        assertEquals(
            ManagementRuntimeExecutionResult.NotQuickInspectOperation(OperationType.INSTALL),
            result,
        )
        assertEquals(0, handle.executeCalls)
        assertEquals(OperationRevision(0), journal.current.revision)
    }

    private class SingleOperationJournal(
        var current: VersionedOperationSnapshot,
    ) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.AlreadyExists
        override suspend fun get(operationId: OperationId) =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current)
            else OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = OperationJournalResult.Success(listOf(current))
        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ) = OperationJournalResult.InvalidTransition("unused")
        override suspend fun history(operationId: OperationId) =
            OperationJournalResult.Success(emptyList<OperationJournalEntry>())
    }

    private object UnusedInstallationRepository : XuiInstallationRepository {
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
            RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> =
            RepositoryResult.Success(emptyList())
        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> =
            RepositoryResult.ConstraintConflict("unused")
        override suspend fun update(
            installation: XuiInstallation,
            expectedRevision: RecordRevision,
        ): RepositoryResult<RecordRevision> = RepositoryResult.ConstraintConflict("unused")
        override suspend fun delete(
            installationId: XuiInstallationId,
            expectedRevision: RecordRevision,
        ): RepositoryResult<Unit> = RepositoryResult.ConstraintConflict("unused")
    }

    private object UnusedManagementAccessRepository : ManagementAccessRepository {
        override suspend fun get(
            installationId: XuiInstallationId,
            serverAccessId: ServerAccessId,
        ): RepositoryResult<ManagementAccess> = RepositoryResult.NotFound
        override suspend fun listForInstallation(installationId: XuiInstallationId): RepositoryResult<List<ManagementAccess>> =
            RepositoryResult.Success(emptyList())
        override suspend fun listForServerAccess(serverAccessId: ServerAccessId): RepositoryResult<List<ManagementAccess>> =
            RepositoryResult.Success(emptyList())
        override suspend fun create(access: ManagementAccess): RepositoryResult<Unit> =
            RepositoryResult.ConstraintConflict("unused")
        override suspend fun delete(
            installationId: XuiInstallationId,
            serverAccessId: ServerAccessId,
        ): RepositoryResult<Unit> = RepositoryResult.ConstraintConflict("unused")
    }

    private class NoCommandSession(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        override var isOpen: Boolean = true
        var executeCalls: Int = 0

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executeCalls += 1
            error("Non-QUICK_INSPECT routing must not execute a Management command")
        }

        override fun close() {
            isOpen = false
        }
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext
            override fun resumeWith(result: Result<T>) {
                outcome = result
            }
        })
        return checkNotNull(outcome).getOrThrow()
    }
}
