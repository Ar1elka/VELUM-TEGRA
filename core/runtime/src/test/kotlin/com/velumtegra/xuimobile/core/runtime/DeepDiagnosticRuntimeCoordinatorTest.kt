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
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
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
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.CapturedOutput
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.DeepDiagnosticSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeepDiagnosticRuntimeCoordinatorTest {
    private val operationId = OperationId("deep-runtime-op")
    private val serverId = ServerId("deep-runtime-server")
    private val accessId = ServerAccessId("deep-runtime-access")
    private val installationId = XuiInstallationId("deep-runtime-installation")
    private val startedAt = Instant.parse("2026-09-06T16:50:00Z")

    @Test
    fun `non deep operation is not consumed and runs no remote command`() = runSuspend {
        val fixture = Fixture(operationType = OperationType.QUICK_INSPECT)
        val result = fixture.coordinator.execute(fixture.admission, fixture.expectedBinding)

        assertEquals(
            DeepDiagnosticRuntimeExecutionResult.NotDeepDiagnosticOperation(OperationType.QUICK_INSPECT),
            result,
        )
        assertEquals(0, fixture.handle.executedLabels.size)
    }


    @Test
    fun `non deep installer post verify checkpoint is typed not applicable before deep checkpoint validation`() = runSuspend {
        val fixture = Fixture(
            operationType = OperationType.INSTALL,
            checkpointSemantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.expectedBinding)

        assertEquals(
            DeepDiagnosticRuntimeExecutionResult.NotDeepDiagnosticOperation(OperationType.INSTALL),
            result,
        )
        assertEquals(0, fixture.handle.executedLabels.size)
    }

    @Test
    fun `missing exact ManagementAccess fails before remote command`() = runSuspend {
        val fixture = Fixture(accessResult = RepositoryResult.NotFound)
        val result = fixture.coordinator.execute(fixture.admission, fixture.expectedBinding)

        assertTrue(result is DeepDiagnosticRuntimeExecutionResult.ContractViolation)
        assertEquals(0, fixture.handle.executedLabels.size)
    }

    @Test
    fun `stale caller SessionId is rejected before remote command`() = runSuspend {
        val fixture = Fixture()
        val stale = fixture.expectedBinding.copy(sessionId = SessionId("stale-session"))
        val result = fixture.coordinator.execute(fixture.admission, stale)

        assertTrue(result is DeepDiagnosticRuntimeExecutionResult.StaleSession)
        assertEquals(0, fixture.handle.executedLabels.size)
    }

    @Test
    fun `successful deep diagnostic uses same exact session and commits one generic terminal`() = runSuspend {
        val fixture = Fixture()
        val result = fixture.coordinator.execute(fixture.admission, fixture.expectedBinding)

        assertTrue(result is DeepDiagnosticRuntimeExecutionResult.Completed)
        result as DeepDiagnosticRuntimeExecutionResult.Completed
        assertEquals(DeepDiagnosticOverallStatus.HEALTHY, result.snapshot.overallStatus)
        assertEquals(12, fixture.handle.executedLabels.size)
        assertEquals(
            listOf(
                "management-service-presence",
                "management-path-presence",
                "management-path-presence",
                "management-path-presence",
                "management-service-state",
                "management-panel-settings",
                "management-listener-presence",
                "deep-service-definition",
                "deep-binary-version",
                "deep-database-quick-check",
                "deep-database-schema",
                "deep-certificate-references",
            ),
            fixture.handle.executedLabels,
        )
        assertEquals(OperationStatus.SUCCEEDED, fixture.journal.current.snapshot.status)
        assertEquals("DEEP_DIAGNOSTIC_RESULT", fixture.journal.current.snapshot.checkpoint.phaseName)
        assertEquals(CheckpointSemantics.TERMINAL, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(OperationRevision(1), result.committedRevision)
    }

    private inner class Fixture(
        operationType: OperationType = OperationType.DEEP_DIAGNOSTIC,
        checkpointSemantics: CheckpointSemantics = CheckpointSemantics.READ_ONLY,
        accessResult: RepositoryResult<ManagementAccess> = RepositoryResult.Success(
            ManagementAccess(installationId, accessId),
        ),
    ) {
        val journal = FakeJournal(operationType, checkpointSemantics)
        private val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val sessionRegistry = ExactSessionRegistry()
        val handle = ScriptedHandle(
            SessionBinding(
                sessionId = SessionId("deep-runtime-session"),
                serverAccessId = accessId,
                owner = SessionOwner.Operation(operationId),
            ),
        )
        val expectedBinding = handle.binding
        val admission: RecoveryRuntimeAdmission
        val coordinator: DeepDiagnosticRuntimeCoordinator

        init {
            val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
            admission = RecoveryRuntimeAdmission(
                plan = ColdStartRecoveryPlan(
                    operationId = operationId,
                    target = journal.current.snapshot.target,
                    expectedRevision = journal.current.revision,
                    action = RecoveryAction.RECONNECT_EXACT_OWNER,
                    automaticAllowed = true,
                ),
                runtimeLease = lease,
            )
            sessionRegistry.install(handle)
            coordinator = DeepDiagnosticRuntimeCoordinator(
                journal = journal,
                installationRepository = FakeInstallationRepository(),
                managementAccessRepository = FakeManagementAccessRepository(accessResult),
                runtimeRegistry = runtimeRegistry,
                sessionRegistry = sessionRegistry,
                managementExecutor = ManagementSshProbeExecutor { startedAt.plusSeconds(1) },
                deepExecutor = DeepDiagnosticSshProbeExecutor { startedAt.plusSeconds(2) },
                now = { startedAt.plusSeconds(3) },
                proofIdFactory = { TargetProofId("deep-runtime-proof") },
            )
        }
    }

    private inner class FakeJournal(
        operationType: OperationType,
        checkpointSemantics: CheckpointSemantics,
    ) : OperationJournal {
        var current = VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = operationId,
                type = operationType,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = if (operationType == OperationType.DEEP_DIAGNOSTIC) "DEEP_DIAGNOSTIC" else "OTHER",
                    semantics = checkpointSemantics,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            ),
            revision = OperationRevision(0),
        )

        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.AlreadyExists
        override suspend fun get(operationId: OperationId) =
            if (operationId == this@DeepDiagnosticRuntimeCoordinatorTest.operationId) {
                OperationJournalResult.Success(current)
            } else {
                OperationJournalResult.NotFound
            }
        override suspend fun listNonTerminal() = OperationJournalResult.Success(listOf(current))
        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            if (expectedRevision != current.revision) {
                return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            }
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
    }

    private inner class FakeInstallationRepository : XuiInstallationRepository {
        private val versioned = VersionedRecord(installation(), RecordRevision(1))
        override suspend fun get(installationId: XuiInstallationId) =
            if (installationId == this@DeepDiagnosticRuntimeCoordinatorTest.installationId) {
                RepositoryResult.Success(versioned)
            } else RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(versioned))
        override suspend fun create(installation: XuiInstallation) = RepositoryResult.ConstraintConflict("unused")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = RepositoryResult.ConstraintConflict("unused")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = RepositoryResult.ConstraintConflict("unused")
    }

    private inner class FakeManagementAccessRepository(
        private val result: RepositoryResult<ManagementAccess>,
    ) : ManagementAccessRepository {
        override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = result
        override suspend fun listForInstallation(installationId: XuiInstallationId) = RepositoryResult.Success(emptyList<ManagementAccess>())
        override suspend fun listForServerAccess(serverAccessId: ServerAccessId) = RepositoryResult.Success(emptyList<ManagementAccess>())
        override suspend fun create(access: ManagementAccess) = RepositoryResult.ConstraintConflict("unused")
        override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = RepositoryResult.ConstraintConflict("unused")
    }

    private fun installation() = XuiInstallation(
        id = installationId,
        serverId = serverId,
        ownership = InstallationOwnership.ADOPTED,
        identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = null,
        ),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = 54321,
            webBasePath = "/panel/",
            listenAddress = null,
            capturedAt = startedAt.minusSeconds(60),
        ),
    )

    private class ScriptedHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        override var isOpen: Boolean = true
        val executedLabels = mutableListOf<String>()

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executedLabels += command.redactedLabel
            val stdout = when (command.redactedLabel) {
                "management-service-state" -> "active\n"
                "management-panel-settings" -> "PORT=54321\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=\n"
                "deep-service-definition" -> "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; }\n"
                "deep-binary-version" -> "2.6.8\n"
                "deep-database-quick-check" -> "ok\n"
                "deep-database-schema" -> "SUPPORTED\n"
                "deep-certificate-references" -> "CERT=\nKEY=\n"
                else -> ""
            }
            return SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = CommandCompletion.ConfirmedSuccess,
                stdout = CapturedOutput.of(stdout.toByteArray(), truncated = false),
                stderr = CapturedOutput.EMPTY,
            )
        }

        override fun close() { isOpen = false }
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext
            override fun resumeWith(result: Result<T>) { outcome = result }
        })
        return checkNotNull(outcome).getOrThrow()
    }
}
