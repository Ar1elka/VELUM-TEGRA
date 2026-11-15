package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.*
import org.junit.Test

class ServiceLogRuntimeCoordinatorTest {
    private val operationId = OperationId("logs-runtime-op")
    private val serverId = ServerId("logs-runtime-server")
    private val accessId = ServerAccessId("logs-runtime-access")
    private val installationId = XuiInstallationId("logs-runtime-installation")
    private val startedAt = Instant.parse("2026-10-15T18:00:00Z")

    @Test fun nonLogOperationRunsNoCommand() = runSuspend {
        val f = Fixture(operationType = OperationType.QUICK_INSPECT)
        assertEquals(ServiceLogRuntimeExecutionResult.NotServiceLogOperation, f.coordinator.execute(f.admission, f.expectedBinding))
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun installerPostVerifyIsNotConsumedAsALogRead() = runSuspend {
        val f = Fixture(OperationType.INSTALL, CheckpointSemantics.POST_VERIFY_REQUIRED)
        assertEquals(ServiceLogRuntimeExecutionResult.NotServiceLogOperation, f.coordinator.execute(f.admission, f.expectedBinding))
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun missingManagementBindingStopsBeforeAnyCommand() = runSuspend {
        val f = Fixture(accessResult = RepositoryResult.NotFound)
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is ServiceLogRuntimeExecutionResult.ContractViolation)
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun staleSessionNeverReadsAnything() = runSuspend {
        val f = Fixture()
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding.copy(sessionId = SessionId("stale"))) is ServiceLogRuntimeExecutionResult.StaleSession)
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun successfulReadUsesSameSessionAndOneTerminalJournalAdvance() = runSuspend {
        val f = Fixture()
        val result = f.coordinator.execute(f.admission, f.expectedBinding) as ServiceLogRuntimeExecutionResult.Completed
        assertEquals(9, f.handle.executedLabels.size)
        assertEquals("service-log-read-bounded", f.handle.executedLabels.last())
        assertEquals(OperationStatus.SUCCEEDED, f.journal.current.snapshot.status)
        assertEquals("SERVICE_LOG_READ_RESULT", f.journal.current.snapshot.checkpoint.phaseName)
        assertEquals(OperationRevision(1), result.committedRevision)
        assertEquals(ServiceLogCategory.TIMEOUT, result.snapshot.entries.single().category)
    }
    @Test fun unverifiedInstallationIdentityNeverReadsLogs() = runSuspend {
        val f = Fixture(); f.handle.missingPresence = true
        val result = f.coordinator.execute(f.admission, f.expectedBinding) as ServiceLogRuntimeExecutionResult.ReadbackFailed
        assertEquals(ServiceLogFailure.TARGET_NOT_VERIFIED, result.kind)
        assertFalse("service-log-read-bounded" in f.handle.executedLabels)
    }
    @Test fun sshProfileChangedDuringPreludePreventsReadingTheOldTargetsLogs() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { f.sshAccess = null }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is ServiceLogRuntimeExecutionResult.ContractViolation)
        assertFalse("service-log-read-bounded" in f.handle.executedLabels)
        assertEquals(OperationRevision(0), f.journal.current.revision)
    }
    @Test fun journalAdvancedDuringReadSuppressesLateFactsAndDoesNotCommit() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { label -> if (label == "service-log-read-bounded")
            f.journal.current = f.journal.current.copy(revision = OperationRevision(5)) }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is ServiceLogRuntimeExecutionResult.StalePlan)
        assertEquals(OperationStatus.RUNNING, f.journal.current.snapshot.status)
        assertEquals(OperationRevision(5), f.journal.current.revision)
    }
    @Test fun processDeathOrRebootNeverAutomaticallyAuthorizesLogReading() {
        val f = Fixture()
        RecoveryExitProvenance.entries.forEach { exit ->
            val plan = ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(f.journal.current,
                OperationDurabilityValidation.Valid, exit))
            assertFalse(plan.automaticAllowed)
        }
    }
    private inner class Fixture(
        operationType: OperationType = OperationType.SERVICE_LOG_READ,
        checkpointSemantics: CheckpointSemantics = CheckpointSemantics.READ_ONLY,
        accessResult: RepositoryResult<ManagementAccess> = RepositoryResult.Success(
            ManagementAccess(installationId, accessId),
        ),
    ) {
        var sshAccess: ServerAccess? = ServerAccess(accessId, serverId, SshEndpoint("fixture.invalid", 22), "operator",
            SshAuthRef.Password(SecretId("reference")), HostKeyFingerprint("SHA256:fixture"))
        private val accessRepository = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
                sshAccess?.let { RepositoryResult.Success(it) } ?: RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOfNotNull(sshAccess))
            override suspend fun delete(serverAccessId: ServerAccessId) = RepositoryResult.ConstraintConflict("unused")
        }
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
        val coordinator: ServiceLogRuntimeCoordinator

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
            coordinator = ServiceLogRuntimeCoordinator(
                journal = journal,
                installationRepository = FakeInstallationRepository(),
                managementAccessRepository = FakeManagementAccessRepository(accessResult),
                runtimeRegistry = runtimeRegistry,
                sessionRegistry = sessionRegistry,
                managementExecutor = ManagementSshProbeExecutor { startedAt.plusSeconds(1) },
                logReader = ServiceLogSshReader { startedAt.plusSeconds(2) },
                accessRepository = accessRepository,
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
                    phaseName = if (operationType == OperationType.SERVICE_LOG_READ) "SERVICE_LOG_READ" else "OTHER",
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
            if (operationId == this@ServiceLogRuntimeCoordinatorTest.operationId) {
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
            if (installationId == this@ServiceLogRuntimeCoordinatorTest.installationId) {
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
        var missingPresence = false
        var afterCommand: (String) -> Unit = {}

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executedLabels += command.redactedLabel
            val stdout = when (command.redactedLabel) {
                "management-service-state" -> "active\n"
                "management-panel-settings" -> "PORT=54321\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=\n"
                "deep-service-definition" -> "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n"
                "service-log-read-bounded" -> """{"__REALTIME_TIMESTAMP":"1800000000000000","PRIORITY":"4","MESSAGE":"timeout token=hidden","_SYSTEMD_UNIT":"x-ui.service"}"""
                else -> ""
            }
            afterCommand(command.redactedLabel)
            return SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = if (missingPresence && command.redactedLabel == "management-path-presence")
                    CommandCompletion.ConfirmedFailure("fixture path absent", exitCode = 1) else CommandCompletion.ConfirmedSuccess,
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
