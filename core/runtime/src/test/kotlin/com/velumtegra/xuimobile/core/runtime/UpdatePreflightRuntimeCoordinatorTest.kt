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

class UpdatePreflightRuntimeCoordinatorTest {
    private val operationId = OperationId("update-runtime-op")
    private val serverId = ServerId("update-runtime-server")
    private val accessId = ServerAccessId("update-runtime-access")
    private val installationId = XuiInstallationId("update-runtime-installation")
    private val startedAt = Instant.parse("2026-10-15T18:00:00Z")

    @Test fun nonPreflightOperationRunsNoCommand() = runSuspend {
        val f = Fixture(operationType = OperationType.QUICK_INSPECT)
        assertEquals(UpdatePreflightRuntimeExecutionResult.NotUpdatePreflightOperation, f.coordinator.execute(f.admission, f.expectedBinding))
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun installerPostVerifyIsNotConsumedAsAUpdatePreflight() = runSuspend {
        val f = Fixture(OperationType.INSTALL, CheckpointSemantics.POST_VERIFY_REQUIRED)
        assertEquals(UpdatePreflightRuntimeExecutionResult.NotUpdatePreflightOperation, f.coordinator.execute(f.admission, f.expectedBinding))
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun missingManagementBindingStopsBeforeAnyCommand() = runSuspend {
        val f = Fixture(accessResult = RepositoryResult.NotFound)
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.ContractViolation)
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun staleSessionNeverReadsAnything() = runSuspend {
        val f = Fixture()
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding.copy(sessionId = SessionId("stale"))) is UpdatePreflightRuntimeExecutionResult.StaleSession)
        assertTrue(f.handle.executedLabels.isEmpty())
    }
    @Test fun successfulReadUsesSameSessionAndOneTerminalJournalAdvance() = runSuspend {
        val f = Fixture()
        val result = f.coordinator.execute(f.admission, f.expectedBinding) as UpdatePreflightRuntimeExecutionResult.Completed
        assertEquals(27, f.handle.executedLabels.size)
        assertEquals("recovery-files-metadata", f.handle.executedLabels.last())
        assertEquals(OperationStatus.SUCCEEDED, f.journal.current.snapshot.status)
        assertEquals("UPDATE_PREFLIGHT_RESULT", f.journal.current.snapshot.checkpoint.phaseName)
        assertEquals(OperationRevision(1), result.committedRevision)
        assertEquals("3.0.0", result.snapshot.currentVersion)
        assertEquals(UpdateRootStatus.DIRECT_ROOT, result.snapshot.root)
        assertEquals(UpdateServerArchitecture.AMD64, result.snapshot.architecture)
        assertEquals(UpdateRecoveryDatabaseState.PRIVATE_REGULAR, result.snapshot.recovery!!.database)
        assertNotNull(result.snapshot.recoveryFiles!!.knownSetDigest)
    }
    @Test fun unverifiedInstallationIdentityStopsPreflight() = runSuspend {
        val f = Fixture(); f.handle.missingPresence = true
        val result = f.coordinator.execute(f.admission, f.expectedBinding) as UpdatePreflightRuntimeExecutionResult.ReadbackFailed
        assertEquals(UpdatePreflightFailure.TARGET_NOT_VERIFIED, result.kind)
        assertFalse("xui-readonly-binary-version" in f.handle.executedLabels)
    }
    @Test fun sshProfileChangedDuringPreludePreventsReadingTheOldTargetsFacts() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { f.sshAccess = null }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.ContractViolation)
        assertFalse("xui-readonly-binary-version" in f.handle.executedLabels)
        assertEquals(OperationRevision(0), f.journal.current.revision)
    }
    @Test fun journalAdvancedDuringReadSuppressesLateFactsAndDoesNotCommit() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { label -> if (label == "xui-readonly-binary-version")
            f.journal.current = f.journal.current.copy(revision = OperationRevision(5)) }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.StalePlan)
        assertEquals(OperationStatus.RUNNING, f.journal.current.snapshot.status)
        assertEquals(OperationRevision(5), f.journal.current.revision)
    }
    @Test fun processDeathOrRebootNeverAutomaticallyAuthorizesUpdatePreflighting() {
        val f = Fixture()
        RecoveryExitProvenance.entries.forEach { exit ->
            val plan = ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(f.journal.current,
                OperationDurabilityValidation.Valid, exit))
            assertFalse(plan.automaticAllowed)
        }
    }
    @Test fun sshAccessRemovedDuringRecoverySourceReadSuppressesTheWholeReport() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { label -> if (label == "deep-database-quick-check") f.sshAccess = null }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.ContractViolation)
        assertEquals(OperationRevision(0), f.journal.current.revision)
        assertEquals(OperationStatus.RUNNING, f.journal.current.snapshot.status)
    }
    @Test fun journalRevisionChangedDuringRecoveryReadCannotCommitLateSourceFacts() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { label -> if (label == "deep-database-schema")
            f.journal.current = f.journal.current.copy(revision = OperationRevision(7)) }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.StalePlan)
        assertEquals(OperationRevision(7), f.journal.current.revision)
        assertEquals(OperationStatus.RUNNING, f.journal.current.snapshot.status)
    }
    @Test fun sshAccessRemovedDuringFileInventorySuppressesAllFactsBeforeCommit() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { label -> if (label == "recovery-files-metadata") f.sshAccess = null }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.ContractViolation)
        assertEquals(OperationRevision(0), f.journal.current.revision)
    }
    @Test fun journalAdvanceDuringFileInventoryCannotCommitLateCompletion() = runSuspend {
        val f = Fixture()
        f.handle.afterCommand = { label -> if (label == "recovery-files-references") f.journal.current = f.journal.current.copy(revision = OperationRevision(7)) }
        assertTrue(f.coordinator.execute(f.admission, f.expectedBinding) is UpdatePreflightRuntimeExecutionResult.StalePlan)
        assertEquals(OperationRevision(7), f.journal.current.revision)
    }
    @Test fun unavailableInventoryPreservesActualPreflightWithAFiniteMissingEvidenceFinding() = runSuspend {
        val f = Fixture(); f.handle.inventoryAvailable = false
        val result = f.coordinator.execute(f.admission, f.expectedBinding) as UpdatePreflightRuntimeExecutionResult.Completed
        assertEquals("3.0.0", result.snapshot.currentVersion)
        assertEquals(setOf(RecoveryFileIssue.READ_UNAVAILABLE), result.snapshot.recoveryFiles!!.issues)
        assertNull(result.snapshot.recoveryFiles!!.knownSetDigest)
    }
    private inner class Fixture(
        operationType: OperationType = OperationType.UPDATE_PREFLIGHT,
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
        val coordinator: UpdatePreflightRuntimeCoordinator

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
            coordinator = UpdatePreflightRuntimeCoordinator(
                journal = journal,
                installationRepository = FakeInstallationRepository(),
                managementAccessRepository = FakeManagementAccessRepository(accessResult),
                runtimeRegistry = runtimeRegistry,
                sessionRegistry = sessionRegistry,
                managementExecutor = ManagementSshProbeExecutor { startedAt.plusSeconds(1) },
                preflightReader = UpdatePreflightSshReader { startedAt.plusSeconds(3) },
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
                    phaseName = if (operationType == OperationType.UPDATE_PREFLIGHT) "UPDATE_PREFLIGHT" else "OTHER",
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
            if (operationId == this@UpdatePreflightRuntimeCoordinatorTest.operationId) {
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
            if (installationId == this@UpdatePreflightRuntimeCoordinatorTest.installationId) {
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
        var inventoryAvailable = true
        var afterCommand: (String) -> Unit = {}

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executedLabels += command.redactedLabel
            val stdout = when (command.redactedLabel) {
                "management-service-state" -> "active\n"
                "management-panel-settings" -> "PORT=54321\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=\n"
                "deep-service-definition" -> "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n"
                "update-preflight-effective-uid" -> "0\n"
                "xui-readonly-binary-version" -> "3.0.0\n"
                "update-preflight-architecture" -> "x86_64\n"
                "update-recovery-tools" -> "SQLITE3=AVAILABLE\nTAR=AVAILABLE\nSHA256SUM=AVAILABLE\nSTAT=AVAILABLE\n"
                "update-recovery-database-metadata" -> "META=8|1|0|0|600|4096|1792180000|1792180000\n"
                "update-recovery-runtime-files" -> "PRESENT\n"
                "deep-database-quick-check" -> "ok\n"
                "deep-database-schema" -> "SUPPORTED\n"
                "deep-certificate-references" -> "CERT=\nKEY=\n"
                "recovery-files-tools" -> if (inventoryAvailable) "READY\n" else ""
                "recovery-files-runtime" -> "d|/usr/local/x-ui/bin\nf|/usr/local/x-ui/x-ui\nf|/usr/local/x-ui/bin/xray-linux-amd64\n"
                "recovery-files-service" -> "FRAGMENT=/etc/systemd/system/x-ui.service\nDROPINS=\nENVIRONMENT=NONE\nENVFILES=NONE\nDIRECTORY=/usr/local/x-ui\nNODEKEY=ABSENT\n"
                "recovery-files-references" -> "DOCS|1|2|0|0\n"
                "recovery-files-metadata" -> "F|0|8|1|0|644|200|1|1|1\nF|1|8|2|0|755|200000|1|1|1\nF|2|8|3|0|755|100000|1|1|1\n"
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
