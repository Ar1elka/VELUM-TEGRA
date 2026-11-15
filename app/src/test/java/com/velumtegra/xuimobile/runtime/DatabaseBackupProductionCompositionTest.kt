package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.management.*
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.*
import org.junit.Test

/** Actual production action, shared coordinator, host sequence and SSH adapters; scripted transport only. */
class DatabaseBackupProductionCompositionTest {
    @Test fun confirmedCopyUsesOneSharedSessionOneDispatchAndVerifiedTerminalResult() = runSuspend {
        val f = Fixture()
        assertEquals(DatabaseBackupStart.Recorded("fixture-operation"), f.actions.createConfirmed(f.review, f.sourcePointer))
        assertEquals(0, f.connects); assertEquals(0, f.copyCommands)
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Completed)
        assertEquals(OperationStatus.SUCCEEDED, f.current!!.snapshot.status)
        assertEquals(1, f.copyCommands); assertEquals(1, f.closed)
        val observation = JournalDatabaseBackupStatusPort(f.journal, f.local, f.registry).read(f.review.serverId, f.review.installationId, f.review.accessId, "fixture-operation")
        assertEquals("b".repeat(64), observation!!.receipt!!.sha256)
    }
    @Test fun unknownCopyCanOnlyBeVerifiedAfterFreshExplicitRequestWithoutReplay() = runSuspend {
        val f = Fixture(); f.uncertainDispatch = true
        f.actions.createConfirmed(f.review, f.sourcePointer)
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.AwaitingVerification)
        assertEquals(0, f.labels.count { it == "database-backup-artifact-metadata" })
        f.newProcess()
        assertNull(f.actions.checkConfirmed(f.review, "fixture-operation"))
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Completed)
        assertEquals(1, f.copyCommands); assertEquals(2, f.connects); assertEquals(2, f.closed)
    }
    @Test fun missingProofAfterUnknownOutcomeRetainsDurableBarrierAndNeverCreatesAgain() = runSuspend {
        val f = Fixture(); f.uncertainDispatch = true; f.validProof = false
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        f.newProcess(); f.actions.checkConfirmed(f.review, "fixture-operation"); f.runBackupHost()
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, f.current!!.snapshot.status)
        assertTrue(f.actions.createConfirmed(f.review, f.sourcePointer) is DatabaseBackupStart.Blocked)
        assertEquals(1, f.copyCommands)
    }
    @Test fun lostFreshConfirmationBlocksBeforeOpeningAnyConnection() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer); f.newProcess()
        val r = f.runHost() as ExactOperationHostTransportSequenceResult.DatabaseBackupPrepared
        assertEquals(DatabaseBackupRuntimeResult.Rejected(DatabaseBackupFailure.AUTHORITY_MISSING), r.backup)
        assertEquals(0, f.connects); assertEquals(0, f.copyCommands)
    }
    @Test fun nonRootFreshPreflightAndFullQuotaNeverCrossWriteBoundary() = runSuspend {
        for (quota in listOf(false, true)) {
            val f = Fixture(); if (quota) f.slots = 4 else f.uid = "1000\n"
            f.actions.createConfirmed(f.review, f.sourcePointer)
            assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Failed)
            assertEquals(0, f.copyCommands); assertEquals(1, f.closed)
        }
    }
    @Test fun failedDurableCasCannotDispatch() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer); f.rejectCas = true
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Rejected)
        assertEquals(0, f.copyCommands); assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, f.current!!.snapshot.checkpoint.semantics)
    }
    @Test fun pendingCancellationIsLocalAndCannotAuthorizeAReadOrCopy() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer)
        assertNotNull(f.actions.checkConfirmed(f.review, "fixture-operation"))
        assertNull(f.actions.cancelPending(f.review, "fixture-operation"))
        assertEquals(OperationStatus.CANCELLED, f.current!!.snapshot.status)
        assertEquals(0, f.connects); assertEquals(0, f.copyCommands)
    }
    @Test fun changedReviewedTargetBlocksBeforeJournalAndHost() = runSuspend {
        val f = Fixture(); f.currentReview = f.review.copy(access = f.access.copy(username = "other"))
        assertTrue(f.actions.createConfirmed(f.review, f.sourcePointer) is DatabaseBackupStart.Blocked)
        assertNull(f.current); assertEquals(0, f.hostRequests.size)
    }
    @Test fun lostProcessReceiptCannotInventHashOrReadRemoteDataFromLocalStatus() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        val count = f.labels.size
        val status = JournalDatabaseBackupStatusPort(f.journal, f.local, DatabaseBackupResultRegistry()).read(
            f.review.serverId, f.review.installationId, f.review.accessId, "fixture-operation")!!
        assertTrue(status.terminal); assertNull(status.receipt); assertEquals(count, f.labels.size)
    }
    @Test fun accessChangedDuringFreshPreludeCannotCrossCopyBoundary() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer)
        f.afterCommand = { label -> if (label == "deep-database-schema") f.storedAccess = f.access.copy(username = "changed") }
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Rejected)
        assertEquals(0, f.copyCommands); assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, f.current!!.snapshot.checkpoint.semantics)
    }
    @Test fun journalChangedDuringPreflightCannotCommitOrDispatchLateCopy() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer)
        f.afterCommand = { label -> if (label == "update-preflight-architecture") f.current = f.current!!.copy(revision = OperationRevision(7)) }
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Rejected)
        assertEquals(0, f.copyCommands); assertEquals(OperationRevision(7), f.current!!.revision)
    }
    @Test fun accessChangedDuringPostVerificationCannotPublishOldTargetsReceipt() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer)
        f.afterCommand = { label -> if (label == "database-backup-sha256") f.storedAccess = f.access.copy(pinnedHostKey = HostKeyFingerprint("SHA256:changed")) }
        assertTrue(f.runBackupHost() is DatabaseBackupRuntimeResult.Rejected)
        assertEquals(1, f.copyCommands); assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, f.current!!.snapshot.checkpoint.semantics)
    }
    @Test fun duplicateVisibleRequestCannotCreateASecondPendingBackup() = runSuspend {
        val f = Fixture(); f.actions.createConfirmed(f.review, f.sourcePointer)
        assertTrue(f.actions.createConfirmed(f.review, f.sourcePointer) is DatabaseBackupStart.Blocked)
        assertEquals(1, f.hostRequests.size); assertEquals(0, f.connects)
    }
    @Test fun slotObservationIsDisplayOnlyAndSendsNoCleanupCommand() = runSuspend {
        val f = Fixture(); f.slots = 2
        assertNull(f.coordinator.databaseBackupSlotInventory(ServerId("fixture-server"), f.review.access))
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        val inv = f.coordinator.databaseBackupSlotInventory(ServerId("fixture-server"), f.review.access) as BackupSlotInventory.Known
        assertEquals(2, inv.used); assertEquals(4, inv.max); assertEquals(2, inv.free); assertFalse(inv.saturated)
        assertEquals(1, f.copyCommands)
        assertTrue(f.labels.none { "delete" in it || "cleanup" in it || "remove" in it || "prune" in it })
    }
    @Test fun fullSlotsAreSaturatedAndNeverDispatchCopy() = runSuspend {
        val f = Fixture(); f.slots = 4
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        val inv = f.coordinator.databaseBackupSlotInventory(ServerId("fixture-server"), f.review.access) as BackupSlotInventory.Known
        assertEquals(4, inv.used); assertTrue(inv.saturated); assertEquals(0, inv.free)
        assertEquals(0, f.copyCommands); assertNotEquals(OperationStatus.SUCCEEDED, f.current!!.snapshot.status)
    }
    @Test fun unparsableStorageIsUnavailableNeverFree() = runSuspend {
        val f = Fixture(); f.storageOverride = "garbage\n"
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        assertTrue(f.coordinator.databaseBackupSlotInventory(ServerId("fixture-server"), f.review.access) is BackupSlotInventory.Unavailable)
        assertEquals(0, f.copyCommands)
    }
    @Test fun probeCountAboveCapIsNotShownAsFree() = runSuspend {
        val f = Fixture(); f.storageOverride = "5\n1000000|4096\n"
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        val inv = f.coordinator.databaseBackupSlotInventory(ServerId("fixture-server"), f.review.access)
        if (inv is BackupSlotInventory.Known) { assertTrue(inv.overflow); assertTrue(inv.saturated) }
        else assertTrue(inv is BackupSlotInventory.Unavailable)
        assertEquals(0, f.copyCommands)
    }
    @Test fun statusPortSlotReadUsesLocalMemoryOnly() = runSuspend {
        val f = Fixture(); f.slots = 1
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        val before = f.labels.size
        val port = JournalDatabaseBackupStatusPort(f.journal, f.local, f.registry) { id, profile -> f.coordinator.databaseBackupSlotInventory(id, profile) }
        assertEquals(1, (port.slots(f.review) as BackupSlotInventory.Known).used)
        assertNull(port.slots(f.review.copy(access = f.review.access.copy(serverId = ServerId("other-server")))))
        assertEquals(before, f.labels.size)
    }
    @Test fun statusPortDoesNotShowProfileAObservationForProfileBOfSameServer() = runSuspend {
        val f = Fixture(); f.slots = 1
        f.actions.createConfirmed(f.review, f.sourcePointer); f.runBackupHost()
        val before = f.labels.size
        val port = JournalDatabaseBackupStatusPort(f.journal, f.local, f.registry) { id, profile -> f.coordinator.databaseBackupSlotInventory(id, profile) }
        assertNotNull(port.slots(f.review))
        val a = f.review.access
        val otherEndpoint = f.review.copy(access = a.copy(endpoint = SshEndpoint(a.endpoint.host, a.endpoint.port + 1)))
        val otherKey = f.review.copy(access = a.copy(pinnedHostKey = HostKeyFingerprint(a.pinnedHostKey.value + "-b")))
        assertEquals(a.serverId, otherEndpoint.access.serverId)
        assertNull(port.slots(otherEndpoint)); assertNull(port.slots(otherKey))
        assertNotNull(port.slots(f.review)); assertEquals(before, f.labels.size)
    }
    private class Fixture {
        private val at = Instant.now()
        private val server = ServerId("fixture-server")
        val access = ServerAccess(ServerAccessId("fixture-access"), server, SshEndpoint("fixture.invalid", 22), "operator",
            SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
        val installation = XuiInstallation(XuiInstallationId("fixture-installation"), server, InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
        val review = ManagementRestartReview("Fixture VPS", installation, access)
        var currentReview = review
        var current: VersionedOperationSnapshot? = null
        var uid = "0\n"
        var uncertainDispatch = false
        var connects = 0
        var closed = 0
        var copyCommands = 0
        var slots = 0
        var storageOverride: String? = null
        var validProof = true
        var rejectCas = false
        var afterCommand: (String) -> Unit = {}
        var storedAccess = access
        val labels = mutableListOf<String>()
        val hostRequests = mutableListOf<OperationId>()
        val journal = object : OperationJournal {
            override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                check(current == null); current = VersionedOperationSnapshot(initial, OperationRevision(0))
                return OperationJournalResult.Success(checkNotNull(current))
            }
            override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
                current?.takeIf { it.snapshot.operationId == operationId }?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
            override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
                OperationJournalResult.Success(listOfNotNull(current?.takeIf { it.snapshot.checkpoint.semantics != CheckpointSemantics.TERMINAL }))
            override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                val before = current ?: return OperationJournalResult.NotFound
                if (operationId != before.snapshot.operationId) return OperationJournalResult.NotFound
                if (expectedRevision != before.revision) return OperationJournalResult.StaleRevision(expectedRevision, before.revision)
                if (rejectCas) return OperationJournalResult.StorageFailure("fixture CAS rejected")
                current = VersionedOperationSnapshot(next, OperationRevision(before.revision.value + 1))
                return OperationJournalResult.Success(checkNotNull(current))
            }
            override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
        }
        private val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
                if (serverAccessId == access.id) RepositoryResult.Success(storedAccess) else RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(access))
            override suspend fun delete(serverAccessId: ServerAccessId) = error("No credential deletion")
        }
        private val installations = object : XuiInstallationRepository {
            override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
                if (installationId == installation.id) RepositoryResult.Success(VersionedRecord(installation, RecordRevision(1))) else RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(VersionedRecord(installation, RecordRevision(1))))
            override suspend fun create(installation: XuiInstallation) = error("No installation writes")
            override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = error("No installation writes")
            override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = error("No installation writes")
        }
        private val management = object : ManagementAccessRepository {
            override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId) =
                RepositoryResult.Success(ManagementAccess(installation.id, access.id))
            override suspend fun listForInstallation(installationId: XuiInstallationId) = RepositoryResult.Success(listOf(ManagementAccess(installation.id, access.id)))
            override suspend fun listForServerAccess(serverAccessId: ServerAccessId) = RepositoryResult.Success(listOf(ManagementAccess(installation.id, access.id)))
            override suspend fun create(access: ManagementAccess) = error("No management writes")
            override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = error("No management writes")
        }
        private val factory = object : SshConnectionFactory {
            override suspend fun connect(access: ServerAccess, owner: SessionOwner, config: SshTransportConfig): SshConnectResult {
                assertEquals(this@Fixture.access, access); assertEquals(SessionOwner.Operation(OperationId("fixture-operation")), owner)
                connects++
                return SshConnectResult.Connected(object : SshSessionHandle {
                    override val binding = SessionBinding(SessionId("fixture-session-$connects"), access.id, owner)
                    private var sessionOpen = true
                    override val isOpen get() = sessionOpen
                    override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
                        check(sessionOpen); labels += command.redactedLabel
                        val b = DatabaseBackupBinding.parse(current!!.snapshot.checkpoint.phaseName)!!.second
                        val manifest = "FORMAT=VELUM_DB_BACKUP_V1\nSCOPE=${b.digest}\nVERSION=${b.version}\nARCH=${b.architecture.name}\nBYTES=4096\nSHA256=${"b".repeat(64)}\n"
                        val text = when (command.redactedLabel) {
                            "update-preflight-effective-uid" -> uid
                            "management-panel-settings" -> "PORT=2053\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n"
                            "management-service-state" -> "active\n"
                            "deep-service-definition" -> "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n"
                            "xui-readonly-binary-version" -> "3.10.0\n"
                            "update-preflight-architecture" -> "x86_64\n"
                            "update-recovery-tools" -> "SQLITE3=AVAILABLE\nTAR=AVAILABLE\nSHA256SUM=AVAILABLE\nSTAT=AVAILABLE\n"
                            "update-recovery-database-metadata" -> "META=8|1|0|0|600|4096|1792180000|1792180000\n"
                            "update-recovery-runtime-files" -> "PRESENT\n"
                            "deep-database-quick-check" -> "ok\n"
                            "deep-database-schema" -> "SUPPORTED\n"
                            "deep-certificate-references" -> "CERT=\nKEY=\n"
                            "database-backup-storage" -> storageOverride ?: "$slots\n1000000|4096\n"
                            "database-backup-create-once" -> {
                                assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, current!!.snapshot.checkpoint.semantics)
                                copyCommands++
                                if (uncertainDispatch) return SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.Unknown("fixture connection dropped"), CapturedOutput.EMPTY, CapturedOutput.EMPTY)
                                "CREATED\n"
                            }
                            "database-backup-artifact-metadata" -> if (validProof) "8|10|0|600|4096|1792180000|1792180000|1\n8|11|0|600|${manifest.toByteArray().size}|1792180000|1792180000|1\n" else "MISSING\n"
                            "database-backup-manifest" -> manifest
                            "database-backup-sha256" -> "${"b".repeat(64)}  ${b.remoteDirectory}/database.sqlite\n"
                            "database-backup-integrity" -> "ok\n"
                            else -> ""
                        }
                        afterCommand(command.redactedLabel)
                        return SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
                            CapturedOutput.of(text.encodeToByteArray(), truncated = false), CapturedOutput.EMPTY)
                    }
                    override fun close() { if (sessionOpen) closed++; sessionOpen = false }
                })
            }
        }
        // Match the complete application graph: the generic host first asks the Installer consumer
        // whether it owns this operation. This capability must exist even for a backup-only test.
        private val publisher = object : ManagementEnrollmentPublisher {
            override suspend fun publish(request: ManagementEnrollmentRequest): ManagementEnrollmentPublicationResult =
                error("BACKUP must never publish an installation")
            override suspend fun publishInstaller(request: InstallerManagementPublicationRequest): ManagementEnrollmentPublicationResult =
                error("BACKUP must never invoke Installer publication")
            override suspend fun republishReinstall(request: ExistingInstallationReinstallPublicationRequest): ExistingInstallationReinstallPublicationResult =
                error("BACKUP must never invoke Reinstall publication")
        }
        var coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher)
        val local = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(currentReview) }
        val registry = DatabaseBackupResultRegistry()
        val sourcePointer = UpdatePreflightPointer("source-preflight", access.id.value)
        private fun sourceReport(): UpdatePreflightSnapshot {
            val scope = ManagementScope(OperationId(sourcePointer.operationId), server, access.id, installation.id)
            return UpdatePreflightSnapshot(scope, UpdateRootStatus.DIRECT_ROOT, UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD,
                DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched,
                at, UpdateServerArchitecture.AMD64, UpdateRecoverySourceSnapshot(scope,
                    UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE }, UpdateRecoveryDatabaseState.PRIVATE_REGULAR,
                    4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT, DeepDiagnosticDatabaseIntegrityStatus.OK,
                    DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, at))
        }
        val actions get() = ProductionDatabaseBackupActionPort(local, UpdatePreflightStatusPort { _, _, _ ->
            UpdatePreflightStatus("fixture", true, sourceReport()) }, journal, coordinator, registry,
            { id -> hostRequests += id; ExactOperationHostStartResult.START_REQUEST_ACCEPTED }, idFactory = { OperationId("fixture-operation") })
        fun newProcess() { coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher) }
        suspend fun runHost(): ExactOperationHostTransportSequenceResult {
            val c = checkNotNull(current)
            val action = if (c.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) RecoveryAction.RECONNECT_EXACT_OWNER else RecoveryAction.RECONCILE_READ_ONLY
            val plan = ColdStartRecoveryPlan(c.snapshot.operationId, c.snapshot.target, c.revision, action, automaticAllowed = false)
            val admission = (coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED) as RecoveryAdmissionResult.Admitted).admission
            try {
                // Fixture stands in for the next Android callback registration's actual observation.
                coordinator.observeConnectivity(ConnectivityState.ONLINE)
                return ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(coordinator)).run(
                    ExactOperationHostRuntimeBinding(c.snapshot.operationId, CoordinatorAdmissionToken(admission)), RetryBudget(1))
            } finally { assertEquals(OperationRuntimeReleaseResult.RELEASED, coordinator.release(admission)) }
        }
        suspend fun runBackupHost(): DatabaseBackupRuntimeResult {
            val result = runHost()
            assertTrue("Expected exact DatabaseBackupEnded, got $result", result is ExactOperationHostTransportSequenceResult.DatabaseBackupEnded)
            registry.publish(current!!.snapshot.operationId, result.databaseBackupResult())
            return (result as ExactOperationHostTransportSequenceResult.DatabaseBackupEnded).backup
        }
    }
}
private fun <T> runSuspend(block: suspend () -> T): T {
    var outcome: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(result: Result<T>) { outcome = result }
    })
    return checkNotNull(outcome).getOrThrow()
}
