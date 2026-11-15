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

/** Actual shared host/runtime/reader; only remote command responses are scripted. No SSH/VPS. */

class RestoreCompatibilityProductionCompositionTest {
    @Test fun explicitComparisonUsesOneOwnedSessionAndOnlyReadCommands()=runSuspend{
        val f=Fixture();val result=f.inspect() as RestoreCompatibilityRuntimeResult.Completed
        assertTrue(result.report.prerequisitesMatch);assertEquals(1,f.connects);assertEquals(1,f.closed)
        assertEquals(1,f.labels.count{it=="restore-compatibility-read"});assertTrue(f.labels.all{it.startsWith("management-") || it=="restore-compatibility-read"})
        assertEquals(OperationStatus.SUCCEEDED,f.current!!.snapshot.status)
    }
    @Test fun unknownTransportCannotBecomeAnObservedMatch()=runSuspend{val f=Fixture();f.uncertainDispatch=true;assertTrue(f.inspect() is RestoreCompatibilityRuntimeResult.Failed);assertEquals(OperationStatus.FAILED,f.current!!.snapshot.status)}
    @Test fun malformedComparisonProofCannotCommitSuccess()=runSuspend{val f=Fixture();f.validProof=false;assertTrue(f.inspect() is RestoreCompatibilityRuntimeResult.Failed)}
    @Test fun changedCheckRevisionAfterReadDiscardsLateReport()=runSuspend{val f=Fixture();f.afterCommand={if(it=="restore-compatibility-read")f.parent=f.parent.copy(revision=OperationRevision(4))};assertTrue(f.inspect() is RestoreCompatibilityRuntimeResult.Rejected);assertEquals(CheckpointSemantics.READ_ONLY,f.current!!.snapshot.checkpoint.semantics)}
    @Test fun changedHostPinAfterReadDiscardsLateReport()=runSuspend{val f=Fixture();f.afterCommand={if(it=="restore-compatibility-read")f.storedAccess=f.access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:changed"))};assertTrue(f.inspect() is RestoreCompatibilityRuntimeResult.Rejected)}
    @Test fun failedDurableCommitDoesNotPublishReport()=runSuspend{val f=Fixture();f.rejectCas=true;assertTrue(f.inspect() is RestoreCompatibilityRuntimeResult.Rejected);assertEquals(OperationStatus.RUNNING,f.current!!.snapshot.status)}
    @Test fun invalidOriginalBackupPreventsNewSourceRequest()=runSuspend{val f=Fixture();val source=f.source();f.backup=f.backup.copy(snapshot=f.backup.snapshot.copy(status=OperationStatus.FAILED));assertTrue(f.actions.startConfirmed(f.review,source) is RestoreCompatibilityStart.Blocked);assertNull(f.current);assertEquals(0,f.connects)}
    @Test fun duplicatePendingRequestDoesNotCreateSecondRecord()=runSuspend{val f=Fixture();val source=f.source();f.start();assertTrue(f.actions.startConfirmed(f.review,source) is RestoreCompatibilityStart.Blocked);assertEquals(0,f.connects);assertEquals(1,f.hostRequests.size)}
    @Test fun pendingCancelIsLocalAndDoesNotConnect()=runSuspend{val f=Fixture();f.start();assertNull(f.actions.cancelPending(f.review,"fixture-operation"));assertEquals(OperationStatus.CANCELLED,f.current!!.snapshot.status);assertEquals(0,f.connects)}
    @Test fun coldStartPendingReadRequiresExplicitAction()=runSuspend{val f=Fixture();f.start();val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(f.current!!,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed);assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER,plan.action);assertEquals(0,f.connects)}
    @Test fun emptyProcessRegistryCannotInventSchemaOrCompatibility()=runSuspend{val f=Fixture();f.inspect();val count=f.labels.size;val o=JournalRestoreCompatibilityStatusPort(f.journal,f.local,RestoreCompatibilityResultRegistry()).read(f.review.serverId,f.review.installationId,f.review.accessId,"fixture-operation")!!;assertTrue(o.terminal);assertNull(o.report);assertFalse(o.fresh);assertEquals(count,f.labels.size)}
    @Test fun differentObservedVersionIsReadSuccessWithoutMigrationClaim()=runSuspend{val f=Fixture();f.currentVersion="3.10.2";val r=f.inspect() as RestoreCompatibilityRuntimeResult.Completed;assertFalse(r.report.sameVersion);assertFalse(r.report.prerequisitesMatch)}
    @Test fun unknownSchemaIsNotRestorationAuthority()=runSuspend{val f=Fixture();f.currentSchema="-";f.currentCount="-";val r=f.inspect() as RestoreCompatibilityRuntimeResult.Completed;assertNull(r.report.currentSchemaSha256);assertFalse(r.report.prerequisitesMatch)}
    @Test fun removedManagementLinkBlocksBeforeConnection()=runSuspend{val f=Fixture();f.start();f.linkPresent=false;val r=f.runHost();assertTrue(r is ExactOperationHostTransportSequenceResult.RestoreCompatibilityPrepared);assertEquals(0,f.connects)}
    @Test fun settingsDriftDuringWorkerRejectsStaleQuickFacts()=runSuspend{
        val f=Fixture();f.afterCommand={if(it=="restore-compatibility-read")f.panelPort=2063}
        assertTrue(f.inspect() is RestoreCompatibilityRuntimeResult.Failed)
        assertEquals(2,f.labels.count{it=="management-panel-settings"})
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
        private val sourceId = OperationId("source-backup")
        private val sourceBinding = InstallationBackupBindingPolicy.bind(sourceId, installation, access, "3.10.0", UpdateServerArchitecture.AMD64)
        var backup = VersionedOperationSnapshot(OperationSnapshot(sourceId, OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(server, access.id, installation.id), OperationStatus.SUCCEEDED,
            OperationCheckpoint(sourceBinding.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, at), at, at), OperationRevision(2))
        private val checkId = OperationId("source-check")
        private val checkedBinding = RestoreCheckBindingPolicy.bind(checkId, installation, access, backup, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3)
        var parent = VersionedOperationSnapshot(OperationSnapshot(checkId, OperationType.INSTALLATION_RESTORE_CHECK,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(3))
        var panelPort = 2053
        var currentVersion = "3.10.0"
        var currentSchema = "1".repeat(64)
        var currentCount = "1"
        var linkPresent = true
        var current: VersionedOperationSnapshot? = null
        val binding get() = requireNotNull(RestoreCompatibilityBinding.parse(current!!.snapshot.checkpoint.phaseName)).second
        var uid = "0\n"
        var uncertainDispatch = false
        var failureCode: Int? = null
        var connects = 0
        var closed = 0
        var copyCommands = 0
        var slots = 0
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
                (if (operationId == sourceId) backup else if(operationId==checkId) parent else current?.takeIf { it.snapshot.operationId == operationId })
                    ?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
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
                if(linkPresent) RepositoryResult.Success(ManagementAccess(installation.id, access.id)) else RepositoryResult.NotFound
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
                        val b = this@Fixture.binding
                        val proof = "FORMAT=VELUM_RESTORE_COMPARISON_V1\nSCOPE=${b.digest}\nSOURCE_RESTORE=${b.source.digest}\nSOURCE_ARCHIVE=${b.source.archiveSha256}\nSOURCE_DB=${b.source.databaseSha256}\nSOURCE_INVENTORY=${b.source.inventorySha256}\nCURRENT_VERSION=$currentVersion\nCURRENT_ARCH=AMD64\nSOURCE_SCHEMA=${"1".repeat(64)}\nCURRENT_SCHEMA=$currentSchema\nFILE_SET=MATCH\nCHANGED_FILES=0\nSOURCE_INBOUNDS=1\nCURRENT_INBOUNDS=$currentCount\n"
                        val text = when (command.redactedLabel) {
                            "management-panel-settings" -> "PORT=$panelPort\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n"
                            "management-service-state" -> "active\n"
                            "restore-compatibility-read" -> {
                                assertEquals(CheckpointSemantics.READ_ONLY,current!!.snapshot.checkpoint.semantics)
                                if(uncertainDispatch)return SshCommandResult(CommandDispatchState.DISPATCHED,CommandCompletion.Unknown("fixture connection dropped"),CapturedOutput.EMPTY,CapturedOutput.EMPTY)
                                if(validProof)proof else "UNAVAILABLE\n"
                            }
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
        val registry = RestoreCompatibilityResultRegistry()
        val actions get() = ProductionRestoreCompatibilityActionPort(local,journal,registry,
            {id->hostRequests+=id;ExactOperationHostStartResult.START_REQUEST_ACCEPTED},idFactory={OperationId("fixture-operation")})
        suspend fun source()=requireNotNull(JournalRestoreCompatibilityStatusPort(journal,local,registry).source(review.serverId,review.installationId,review.accessId,"source-check"))
        suspend fun start(){assertEquals(RestoreCompatibilityStart.Recorded("fixture-operation"),actions.startConfirmed(review,source()))}
        suspend fun inspect():RestoreCompatibilityRuntimeResult{start();return runRestoreHost()}
        fun newProcess() { coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher) }
        suspend fun runHost(): ExactOperationHostTransportSequenceResult {
            val c = checkNotNull(current)
            val action = if (c.snapshot.checkpoint.semantics in setOf(CheckpointSemantics.READ_ONLY, CheckpointSemantics.MUTATION_NOT_STARTED)) RecoveryAction.RECONNECT_EXACT_OWNER else RecoveryAction.RECONCILE_READ_ONLY
            val plan = ColdStartRecoveryPlan(c.snapshot.operationId, c.snapshot.target, c.revision, action, automaticAllowed = false)
            val admission = (coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED) as RecoveryAdmissionResult.Admitted).admission
            try {
                // Fixture stands in for the next Android callback registration's actual observation.
                coordinator.observeConnectivity(ConnectivityState.ONLINE)
                return ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(coordinator)).run(
                    ExactOperationHostRuntimeBinding(c.snapshot.operationId, CoordinatorAdmissionToken(admission)), RetryBudget(1))
            } finally { assertEquals(OperationRuntimeReleaseResult.RELEASED, coordinator.release(admission)) }
        }
        suspend fun runRestoreHost(): RestoreCompatibilityRuntimeResult {
            val result = runHost()
            assertTrue("Expected exact RestoreCompatibilityEnded, got $result", result is ExactOperationHostTransportSequenceResult.RestoreCompatibilityEnded)
            registry.publish(current!!.snapshot.operationId, result.restoreCompatibilityResult())
            return (result as ExactOperationHostTransportSequenceResult.RestoreCompatibilityEnded).restore
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
