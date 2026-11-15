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

/** Actual shared host/runtime/one-shot adapter. Only remote command responses are scripted; no SSH/VPS. */
class WorkingDatabaseRestoreProductionCompositionTest {
    @Test fun oneShotWriteRequiresSeparateReadback(){runSuspend{val f=Fixture();assertTrue(f.inspect() is WorkingDatabaseRestoreRuntimeResult.AwaitingVerification);assertEquals(1,f.copyCommands);assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED,f.current!!.snapshot.checkpoint.semantics);assertFalse(f.labels.contains("working-db-readback-only"));val result=f.verify() as WorkingDatabaseRestoreRuntimeResult.Completed;assertEquals(4096L,result.receipt.previousBytes);assertEquals(1,f.copyCommands);assertEquals(2,f.closed)}}
    @Test fun repeatedHostAfterWriteCanOnlyRead(){runSuspend{val f=Fixture();f.inspect();f.runRestoreHost();assertEquals(1,f.copyCommands);assertEquals(1,f.labels.count{it=="working-db-readback-only"})}}
    @Test fun transportUnknownKeepsBarrierAndCannotReplay(){runSuspend{val f=Fixture();f.uncertainDispatch=true;f.validReadback=false;f.inspect();assertTrue(f.verify() is WorkingDatabaseRestoreRuntimeResult.AwaitingVerification);assertEquals(1,f.copyCommands);assertTrue(DurableServerMutationBarrierPolicy.evaluate(f.review.installation.serverId,listOf(f.current!!.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)}}
    @Test fun finiteNotStartedProofClosesWithoutInventingRestore(){runSuspend{val f=Fixture();f.notStarted=true;assertTrue(f.inspect() is WorkingDatabaseRestoreRuntimeResult.Failed);assertEquals(OperationStatus.FAILED,f.current!!.snapshot.status);assertEquals(1,f.copyCommands)}}
    @Test fun parentRevisionChangedDuringStoragePreventsDispatch(){runSuspend{val f=Fixture();f.afterCommand={if(it=="working-db-storage")f.parent=f.parent.copy(revision=OperationRevision(5))};assertTrue(f.inspect() is WorkingDatabaseRestoreRuntimeResult.Rejected);assertEquals(0,f.copyCommands)}}
    @Test fun changedPinDuringStoragePreventsDispatch(){runSuspend{val f=Fixture();f.afterCommand={if(it=="working-db-storage")f.storedAccess=f.access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:other"))};assertTrue(f.inspect() is WorkingDatabaseRestoreRuntimeResult.Rejected);assertEquals(0,f.copyCommands)}}
    @Test fun failedCheckpointCannotDispatch(){runSuspend{val f=Fixture();f.rejectCas=true;assertTrue(f.inspect() is WorkingDatabaseRestoreRuntimeResult.Rejected);assertEquals(0,f.copyCommands)}}
    @Test fun coldStartPendingHasNoReconstructedConfirmation(){runSuspend{val f=Fixture();f.start();f.newProcess();assertTrue(f.runHost() is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestorePrepared);assertEquals(0,f.connects)}}
    @Test fun coldStartUnsafeCanOnlyReadback(){runSuspend{val f=Fixture();f.inspect();f.newProcess();f.verify();assertEquals(1,f.copyCommands);assertEquals(OperationStatus.SUCCEEDED,f.current!!.snapshot.status)}}
    @Test fun missingReceiptCannotInventCurrentDatabaseFacts(){runSuspend{val f=Fixture();f.inspect();f.verify();val empty=JournalWorkingDatabaseRestoreStatusPort(f.journal,f.local,object:RestoreCompatibilityStatusPort{override suspend fun source(server:String,installation:String,access:String,source:String):RestoreCompatibilitySourceReview?=null
            override suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCompatibilityObservation?=null
            override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
        },WorkingDatabaseRestoreResultRegistry());val o=empty.read(f.review.serverId,f.review.installationId,f.review.accessId,"fixture-operation")!!;assertTrue(o.terminal);assertNull(o.receipt)}}
    @Test fun changedKnownFileReportCannotCreateWriteRequest(){runSuspend{val f=Fixture();f.changedFiles=1;assertTrue(f.actions.startConfirmed(f.review,f.source()) is WorkingDatabaseRestoreStart.Blocked);assertNull(f.current)}}
    @Test fun durableComparisonWithoutReportCannotCreateWriteRequest(){runSuspend{val f=Fixture();f.sourceReportPresent=false;assertTrue(f.actions.startConfirmed(f.review,f.source()) is WorkingDatabaseRestoreStart.Blocked);assertNull(f.current)}}
    @Test fun duplicatePendingRequestDoesNotCreateOrLaunchAgain(){runSuspend{val f=Fixture();val source=f.source();f.start();assertTrue(f.actions.startConfirmed(f.review,source) is WorkingDatabaseRestoreStart.Blocked);assertEquals(1,f.hostRequests.size)}}
    @Test fun cancellationBeforeDispatchIsLocal(){runSuspend{val f=Fixture();f.start();assertNull(f.actions.cancelPending(f.review,"fixture-operation"));assertEquals(OperationStatus.CANCELLED,f.current!!.snapshot.status);assertEquals(0,f.connects)}}
    @Test fun cancellationAfterPossibleWriteCannotClearBarrier(){runSuspend{val f=Fixture();f.inspect();assertNotNull(f.actions.cancelPending(f.review,"fixture-operation"));assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED,f.current!!.snapshot.checkpoint.semantics)}}
    @Test fun removedLinkBlocksBeforeConnect(){runSuspend{val f=Fixture();f.start();f.linkPresent=false;assertTrue(f.runHost() is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestorePrepared);assertEquals(0,f.connects)}}
    @Test fun postDispatchTargetChangeDoesNotPublishSuccess(){runSuspend{val f=Fixture();f.afterCommand={if(it=="working-db-restore-once")f.storedAccess=f.access.copy(username="changed")};assertTrue(f.inspect() is WorkingDatabaseRestoreRuntimeResult.Rejected);assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT,f.current!!.snapshot.checkpoint.semantics);assertEquals(1,f.copyCommands)}}
    @Test fun invalidReadbackCannotCloseUnknownOutcome(){runSuspend{val f=Fixture();f.inspect();f.validReadback=false;assertTrue(f.verify() is WorkingDatabaseRestoreRuntimeResult.AwaitingVerification);assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.current!!.snapshot.status)}}
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
        val checkedParent = VersionedOperationSnapshot(OperationSnapshot(checkId, OperationType.INSTALLATION_RESTORE_CHECK,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(3))
        private val comparisonId=OperationId("source-comparison")
        private val comparisonBinding=RestoreCompatibilityBindingPolicy.bind(comparisonId,installation,access,checkedParent,backup)
        var parent=VersionedOperationSnapshot(OperationSnapshot(comparisonId,OperationType.RESTORE_COMPATIBILITY,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(4))
        private fun report()=RestoreCompatibilityReport(ManagementScope(comparisonId,server,access.id,installation.id),comparisonBinding,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),RestoreFileSetComparison.MATCH,0,1,1,ManagementServiceState.ACTIVE,ManagementBaselineStatus.Matched,at)
        var sourceReportPresent=true
        var changedFiles=0
        var validReadback=true
        var notStarted=false
        var comparisonReads=0
        var panelPort = 2053
        var currentVersion = "3.10.0"
        var currentSchema = "1".repeat(64)
        var currentCount = "1"
        var linkPresent = true
        var current: VersionedOperationSnapshot? = null
        val binding get() = requireNotNull(WorkingDatabaseRestoreBinding.parse(current!!.snapshot.checkpoint.phaseName)).second
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
                (if (operationId == sourceId) backup else if(operationId==checkId) checkedParent else if(operationId==comparisonId) parent else current?.takeIf { it.snapshot.operationId == operationId })
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
                        val proof="FORMAT=VELUM_WORKING_DB_V1\nSCOPE=${b.digest}\nSOURCE_DB_SHA256=${b.source.databaseSha256}\nRESTORED_LOGICAL_SHA256=${"1".repeat(64)}\nPREVIOUS_DB_SHA256=${"2".repeat(64)}\nPREVIOUS_LOGICAL_SHA256=${"3".repeat(64)}\nPREVIOUS_BYTES=4096\nSERVICE=INACTIVE\nSTATE=VERIFIED\n"
                        val text=when(command.redactedLabel){
                            "working-db-storage"->"0\n1073741824\n"
                            "working-db-restore-once"->{
                                assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT,current!!.snapshot.checkpoint.semantics);copyCommands++
                                if(uncertainDispatch)return SshCommandResult(CommandDispatchState.DISPATCHED,CommandCompletion.Unknown("fixture dropped"),CapturedOutput.EMPTY,CapturedOutput.EMPTY)
                                if(notStarted)return SshCommandResult(CommandDispatchState.DISPATCHED,CommandCompletion.ConfirmedFailure(reason = "fixture rejected before stop", exitCode = 81),CapturedOutput.of("NOT_STARTED\n".toByteArray(),false),CapturedOutput.EMPTY)
                                "DATABASE_RESTORED\n"
                            }
                            "working-db-readback-only"->if(validReadback)proof else "UNAVAILABLE\n"
                            else->error("Unapproved command: "+command.redactedLabel)
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
        val registry = WorkingDatabaseRestoreResultRegistry()
        private val comparisonStatuses=object:RestoreCompatibilityStatusPort{
            override suspend fun source(server:String,installation:String,access:String,source:String):RestoreCompatibilitySourceReview?=null
            override suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCompatibilityObservation{
                assertEquals("source-comparison",operation);comparisonReads++
                return RestoreCompatibilityObservation(operation,"source-check","Observed fixture",true,report=if(sourceReportPresent)report().copy(changedFiles=changedFiles)else null,fresh=sourceReportPresent)
            }
            override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
        }
        val statuses get()=JournalWorkingDatabaseRestoreStatusPort(journal,local,comparisonStatuses,registry)
        val actions get()=ProductionWorkingDatabaseRestoreActionPort(local,journal,statuses,coordinator,registry,
            {id->hostRequests+=id;ExactOperationHostStartResult.START_REQUEST_ACCEPTED},idFactory={OperationId("fixture-operation")})
        suspend fun source()=requireNotNull(statuses.source(review.serverId,review.installationId,review.accessId,"source-comparison"))
        suspend fun start(){assertEquals(WorkingDatabaseRestoreStart.Recorded("fixture-operation"),actions.startConfirmed(review,source()))}
        suspend fun inspect():WorkingDatabaseRestoreRuntimeResult{start();return runRestoreHost()}
        suspend fun verify():WorkingDatabaseRestoreRuntimeResult{assertNull(actions.checkConfirmed(review,source(),"fixture-operation"));return runRestoreHost()}
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
        suspend fun runRestoreHost(): WorkingDatabaseRestoreRuntimeResult {
            val result = runHost()
            assertTrue("Expected exact WorkingDatabaseRestoreEnded, got $result", result is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestoreEnded)
            registry.publish(current!!.snapshot.operationId, result.workingDatabaseRestoreResult())
            return (result as ExactOperationHostTransportSequenceResult.WorkingDatabaseRestoreEnded).restore
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
