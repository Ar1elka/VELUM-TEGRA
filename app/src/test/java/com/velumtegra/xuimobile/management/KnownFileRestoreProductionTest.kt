package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
class KnownFileRestoreProductionTest{
    @Test fun openingReviewNeverConnectsOrWrites()=runBlocking{val f=Fixture();assertEquals(KnownFileRestoreAction.APPLY,f.review()!!.action);assertEquals(0,f.connects);assertNull(f.own)}
    @Test fun writeOccursOnlyAfterDurableCreateAndConsumedToken()=runBlocking{val f=Fixture();val r=f.review()!!;assertTrue(f.port.perform(r) is KnownFileRestoreResult.Recorded);assertEquals(1,f.writes);assertEquals(1,f.creates);assertEquals(KnownFileRestorePhase.NEEDS_CHECK,f.phase());f.port.perform(r);assertEquals(1,f.writes)}
    @Test fun missingRemotePlanDoesNotCreateOrWrite()=runBlocking{val f=Fixture();f.prepareMissing=true;assertTrue(f.apply() is KnownFileRestoreResult.Unavailable);assertEquals(0,f.creates);assertEquals(0,f.writes)}
    @Test fun createFailureCannotDispatch()=runBlocking{val f=Fixture();f.rejectCreate=true;f.apply();assertEquals(0,f.writes)}
    @Test fun writeFailureRetainsExactUncertainty()=runBlocking{val f=Fixture();f.failWrite=true;assertTrue(f.apply() is KnownFileRestoreResult.Recorded);assertEquals(KnownFileRestorePhase.APPLYING,f.phase());assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.own!!.snapshot.status)}
    @Test fun cancelAfterCheckpointNeverReplays()=runBlocking{val f=Fixture();f.cancelWrite=true;assertTrue(runCatching{f.apply()}.exceptionOrNull() is CancellationException);assertEquals(KnownFileRestorePhase.APPLYING,f.phase());assertEquals(KnownFileRestoreAction.READ,f.review()!!.action);assertEquals(1,f.writes);assertEquals(1,f.sshClosed)}
    @Test fun partialReadRetainsBarrierAndAllowsSeparateReturn()=runBlocking{val f=Fixture();f.apply();val c=f.own;val p=f.read() as KnownFileRestoreResult.Checked;assertFalse(p.terminal);assertTrue(p.mayReturn);assertEquals(c,f.own);assertEquals(1,f.writes);assertEquals(KnownFileRestoreAction.RETURN,f.returnReview(p.evidence)!!.action)}
    @Test fun independentCompleteReadTerminatesOnlyApply()=runBlocking{val f=Fixture();f.writeDesired=true;f.apply();assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.own!!.snapshot.status);val p=f.read() as KnownFileRestoreResult.Checked;assertTrue(p.terminal);assertFalse(p.mayReturn);assertEquals(KnownFileRestorePhase.APPLIED,f.phase());assertEquals(OperationStatus.SUCCEEDED,f.own!!.snapshot.status);assertNull(f.returnReview(p.evidence))}
    @Test fun returnNeedsOwnReviewAndNextCasThenSeparateRead()=runBlocking{val f=Fixture();f.apply();val p=f.read() as KnownFileRestoreResult.Checked;val r=f.returnReview(p.evidence)!!;val before=f.own!!.revision;f.port.perform(r);assertEquals(2,f.writes);assertTrue(f.own!!.revision.value>before.value);assertEquals(KnownFileRestorePhase.RETURN_NEEDS_CHECK,f.phase());val checked=f.read() as KnownFileRestoreResult.Checked;assertTrue(checked.terminal);assertEquals(KnownFileRestorePhase.RETURNED,f.phase());assertEquals(OperationStatus.FAILED,f.own!!.snapshot.status)}
    @Test fun unknownReturnCannotReplayCompensation()=runBlocking{val f=Fixture();f.apply();val p=f.read() as KnownFileRestoreResult.Checked;val r=f.returnReview(p.evidence)!!;f.failWrite=true;f.port.perform(r);assertEquals(KnownFileRestorePhase.RETURNING,f.phase());assertNull(f.returnReview(p.evidence));assertEquals(KnownFileRestoreAction.READ,f.review()!!.action)}
    @Test fun casFailureBeforeReturnBlocksWriter()=runBlocking{val f=Fixture();f.apply();val p=f.read() as KnownFileRestoreResult.Checked;val r=f.returnReview(p.evidence)!!;f.rejectCas=true;f.port.perform(r);assertEquals(1,f.writes)}
    @Test fun missingManifestCannotClearBarrier()=runBlocking{val f=Fixture();f.apply();val c=f.own;f.available=false;assertTrue(f.read() is KnownFileRestoreResult.Unavailable);assertEquals(c,f.own)}
    @Test fun freshReadCannotPublishForeignOrFutureProof()=runBlocking{val f=Fixture();f.apply();f.foreign=true;assertTrue(f.read() is KnownFileRestoreResult.Unavailable);f.foreign=false;f.future=true;assertTrue(f.read() is KnownFileRestoreResult.Unavailable)}
    @Test fun sourceRevisionDriftAfterPreparationBlocksCreate()=runBlocking{val f=Fixture();f.afterPrepare={f.comparisonParent=f.comparisonParent.copy(revision=OperationRevision(99))};f.apply();assertEquals(0,f.creates);assertEquals(0,f.writes)}
    @Test fun credentialDriftAfterPrepareBlocksCreate()=runBlocking{val f=Fixture();f.afterPrepare={f.currentReview=f.review.copy(access=f.access.copy(auth=SshAuthRef.Password(SecretId("foreign"))))};f.apply();assertEquals(0,f.creates)}
    @Test fun pinDriftBeforeConnectBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.currentReview=f.review.copy(access=f.access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:foreign")));f.port.perform(r);assertEquals(0,f.connects)}
    @Test fun lateProofCannotOverwriteParentDrift()=runBlocking{val f=Fixture();f.apply();val c=f.own;f.afterInspect={f.comparisonParent=f.comparisonParent.copy(revision=OperationRevision(88))};assertTrue(f.read() is KnownFileRestoreResult.Unavailable);assertEquals(c,f.own)}
    @Test fun sharedRuntimeLeaseExcludesOtherMutationAndReleases()=runBlocking{val f=Fixture();val r=f.review()!!;val held=f.runtime.withRecoveryPanelReadLease(f.server,OperationId("other")){f.port.perform(r)};assertTrue(held is KnownFileRestoreResult.Unavailable);assertEquals(0,f.connects);assertEquals(true,f.runtime.withBeforeCopyReturnLease(f.server,OperationId("next")){true})}
    @Test fun otherUncertainMutationBlocksOwnRead()=runBlocking{val f=Fixture();f.apply();f.others=listOf(f.own!!.copy(snapshot=f.own!!.snapshot.copy(operationId=OperationId("other"))));assertNull(f.review());assertEquals(1,f.writes)}
    @Test fun processReentryFindsOnlyOwnReadNoWriteAuthority()=runBlocking{val f=Fixture();f.apply();assertEquals(KnownFileRestoreAction.READ,f.review()!!.action);assertEquals(1,f.writes)}
    @Test fun discardAndExpiredTokenNeverConnect()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.discard(r);f.port.perform(r);assertEquals(0,f.connects);val next=f.review()!!;f.at=f.at.plusSeconds(90);f.port.perform(next);assertEquals(0,f.connects)}
    @Test fun reviewTamperingFailsBeforeConnection()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.perform(r.copy(sshLabel="other"));assertEquals(0,f.connects)}
    @Test fun noInspectionOrAutomaticReturnAfterApply()=runBlocking{val f=Fixture();f.apply();assertEquals(0,f.inspections);assertEquals(1,f.writes);assertEquals(1,f.sshClosed)}
    @Test fun reviewQuotaBounded()=runBlocking{val f=Fixture();repeat(8){assertNotNull(f.review())};assertNull(f.review());assertEquals(0,f.connects)}
    private class Fixture{
        var at = Instant.now()
        val server = ServerId("fixture-server")
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
        var checkedParent = VersionedOperationSnapshot(OperationSnapshot(checkId, OperationType.INSTALLATION_RESTORE_CHECK,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(3))
        val comparisonId=OperationId("source-comparison")
        val comparisonBinding=RestoreCompatibilityBindingPolicy.bind(comparisonId,installation,access,checkedParent,backup)
        var comparisonParent=VersionedOperationSnapshot(OperationSnapshot(comparisonId,OperationType.RESTORE_COMPATIBILITY,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(4))

        fun evidence():RecoveryReadinessEvidence{
            val groups=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,1,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
            return RecoveryReadinessEvidence(ManagementScope(comparisonId,server,access.id,installation.id),comparisonBinding,comparisonParent.revision.value,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups,3,3,1,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.PRESENT,RecoveryQuiescence.STOPPED,"2".repeat(64),at)
        }
        var own:VersionedOperationSnapshot?=null;var others:List<VersionedOperationSnapshot> = emptyList()
        var connects=0;var sshClosed=0;var preparations=0;var writes=0;var inspections=0;var creates=0;var advances=0
        var available=true;var cancelWrite=false;var failWrite=false;var writeDesired=false;var rejectCreate=false;var rejectCas=false
        var desired=0;var foreign=false;var future=false;var prepareMissing=false
        var afterPrepare:()->Unit={};var afterWrite:()->Unit={};var afterInspect:()->Unit={}
        val local=ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(currentReview)}
        val journal=object:OperationJournal{
            override suspend fun get(operationId:OperationId):OperationJournalResult<VersionedOperationSnapshot> =
                (listOf(comparisonParent,checkedParent,backup)+listOfNotNull(own)).singleOrNull{it.snapshot.operationId==operationId}?.let{OperationJournalResult.Success(it)}?:OperationJournalResult.NotFound
            override suspend fun listNonTerminal():OperationJournalResult<List<VersionedOperationSnapshot>> =OperationJournalResult.Success(others+listOfNotNull(own).filter{it.snapshot.status==OperationStatus.RECONCILIATION_REQUIRED})
            override suspend fun create(initial:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot>{creates++;if(rejectCreate)error("fixture create");check(own==null);val c=VersionedOperationSnapshot(initial,OperationRevision(0));own=c;return OperationJournalResult.Success(c)}
            override suspend fun advance(operationId:OperationId,expectedRevision:OperationRevision,next:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot>{advances++;if(rejectCas)error("fixture CAS");check(own!!.snapshot.operationId==operationId && own!!.revision==expectedRevision);val c=VersionedOperationSnapshot(next,OperationRevision(expectedRevision.value+1));own=c;return OperationJournalResult.Success(c)}
            override suspend fun history(operationId:OperationId):OperationJournalResult<List<OperationJournalEntry>> =error("No fallback")
        }
        val installations=object:XuiInstallationRepository{
            override suspend fun get(installationId:XuiInstallationId):RepositoryResult<VersionedRecord<XuiInstallation>> = RepositoryResult.Success(VersionedRecord(currentReview.installation,RecordRevision(1)))
            override suspend fun listForServer(serverId:ServerId):RepositoryResult<List<VersionedRecord<XuiInstallation>>> = error("No fallback")
            override suspend fun create(installation:XuiInstallation):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun update(installation:XuiInstallation,expectedRevision:RecordRevision):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun delete(installationId:XuiInstallationId,expectedRevision:RecordRevision):RepositoryResult<Unit> = error("No writes")
        }
        val accesses=object:ServerAccessRepository{
            override suspend fun get(serverAccessId:ServerAccessId):RepositoryResult<ServerAccess> = if(serverAccessId==access.id)RepositoryResult.Success(currentReview.access)else RepositoryResult.NotFound
            override suspend fun listForServer(serverId:ServerId):RepositoryResult<List<ServerAccess>> = error("No fallback")
            override suspend fun delete(serverAccessId:ServerAccessId):RepositoryResult<Unit> = error("No writes")
        }

        val factory=object:SshConnectionFactory{
            override suspend fun connect(access:ServerAccess,owner:SessionOwner,config:SshTransportConfig):SshConnectResult{
                connects++;return SshConnectResult.Connected(object:SshSessionHandle{
                    override val binding=SessionBinding(SessionId("readiness-fixture"),access.id,owner)
                    override var isOpen=true
                    override suspend fun execute(command:RemoteCommand,config:SshTransportConfig):SshCommandResult=error("Injected typed inspection only")
                    override fun close(){if(isOpen){isOpen=false;sshClosed++}}
                })
            }
        }
        val runtime=OperationRuntimeCoordinator(journal,accesses,factory,ExactSessionRegistry(),installationRepository=installations)
        val port=RepositoryKnownFileRestorePort(local,journal,factory,{s,id,action->runtime.withBeforeCopyReturnLease(s,id,action)},
            prepare={scope,b,_,session->preparations++;assertTrue(session.isOpen);afterPrepare();if(prepareMissing)null else KnownFileRestorePrepared(scope,b,"3".repeat(64),at)},
            write={d,c,_,session->writes++;assertTrue(session.isOpen);assertEquals(own,c);assertTrue(d.consumeOnce(c,at));assertFalse(d.consumeOnce(c,at));if(cancelWrite)throw CancellationException("fixture");if(failWrite)error("unknown remote outcome");if(writeDesired)desired=if(d.action==KnownFileRestoreWrite.APPLY)1 else 0;afterWrite();true},
            inspect={scope,b,_,session->inspections++;assertTrue(session.isOpen);afterInspect();if(!available)null else KnownFileRestoreInspection(if(foreign)scope.copy(serverId=ServerId("foreign"))else scope,b,"4".repeat(64),"3".repeat(64),desired,1-desired,if(future)at.plusSeconds(1)else at)},
            now={at},idFactory={OperationId("files")})
        suspend fun review()=port.review(server.value,installation.id.value,access.id.value,comparisonId.value,null,if(own==null)evidence()else null)
        suspend fun apply()=port.perform(requireNotNull(review()))
        suspend fun read()=port.perform(requireNotNull(port.review(server.value,installation.id.value,access.id.value,comparisonId.value,own!!.snapshot.operationId.value,null)))
        suspend fun returnReview(proof:KnownFileRestoreInspection)=port.review(server.value,installation.id.value,access.id.value,comparisonId.value,own!!.snapshot.operationId.value,null,proof)
        fun phase()=KnownFileRestoreBinding.parse(own!!.snapshot.checkpoint.phaseName)!!.first
    }
}
