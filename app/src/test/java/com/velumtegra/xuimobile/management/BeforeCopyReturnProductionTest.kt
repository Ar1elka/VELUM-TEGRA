package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.core.webpanel.*
import kotlinx.coroutines.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class BeforeCopyReturnProductionTest {
    @Test fun localReviewNeverConnectsOrWrites(){runBlocking{val f=Fixture();assertNotNull(f.review());assertEquals(0,f.connects);assertEquals(0,f.journalWrites)}}
    @Test fun copySeesDurableCheckpointAndClosesSession(){runBlocking{val f=Fixture();assertTrue(f.perform() is BeforeCopyReturnResult.Recorded);assertEquals(BeforeCopyReturnPhase.RETURNING,BeforeCopyReturnBinding.parse(f.checkpointSeen!!.snapshot.checkpoint.phaseName)!!.first);assertEquals(1,f.copies);assertEquals(1,f.sshClosed)}}
    @Test fun dispatchCompletionIsNotReadbackProof(){runBlocking{val f=Fixture();assertTrue(f.perform() is BeforeCopyReturnResult.Recorded);assertEquals(0,f.verifies)}}
    @Test fun consumedTokenDoesNotReplayCopy(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.perform(r);f.port.perform(r);assertEquals(1,f.copies)}}
    @Test fun expiredTokenDoesNotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.at=f.at.plusSeconds(90);f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun tamperedReviewDoesNotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.perform(r.copy(sshLabel="foreign"));assertEquals(0,f.connects)}}
    @Test fun terminalOriginalCannotBeReopened(){runBlocking{val f=Fixture();f.parent=f.parent.copy(snapshot=f.parent.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=f.parent.snapshot.checkpoint.copy(semantics=CheckpointSemantics.TERMINAL)));assertNull(f.review())}}
    @Test fun activeServiceEvidenceCannotAuthorizeCopy(){runBlocking{val f=Fixture();assertNull(f.review(f.evidence().copy(service=BeforeCopyService.ACTIVE,current=BeforeCopyCurrent.UNAVAILABLE)))}}
    @Test fun sameCurrentDatabaseCannotAuthorizeCopy(){runBlocking{val f=Fixture();assertNull(f.review(f.evidence().copy(current=BeforeCopyCurrent.SAME)))}}
    @Test fun changedStructureCannotAuthorizeCopy(){runBlocking{val f=Fixture();assertNull(f.review(f.evidence().copy(structure=BeforeCopyStructure.DIFFERENT)))}}
    @Test fun staleEvidenceCannotAuthorizeCopy(){runBlocking{val f=Fixture();assertNull(f.review(f.evidence().copy(observedAt=f.at.minusSeconds(301))))}}
    @Test fun credentialDriftBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.currentReview=f.review.copy(access=f.access.copy(auth=SshAuthRef.Password(SecretId("other"))));f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun parentRevisionDriftBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.parent=f.parent.copy(revision=OperationRevision(99));f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun otherUncertainOperationBlocksReturn(){runBlocking{val f=Fixture();f.others=listOf(f.current.copy(snapshot=f.current.snapshot.copy(status=OperationStatus.RUNNING)));assertNull(f.review())}}
    @Test fun sharedMutationLeaseExcludesDispatch(){runBlocking{val f=Fixture();val r=f.review()!!;val result=f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("other")){f.port.perform(r)};assertTrue(result is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.connects)}}
    @Test fun separateReadbackCannotCopyAgain(){runBlocking{val f=Fixture();f.perform();val r=f.review(null)!!;assertEquals(BeforeCopyReturnAction.READ_RESULT,r.action);assertTrue(f.port.perform(r) is BeforeCopyReturnResult.Checked);assertEquals(1,f.copies);assertEquals(1,f.verifies)}}
    @Test fun durableBindingRequiresNoOldEvidenceForReadback(){runBlocking{val f=Fixture();f.perform();assertNotNull(f.port.review(f.review.serverId,f.review.installationId,f.review.accessId,f.parent.snapshot.operationId.value,null))}}
    @Test fun cancellationAfterCheckpointKeepsNoReplayBarrier(){runBlocking{val f=Fixture();f.copyCancel=true;assertTrue(runCatching{f.perform()}.exceptionOrNull() is CancellationException);assertEquals(BeforeCopyReturnAction.READ_RESULT,f.review(null)!!.action);assertEquals(1,f.sshClosed)}}
    @Test fun unknownCopyResultHasOnlyReadback(){runBlocking{val f=Fixture();f.copyOkay=false;f.perform();assertEquals(BeforeCopyReturnAction.READ_RESULT,f.review(null)!!.action);assertEquals(1,f.copies)}}
    @Test fun unavailableReadbackKeepsUncertainRow(){runBlocking{val f=Fixture();f.perform();val before=f.parent;f.verifyOkay=false;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(before,f.parent)}}
    @Test fun foreignReadbackCannotPublish(){runBlocking{val f=Fixture();f.perform();f.verifyForeign=true;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable)}}
    @Test fun checkedReturnNeverClearsBarrierOrClaimsWorkingRecovery(){runBlocking{val f=Fixture();f.perform();f.perform();assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.parent.snapshot.status);assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED,f.parent.snapshot.checkpoint.semantics);assertTrue(DurableServerMutationBarrierPolicy.evaluate(f.installation.serverId,listOf(f.parent.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)}}
    @Test fun failedJournalCasCannotDispatchCopy(){runBlocking{val f=Fixture();f.journalFails=true;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.copies)}}
    @Test fun cancellationDuringFreshObservationDoesNotCheckpoint(){runBlocking{val f=Fixture();f.inspectCancel=true;assertTrue(runCatching{f.perform()}.exceptionOrNull() is CancellationException);assertEquals(0,f.journalWrites);assertEquals(0,f.copies);assertEquals(1,f.sshClosed)}}
    @Test fun discardedTokenCannotDispatch(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.discard(r);f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun freshObservationUnavailableCannotCheckpoint(){runBlocking{val f=Fixture();f.proofAvailable=false;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.journalWrites)}}
    @Test fun changedCopyHashDuringFreshObservationCannotDispatch(){runBlocking{val f=Fixture();f.observeWrongHash=true;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.journalWrites);assertEquals(0,f.copies)}}
    @Test fun sourceRevisionChangesDuringObservationCannotDispatch(){runBlocking{val f=Fixture();f.afterInspect={f.parent=f.parent.copy(revision=OperationRevision(99))};assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.copies)}}
    @Test fun foreignSessionOwnershipBlocksBeforeCommand(){runBlocking{val f=Fixture();f.foreignSession=true;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.inspections);assertEquals(1,f.sshClosed)}}
    @Test fun staleReadbackCannotPublish(){runBlocking{val f=Fixture();f.perform();f.verifyStale=true;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable)}}
    @Test fun failedReadbackJournalCasCannotPublishSuccess(){runBlocking{val f=Fixture();f.perform();f.journalFails=true;assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable)}}
    @Test fun sharedLeaseReleasesAfterCancelledCopy(){runBlocking{val f=Fixture();f.copyCancel=true;runCatching{f.perform()};assertEquals(true,f.runtime.withBeforeCopyReturnLease(f.installation.serverId,OperationId("later")){true})}}
    @Test fun consentExpiryDuringFreshReadCannotCheckpointOrCopy(){runBlocking{val f=Fixture();f.afterInspect={f.at=f.at.plusSeconds(90)};assertTrue(f.perform() is BeforeCopyReturnResult.Unavailable);assertEquals(0,f.journalWrites);assertEquals(0,f.copies)}}
    private class Fixture {
        var at = Instant.now()
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
        val comparisonParent=VersionedOperationSnapshot(OperationSnapshot(comparisonId,OperationType.RESTORE_COMPATIBILITY,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(4))
        private val restoreId=OperationId("source-restore")
        private val restoreBinding=WorkingDatabaseRestoreBindingPolicy.bind(restoreId,installation,access,comparisonParent,checkedParent,backup)
        var parent=VersionedOperationSnapshot(OperationSnapshot(restoreId,OperationType.WORKING_DATABASE_RESTORE,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(restoreBinding.phaseName(WorkingDatabaseRestorePhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(5))

        private val startId=OperationId("source-start")
        private val startBinding=RestoredPanelStartBindingPolicy.bind(startId,installation,access,parent,comparisonParent,checkedParent,backup)
        var current=VersionedOperationSnapshot(OperationSnapshot(startId,OperationType.RESTORED_PANEL_START,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(startBinding.phaseName(RestoredPanelStartPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(6))
        var panel=WebPanelAccess(WebPanelAccessId("panel"),WebPanelInstallationLink.Linked(installation.id),"admin",SecretId("panel-reference"),WebPanelRoute.Direct("panel.invalid"))
        var panelRevision=RecordRevision(7);var pin:String?="A".repeat(64)
        var auths=0;var apiReads=0;var connects=0;var sessionsClosed=0;var forwardClosed=0;var sshClosed=0
        var failAuth=false;var failApi=false;var cancelAuth=false;var afterApi:()->Unit={}
        var others:List<VersionedOperationSnapshot> = emptyList()
        var proofAvailable=true;var proofForeign=false;var proofStale=false;var inspectCancel=false;var afterInspect:()->Unit={}
        var inspections=0
        val local=ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(currentReview)}
        val journal=object:OperationJournal{
            override suspend fun get(operationId:OperationId):OperationJournalResult<VersionedOperationSnapshot> =
                listOf(current,parent,comparisonParent,checkedParent,backup).singleOrNull{it.snapshot.operationId==operationId}?.let{OperationJournalResult.Success(it)}?:OperationJournalResult.NotFound
            override suspend fun listNonTerminal():OperationJournalResult<List<VersionedOperationSnapshot>> = OperationJournalResult.Success(listOf(parent)+others)
            override suspend fun create(initial:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot> = error("No journal writes")
            override suspend fun advance(operationId:OperationId,expectedRevision:OperationRevision,next:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot>{
                if(journalFails)return OperationJournalResult.StorageFailure("fixture")
                if(operationId!=parent.snapshot.operationId || expectedRevision!=parent.revision)return OperationJournalResult.StaleRevision(expectedRevision,parent.revision)
                if(OperationJournalContractPolicy.validateAdvance(parent.snapshot,next)!=OperationSnapshotValidation.Valid)return OperationJournalResult.InvalidTransition("fixture")
                parent=VersionedOperationSnapshot(next,OperationRevision(expectedRevision.value+1));journalWrites++;return OperationJournalResult.Success(parent)
            }
            override suspend fun history(operationId:OperationId):OperationJournalResult<List<OperationJournalEntry>> = error("No history fallback")
        }
        val panels=object:WebPanelAccessRepository{
            override suspend fun get(webPanelAccessId:WebPanelAccessId):RepositoryResult<VersionedRecord<WebPanelAccess>> = if(webPanelAccessId==panel.id)RepositoryResult.Success(VersionedRecord(panel,panelRevision))else RepositoryResult.NotFound
            override suspend fun list():RepositoryResult<List<VersionedRecord<WebPanelAccess>>> = RepositoryResult.Success(listOf(VersionedRecord(panel,panelRevision)))
            override suspend fun updateMetadata(access:WebPanelAccess,expectedRevision:RecordRevision):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun delete(webPanelAccessId:WebPanelAccessId,expectedRevision:RecordRevision):RepositoryResult<Unit> = error("No writes")
        }
        val installations=object:XuiInstallationRepository{
            override suspend fun get(installationId:XuiInstallationId):RepositoryResult<VersionedRecord<XuiInstallation>> = RepositoryResult.Success(VersionedRecord(currentReview.installation,RecordRevision(1)))
            override suspend fun listForServer(serverId:ServerId):RepositoryResult<List<VersionedRecord<XuiInstallation>>> = error("No fallback")
            override suspend fun create(installation:XuiInstallation):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun update(installation:XuiInstallation,expectedRevision:RecordRevision):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun delete(installationId:XuiInstallationId,expectedRevision:RecordRevision):RepositoryResult<Unit> = error("No writes")
        }
        val servers=object:ServerRepository{
            override suspend fun get(serverId:ServerId):RepositoryResult<VersionedRecord<Server>> = RepositoryResult.Success(VersionedRecord(Server(server,"fixture",at),RecordRevision(1)))
            override suspend fun list():RepositoryResult<List<VersionedRecord<Server>>> = error("No fallback")
            override suspend fun create(server:Server):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun update(server:Server,expectedRevision:RecordRevision):RepositoryResult<RecordRevision> = error("No writes")
            override suspend fun delete(serverId:ServerId,expectedRevision:RecordRevision):RepositoryResult<Unit> = error("No writes")
        }
        val accesses=object:ServerAccessRepository{
            override suspend fun get(serverAccessId:ServerAccessId):RepositoryResult<ServerAccess> = if(serverAccessId==access.id)RepositoryResult.Success(currentReview.access)else RepositoryResult.NotFound
            override suspend fun listForServer(serverId:ServerId):RepositoryResult<List<ServerAccess>> = error("No fallback")
            override suspend fun delete(serverAccessId:ServerAccessId):RepositoryResult<Unit> = error("No writes")
        }
        val sshFactory=object:SshConnectionFactory{
            override suspend fun connect(access:ServerAccess,owner:SessionOwner,config:SshTransportConfig):SshConnectResult{
                connects++;return SshConnectResult.Connected(object:WebPanelForwardingSshSessionHandle{
                    override val binding=SessionBinding(SessionId("fixture-panel-session"),access.id,if(foreignSession)SessionOwner.Operation(OperationId("foreign"))else owner)
                    override var isOpen=true
                    override suspend fun execute(command:RemoteCommand,config:SshTransportConfig):SshCommandResult=error("No commands")
                    override fun close(){if(isOpen){isOpen=false;sshClosed++}}
                    override fun openWebPanelLocalForward(target:ResolvedWebPanelTarget,config:WebPanelLocalForwardConfig):WebPanelLocalForwardOpenResult{
                        val b=binding
                        val resolvedTarget=target
                        return WebPanelLocalForwardOpenResult.Opened(object:WebPanelLocalForwardHandle{
                            override val sessionBinding=b
                            override val target=resolvedTarget
                            override val localEndpoint=WebPanelLoopbackEndpoint::class.java.declaredConstructors.single{it.parameterCount==1}.let{it.isAccessible=true;it.newInstance(12345) as WebPanelLoopbackEndpoint}
                            override var isOpen=true
                            override fun close(){if(isOpen){isOpen=false;forwardClosed++}}
                        })
                    }
                })
            }
        }
        val runtime=OperationRuntimeCoordinator(journal,accesses,sshFactory,ExactSessionRegistry(),installationRepository=installations)

        var journalFails=false;var journalWrites=0;var copies=0;var verifies=0;var copyCancel=false;var copyOkay=true;var verifyOkay=true;var verifyForeign=false
        var checkpointSeen:VersionedOperationSnapshot?=null
        var observeWrongHash=false;var foreignSession=false;var verifyStale=false
        fun evidence()=BeforeCopyEvidence(ManagementScope(parent.snapshot.operationId,installation.serverId,access.id,installation.id),restoreBinding,
            "1".repeat(64),"2".repeat(64),4096,BeforeCopyService.INACTIVE,BeforeCopyCurrent.DIFFERENT,BeforeCopyStructure.MATCH,BeforeCopyCompletion.PARTIAL,at)
        val port=RepositoryBeforeCopyReturnPort(local,journal,sshFactory,
            {server,id,action->runtime.withBeforeCopyReturnLease(server,id,action)},
            {scope,b,session->inspections++;if(inspectCancel)throw CancellationException("fixture");afterInspect();if(!proofAvailable)null else evidence().copy(scope=scope,binding=b,databaseSha256=if(observeWrongHash)"f".repeat(64)else "1".repeat(64))},
            {d,c,session->checkpointSeen=parent;assertEquals(parent,c);assertTrue(d.consumeOnce(c,at));copies++;if(copyCancel)throw CancellationException("fixture");copyOkay},
            {scope,b,session->verifies++;if(!verifyOkay)null else BeforeCopyReturnReceipt(if(verifyForeign)scope.copy(serverId=ServerId("foreign"))else scope,b,"3".repeat(64),4096,if(verifyStale)at.minusSeconds(1)else at)},
            {at})
        suspend fun review(e:BeforeCopyEvidence?=evidence())=port.review(review.serverId,review.installationId,review.accessId,parent.snapshot.operationId.value,e)
        suspend fun perform()=port.perform(requireNotNull(review()))
        fun uncertain(){parent=parent.copy(snapshot=parent.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint=OperationCheckpoint(restoreBinding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))}
        init{uncertain()}
    }
}
