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
class CompensatedPanelStartProductionTest {
    @Test fun localReviewDoesNotConnectOrWrite(){runBlocking{val f=Fixture();assertNotNull(f.review());assertEquals(0,f.connects);assertEquals(0,f.journalWrites)}}
    @Test fun startSeesExactDurableSameRowCheckpoint(){runBlocking{val f=Fixture();assertTrue(f.perform() is CompensatedPanelStartResult.Recorded);assertEquals(CompensatedPanelStartPhase.STARTING,CompensatedPanelStartBinding.parse(f.checkpointSeen!!.snapshot.checkpoint.phaseName)!!.first);assertEquals(1,f.starts);assertEquals(1,f.sshClosed)}}
    @Test fun startCompletionIsNotActiveOrAuthProof(){runBlocking{val f=Fixture();f.perform();assertEquals(0,f.verifies);assertNull(f.verifiedSource());assertNull(f.authReview())}}
    @Test fun consumedTokenCannotReplayStart(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.perform(r);f.port.perform(r);assertEquals(1,f.starts)}}
    @Test fun expiredTokenDoesNotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.at=f.at.plusSeconds(90);f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun tamperedReviewCannotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.perform(r.copy(sshLabel="foreign"));assertEquals(0,f.connects)}}
    @Test fun unverifiedReturnCannotAuthorizeStart(){runBlocking{val f=Fixture();val b=BeforeCopyReturnBinding.parse(f.parent.snapshot.checkpoint.phaseName)!!.second;f.parent=f.parent.copy(snapshot=f.parent.snapshot.copy(checkpoint=f.parent.snapshot.checkpoint.copy(phaseName=b.phaseName(BeforeCopyReturnPhase.AWAITING_READBACK))));assertNull(f.review())}}
    @Test fun terminalSourceNeverReopened(){runBlocking{val f=Fixture();f.parent=f.parent.copy(snapshot=f.parent.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=f.parent.snapshot.checkpoint.copy(semantics=CheckpointSemantics.TERMINAL)));assertNull(f.review())}}
    @Test fun changedCredentialBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.currentReview=f.review.copy(access=f.access.copy(auth=SshAuthRef.Password(SecretId("foreign"))));f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun sourceRevisionDriftBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.parent=f.parent.copy(revision=OperationRevision(99));f.port.perform(r);assertEquals(0,f.connects)}}
    @Test fun otherUncertainRowBlocksReview(){runBlocking{val f=Fixture();f.others=listOf(f.current.copy(snapshot=f.current.snapshot.copy(status=OperationStatus.RUNNING)));assertNull(f.review())}}
    @Test fun sharedLeaseBlocksParallelStart(){runBlocking{val f=Fixture();val r=f.review()!!;val result=f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("other")){f.port.perform(r)};assertTrue(result is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.connects)}}
    @Test fun separateReadCannotStartAgain(){runBlocking{val f=Fixture();f.perform();assertEquals(CompensatedPanelStartAction.READ_RESULT,f.review()!!.action);assertTrue(f.perform() is CompensatedPanelStartResult.Checked);assertEquals(1,f.starts);assertEquals(1,f.verifies)}}
    @Test fun cancellationAfterCheckpointRetainsReadOnlyPlan(){runBlocking{val f=Fixture();f.startCancel=true;assertTrue(runCatching{f.perform()}.exceptionOrNull() is CancellationException);assertEquals(CompensatedPanelStartAction.READ_RESULT,f.review()!!.action);assertEquals(1,f.sshClosed)}}
    @Test fun unknownDispatchCannotReplay(){runBlocking{val f=Fixture();f.startOkay=false;f.perform();assertEquals(CompensatedPanelStartAction.READ_RESULT,f.review()!!.action);assertNull(f.authReview())}}
    @Test fun unavailableReadbackRetainsBarrier(){runBlocking{val f=Fixture();f.perform();val c=f.parent;f.verifyOkay=false;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(c,f.parent)}}
    @Test fun foreignReadbackCannotPublish(){runBlocking{val f=Fixture();f.perform();f.verifyForeign=true;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertNull(f.verifiedSource())}}
    @Test fun activeReadbackNeverClearsOriginalBarrier(){runBlocking{val f=Fixture();f.perform();f.perform();assertTrue(DurableServerMutationBarrierPolicy.evaluate(f.installation.serverId,listOf(f.parent.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation);assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.parent.snapshot.status)}}
    @Test fun failedCasDoesNotDispatchStart(){runBlocking{val f=Fixture();f.journalFails=true;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.starts)}}
    @Test fun cancelledFreshReadDoesNotCheckpoint(){runBlocking{val f=Fixture();f.inspectCancel=true;assertTrue(runCatching{f.perform()}.exceptionOrNull() is CancellationException);assertEquals(0,f.journalWrites);assertEquals(0,f.starts);assertEquals(1,f.sshClosed)}}
    @Test fun missingCompletionProofCannotCheckpointOrStart(){runBlocking{val f=Fixture();f.proofAvailable=false;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.journalWrites);assertEquals(0,f.starts)}}
    @Test fun changedBeforeCopyHashDuringFreshReadBlocks(){runBlocking{val f=Fixture();f.observeWrongHash=true;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.starts)}}
    @Test fun sourceChangesDuringFreshReadBlocks(){runBlocking{val f=Fixture();f.afterInspect={f.parent=f.parent.copy(revision=OperationRevision(99))};assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.starts)}}
    @Test fun foreignSessionOwnerBlocksBeforeCommand(){runBlocking{val f=Fixture();f.foreignSession=true;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.inspections);assertEquals(1,f.sshClosed)}}
    @Test fun staleReadbackCannotPublish(){runBlocking{val f=Fixture();f.perform();f.verifyStale=true;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable)}}
    @Test fun readbackCasFailureCannotPublishProof(){runBlocking{val f=Fixture();f.perform();f.journalFails=true;assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertNull(f.verifiedSource())}}
    @Test fun consentExpiryDuringFreshReadBlocksCheckpoint(){runBlocking{val f=Fixture();f.afterInspect={f.at=f.at.plusSeconds(90)};assertTrue(f.perform() is CompensatedPanelStartResult.Unavailable);assertEquals(0,f.journalWrites);assertEquals(0,f.starts)}}
    @Test fun cancelledStartReleasesSameRuntimeLease(){runBlocking{val f=Fixture();f.startCancel=true;runCatching{f.perform()};assertEquals(true,f.runtime.withBeforeCopyReturnLease(f.installation.serverId,OperationId("next")){true})}}
    @Test fun coldProcessMustExplicitlyReadAgainAndCannotStart(){runBlocking{val f=Fixture();f.perform();f.perform();f.port=f.newPort();assertNull(f.verifiedSource());assertNull(f.authReview());assertEquals(CompensatedPanelStartAction.READ_RESULT,f.review()!!.action);f.perform();assertNotNull(f.verifiedSource());assertEquals(1,f.starts)}}
    @Test fun receiptExpiryNeedsAnotherExplicitServiceRead(){runBlocking{val f=Fixture();f.perform();f.perform();f.at=f.at.plusSeconds(90);assertNull(f.verifiedSource());assertNull(f.authReview())}}
    @Test fun foreignAccessCannotUseCachedActiveObservation(){runBlocking{val f=Fixture();f.perform();f.perform();assertNull(f.port.verifiedSource(f.review.serverId,f.review.installationId,"foreign",f.parent.snapshot.operationId.value))}}
    @Test fun activeSourceReviewDoesNotSendCredentials(){runBlocking{val f=Fixture();f.perform();f.perform();assertNotNull(f.authReview());assertEquals(0,f.auths)}}
    @Test fun separatelyReviewedLoginReadsApiAndKeepsBarrier(){runBlocking{val f=Fixture();f.perform();f.perform();val writes=f.journalWrites;assertTrue(f.authCheck() is RecoveryPanelCheckResult.Verified);assertEquals(1,f.auths);assertEquals(1,f.apiReads);assertEquals(writes,f.journalWrites);assertTrue(DurableServerMutationBarrierPolicy.evaluate(f.installation.serverId,listOf(f.parent.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)}}
    @Test fun privateLoginUsesExistingExactRoutePinAndOwner(){runBlocking{val f=Fixture();f.perform();f.perform();f.privateRoute();assertTrue(f.authCheck() is RecoveryPanelCheckResult.Verified);assertEquals(1,f.forwardClosed);assertEquals(3,f.sshClosed)}}
    @Test fun missingPrivatePinCannotFallBackToDirect(){runBlocking{val f=Fixture();f.perform();f.perform();f.privateRoute();f.pin=null;assertNull(f.authReview());assertEquals(0,f.auths)}}
    @Test fun changedPrivatePinBlocksBeforeCredentialSubmission(){runBlocking{val f=Fixture();f.perform();f.perform();f.privateRoute();val r=f.authReview()!!;f.pin="B".repeat(64);f.authPort.check(r);assertEquals(0,f.auths);assertEquals(2,f.connects)}}
    @Test fun changedPasswordReferenceBlocksLogin(){runBlocking{val f=Fixture();f.perform();f.perform();val r=f.authReview()!!;f.panel=f.panel.copy(passwordSecretId=SecretId("changed"));f.authPort.check(r);assertEquals(0,f.auths)}}
    @Test fun changedParentInvalidatesActiveObservationBeforeLogin(){runBlocking{val f=Fixture();f.perform();f.perform();val r=f.authReview()!!;f.backup=f.backup.copy(revision=OperationRevision(99));f.authPort.check(r);assertEquals(0,f.auths)}}
    @Test fun authUnknownOutcomeCannotResubmitPassword(){runBlocking{val f=Fixture();f.perform();f.perform();f.failAuth=true;assertTrue(f.authCheck() is RecoveryPanelCheckResult.Unverified);assertTrue(f.authCheck() is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.auths);assertEquals(0,f.apiReads)}}
    @Test fun apiFailureIsNotAuthenticatedRecoveryProof(){runBlocking{val f=Fixture();f.perform();f.perform();f.failApi=true;assertTrue(f.authCheck() is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.sessionsClosed)}}
    @Test fun sourceDriftDuringApiCannotPublish(){runBlocking{val f=Fixture();f.perform();f.perform();f.afterApi={f.parent=f.parent.copy(revision=OperationRevision(99))};assertTrue(f.authCheck() is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.sessionsClosed)}}
    @Test fun cancelledPrivateLoginClosesForwardAndCannotReplay(){runBlocking{val f=Fixture();f.perform();f.perform();f.privateRoute();f.cancelAuth=true;val r=f.authReview()!!;assertTrue(runCatching{f.authPort.check(r)}.exceptionOrNull() is CancellationException);assertEquals(1,f.forwardClosed);assertEquals(3,f.sshClosed);assertTrue(f.authPort.check(r) is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.auths)}}
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

        var journalFails=false;var journalWrites=0;var starts=0;var verifies=0;var startCancel=false;var startOkay=true;var verifyOkay=true;var verifyForeign=false
        var checkpointSeen:VersionedOperationSnapshot?=null
        var observeWrongHash=false;var foreignSession=false;var verifyStale=false
        fun evidence()=BeforeCopyEvidence(ManagementScope(parent.snapshot.operationId,installation.serverId,access.id,installation.id),restoreBinding,
            "1".repeat(64),"2".repeat(64),4096,BeforeCopyService.INACTIVE,BeforeCopyCurrent.DIFFERENT,BeforeCopyStructure.MATCH,BeforeCopyCompletion.PARTIAL,at)
        fun newPort()=RepositoryCompensatedPanelStartPort(local,journal,sshFactory,
            {server,id,action->runtime.withBeforeCopyReturnLease(server,id,action)},
            {scope,b,session->inspections++;if(inspectCancel)throw CancellationException("fixture");afterInspect();if(!proofAvailable)null else BeforeCopyReturnReceipt(scope,if(observeWrongHash)b.copy(beforeDatabaseSha256="f".repeat(64))else b,"3".repeat(64),4096,at)},
            {d,c,session->checkpointSeen=parent;assertEquals(parent,c);assertTrue(d.consumeOnce(c,at));starts++;if(startCancel)throw CancellationException("fixture");startOkay},
            {scope,b,session->verifies++;if(!verifyOkay)null else CompensatedPanelStartReceipt(if(verifyForeign)scope.copy(serverId=ServerId("foreign"))else scope,b,"4".repeat(64),2,if(verifyStale)at.minusSeconds(1)else at)},
            {at})
        var port=newPort()
        suspend fun review()=port.review(review.serverId,review.installationId,review.accessId,parent.snapshot.operationId.value)
        suspend fun perform()=port.perform(requireNotNull(review()))
        suspend fun verifiedSource()=port.verifiedSource(review.serverId,review.installationId,review.accessId,parent.snapshot.operationId.value)
        val authPort=RepositoryRecoveryPanelCheckPort(local,journal,JournalRestoredPanelStartStatusPort(journal,local,RestoredPanelStartResultRegistry()),
            panels,ExactWebPanelTargetResolver(panels,installations,servers,accesses),object:WebPanelAuthenticationClient{
                override suspend fun authenticate(request:WebPanelAuthenticationRequest):WebPanelAuthenticationResult{
                    auths++;assertTrue(request.credentialAuthority())
                    if(cancelAuth)throw CancellationException("scripted cancel")
                    if(failAuth)return WebPanelAuthenticationResult.Failed(WebPanelAuthenticationFailureEvidence(WebPanelAuthenticationStage.LOGIN,WebPanelAuthenticationFailure.LOGIN_OUTCOME_UNKNOWN,CredentialSubmissionState.OUTCOME_UNKNOWN))
                    if(panel.route is WebPanelRoute.SshTunnel){val t=request.transport as WebPanelAuthenticationTransport.SshTunnel;assertEquals("A".repeat(64),t.pinnedCertificate!!.sha256);assertEquals(SessionOwner.WebPanel(panel.id),t.forward.sessionBinding.owner)}
                    return WebPanelAuthenticationResult.Authenticated(object:WebPanelServerStatusSession{
                        override val target=request.target
                        override val webPanelAccessId=request.target.webPanelAccessId
                        override var isOpen=true
                        override fun close(){if(isOpen){isOpen=false;sessionsClosed++}}
                        override suspend fun readServerStatusOnce():WebPanelServerStatusResult{
                            apiReads++;afterApi();return if(failApi)WebPanelServerStatusResult.Failed(WebPanelServerStatusFailure.AUTH_REQUIRED)
                            else WebPanelServerStatusResult.Success(WebPanelServerStatusSnapshot(1.0,null,null,null,null,null))
                        }
                    })
                }
            },sshFactory,{pin},{server,id,read->runtime.withRecoveryPanelReadLease(server,id,read)},{at},{s,i,a,id->port.verifiedSource(s,i,a,id)})
        suspend fun authReview()=authPort.review(review.serverId,review.installationId,review.accessId,parent.snapshot.operationId.value,panel.id.value)
        suspend fun authCheck()=authPort.check(requireNotNull(authReview()))
        fun privateRoute(){panel=panel.copy(route=WebPanelRoute.SshTunnel(access.id))}
        fun uncertain(){parent=parent.copy(snapshot=parent.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint=OperationCheckpoint(restoreBinding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))}
        init{uncertain();val b=BeforeCopyReturnPolicy.bind(parent,evidence(),at)!!;parent=parent.copy(revision=OperationRevision(7),snapshot=parent.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))}
    }
}
