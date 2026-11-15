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
class BeforeCopyEvidenceProductionTest {
    @Test fun localReviewNeverConnects(){runBlocking{val f=Fixture();assertNotNull(f.review());assertEquals(0,f.connects);assertEquals(0,f.inspections)}}
    @Test fun exactReadClosesSsh(){runBlocking{val f=Fixture();assertTrue(f.read() is BeforeCopyResult.Observed);assertEquals(1,f.connects);assertEquals(1,f.inspections);assertEquals(1,f.sshClosed)}}
    @Test fun uncertainParentMayReadWithoutClearingItsJournal(){runBlocking{val f=Fixture();f.uncertain();val before=f.parent;assertTrue(f.read() is BeforeCopyResult.Observed);assertEquals(before,f.parent)}}
    @Test fun pendingParentCannotReview(){runBlocking{val f=Fixture();f.parent=f.parent.copy(snapshot=f.parent.snapshot.copy(status=OperationStatus.RUNNING,checkpoint=f.parent.snapshot.checkpoint.copy(semantics=CheckpointSemantics.MUTATION_NOT_STARTED)));assertNull(f.review())}}
    @Test fun failedParentCannotReview(){runBlocking{val f=Fixture();f.parent=f.parent.copy(snapshot=f.parent.snapshot.copy(status=OperationStatus.FAILED));assertNull(f.review())}}
    @Test fun discardedTokenCannotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.discard(r);assertTrue(f.port.read(r) is BeforeCopyResult.Unavailable);assertEquals(0,f.connects)}}
    @Test fun consumedTokenCannotConnectAgain(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.read(r);f.port.read(r);assertEquals(1,f.connects)}}
    @Test fun expiredTokenCannotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.at=f.at.plusSeconds(90);f.port.read(r);assertEquals(0,f.connects)}}
    @Test fun tamperedPublicReviewCannotConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.port.read(r.copy(sshLabel="other"));assertEquals(0,f.connects)}}
    @Test fun changedParentRevisionBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.parent=f.parent.copy(revision=OperationRevision(88));f.port.read(r);assertEquals(0,f.connects)}}
    @Test fun changedBackupRevisionBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.backup=f.backup.copy(revision=OperationRevision(88));f.port.read(r);assertEquals(0,f.connects)}}
    @Test fun changedCredentialReferenceBlocksBeforeConnect(){runBlocking{val f=Fixture();val r=f.review()!!;f.currentReview=f.review.copy(access=f.access.copy(auth=SshAuthRef.Password(SecretId("changed"))));f.port.read(r);assertEquals(0,f.connects)}}
    @Test fun otherNonterminalSameServerBlocksRead(){runBlocking{val f=Fixture();f.others=listOf(f.current.copy(snapshot=f.current.snapshot.copy(status=OperationStatus.RUNNING)));assertNull(f.review());assertEquals(0,f.connects)}}
    @Test fun exactUncertainParentInNonterminalListDoesNotBlockRead(){runBlocking{val f=Fixture();f.uncertain();f.others=listOf(f.parent);assertTrue(f.read() is BeforeCopyResult.Observed)}}
    @Test fun unavailableProofCannotInventBeforeCopy(){runBlocking{val f=Fixture();f.proofAvailable=false;assertTrue(f.read() is BeforeCopyResult.Unavailable);assertEquals(1,f.sshClosed)}}
    @Test fun foreignProofCannotInventExactTarget(){runBlocking{val f=Fixture();f.proofForeign=true;assertTrue(f.read() is BeforeCopyResult.Unavailable)}}
    @Test fun staleProofCannotBecomeCurrentEvidence(){runBlocking{val f=Fixture();f.proofStale=true;assertTrue(f.read() is BeforeCopyResult.Unavailable)}}
    @Test fun sourceDriftDuringReadCannotPublish(){runBlocking{val f=Fixture();f.afterInspect={f.parent=f.parent.copy(revision=OperationRevision(99))};assertTrue(f.read() is BeforeCopyResult.Unavailable);assertEquals(1,f.sshClosed)}}
    @Test fun sharedLeaseExcludesReadAndReleases(){runBlocking{val f=Fixture();val r=f.review()!!;val result=f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("competing")){f.port.read(r)};assertTrue(result is BeforeCopyResult.Unavailable);assertEquals(0,f.connects);assertEquals(true,f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("next")){true})}}
    @Test fun cancellationClosesSessionAndConsumesToken(){runBlocking{val f=Fixture();f.inspectCancel=true;val r=f.review()!!;assertTrue(runCatching{f.port.read(r)}.exceptionOrNull() is CancellationException);assertEquals(1,f.sshClosed);f.port.read(r);assertEquals(1,f.connects)}}
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
            override suspend fun listNonTerminal():OperationJournalResult<List<VersionedOperationSnapshot>> = OperationJournalResult.Success(others)
            override suspend fun create(initial:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot> = error("No journal writes")
            override suspend fun advance(operationId:OperationId,expectedRevision:OperationRevision,next:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot> = error("No journal writes")
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
                    override val binding=SessionBinding(SessionId("fixture-panel-session"),access.id,owner)
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
        val port=RepositoryBeforeCopyEvidencePort(local,journal,sshFactory,
            {server,id,read->runtime.withRecoveryPanelReadLease(server,id,read)},
            {scope,b,session->
                inspections++;assertTrue(session.isOpen)
                if(inspectCancel)throw CancellationException("fixture")
                afterInspect()
                if(!proofAvailable)null else BeforeCopyEvidence(if(proofForeign)scope.copy(serverId=ServerId("foreign"))else scope,b,"1".repeat(64),"2".repeat(64),4096,
                    BeforeCopyService.INACTIVE,BeforeCopyCurrent.DIFFERENT,BeforeCopyStructure.MATCH,BeforeCopyCompletion.PARTIAL,if(proofStale)at.minusSeconds(1)else at)
            },{at})
        suspend fun review()=port.review(review.serverId,review.installationId,review.accessId,parent.snapshot.operationId.value)
        suspend fun read()=port.read(requireNotNull(review()))
        fun uncertain(){parent=parent.copy(snapshot=parent.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint=OperationCheckpoint(restoreBinding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))}
    }
}
