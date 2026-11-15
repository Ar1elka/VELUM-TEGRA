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

/** Actual production authority/consumption/session flow, real shared runtime gate and fake network sessions. */
class RecoveryPanelCheckProductionTest {
    @Test fun reviewAndListingNeverConnectOrAuthenticate()=runBlocking{val f=Fixture();assertEquals(1,f.choices().size);assertNotNull(f.review());assertEquals(0,f.auths);assertEquals(0,f.connects)}
    @Test fun oneLoginOneApiAndClosedSession()=runBlocking{val f=Fixture();assertTrue(f.check() is RecoveryPanelCheckResult.Verified);assertEquals(1,f.auths);assertEquals(1,f.apiReads);assertEquals(1,f.sessionsClosed)}
    @Test fun consumedReviewCannotResubmit()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.check(r);assertTrue(f.port.check(r) is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.auths)}
    @Test fun newReviewOfSameSourcePanelCannotRepeatPassword()=runBlocking{val f=Fixture();f.check();val r=f.review()!!;assertTrue(f.port.check(r) is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.auths)}
    @Test fun dismissedReviewNeverSubmits()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.discard(r);f.port.check(r);assertEquals(0,f.auths)}
    @Test fun expiredReviewNeverSubmits()=runBlocking{val f=Fixture();val r=f.review()!!;f.at=f.at.plusSeconds(91);f.port.check(r);assertEquals(0,f.auths)}
    @Test fun tamperedPublicReviewNeverSubmits()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.check(r.copy(username="changed"));assertEquals(0,f.auths)}
    @Test fun changedPanelRevisionBlocksBeforeCredentials()=runBlocking{val f=Fixture();val r=f.review()!!;f.panelRevision=RecordRevision(8);f.port.check(r);assertEquals(0,f.auths)}
    @Test fun changedPasswordReferenceBlocksBeforeCredentials()=runBlocking{val f=Fixture();val r=f.review()!!;f.panel=f.panel.copy(passwordSecretId=SecretId("changed"));f.port.check(r);assertEquals(0,f.auths)}
    @Test fun changedSourceRevisionBlocksBeforeCredentials()=runBlocking{val f=Fixture();val r=f.review()!!;f.current=f.current.copy(revision=OperationRevision(9));f.port.check(r);assertEquals(0,f.auths)}
    @Test fun changedParentInvalidatesFullSourceChain()=runBlocking{val f=Fixture();val r=f.review()!!;f.parent=f.parent.copy(revision=OperationRevision(8));f.port.check(r);assertEquals(0,f.auths)}
    @Test fun otherInstallationHasNoCandidate()=runBlocking{val f=Fixture();f.panel=f.panel.copy(installationLink=WebPanelInstallationLink.Linked(XuiInstallationId("elsewhere")));assertTrue(f.choices().isEmpty());assertNull(f.review())}
    @Test fun unknownStartCannotReviewCredentials()=runBlocking{val f=Fixture();f.current=f.current.copy(snapshot=f.current.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED));assertNull(f.review());assertEquals(0,f.auths)}
    @Test fun privatePinMissingBlocksWithoutDirectFallback()=runBlocking{val f=Fixture();f.privateRoute();f.pin=null;assertNull(f.review());assertEquals(0,f.connects);assertEquals(0,f.auths)}
    @Test fun privateRouteUsesExactOwnerPinAndClosesBothHandles()=runBlocking{val f=Fixture();f.privateRoute();assertTrue(f.check() is RecoveryPanelCheckResult.Verified);assertEquals(1,f.connects);assertEquals(1,f.forwardClosed);assertEquals(1,f.sshClosed);assertEquals(1,f.auths)}
    @Test fun changedPrivatePinBlocksBeforeSsh()=runBlocking{val f=Fixture();f.privateRoute();val r=f.review()!!;f.pin="B".repeat(64);f.port.check(r);assertEquals(0,f.connects)}
    @Test fun anotherSshProfileCannotReplaceAcceptedOwner()=runBlocking{val f=Fixture();f.panel=f.panel.copy(route=WebPanelRoute.SshTunnel(ServerAccessId("elsewhere")));assertNull(f.review());assertEquals(0,f.connects)}
    @Test fun authFailureCannotPublishApiReceipt()=runBlocking{val f=Fixture();f.failAuth=true;assertTrue(f.check() is RecoveryPanelCheckResult.Unverified);assertEquals(0,f.apiReads);assertEquals(1,f.auths)}
    @Test fun apiFailureClosesSessionWithoutSuccess()=runBlocking{val f=Fixture();f.failApi=true;assertTrue(f.check() is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.sessionsClosed)}
    @Test fun staleTargetDuringApiCannotPublishReceipt()=runBlocking{val f=Fixture();f.afterApi={f.panelRevision=RecordRevision(99)};assertTrue(f.check() is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.sessionsClosed)}
    @Test fun sharedRuntimeGateBlocksParallelRecoveryAndReleases()=runBlocking{val f=Fixture();val r=f.review()!!;val held=f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("competing")){f.port.check(r)};assertTrue(held is RecoveryPanelCheckResult.Unverified);assertEquals(0,f.auths);assertEquals(true,f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("next")){true})}
    @Test fun cancellationClosesPrivateForwardAndCannotReplay()=runBlocking{val f=Fixture();f.privateRoute();f.cancelAuth=true;val r=f.review()!!;assertTrue(runCatching{f.port.check(r)}.exceptionOrNull() is CancellationException);assertEquals(1,f.forwardClosed);assertEquals(1,f.sshClosed);assertTrue(f.port.check(r) is RecoveryPanelCheckResult.Unverified);assertEquals(1,f.auths)}
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
        val local=ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(currentReview)}
        val journal=object:OperationJournal{
            override suspend fun get(operationId:OperationId):OperationJournalResult<VersionedOperationSnapshot> =
                listOf(current,parent,comparisonParent,checkedParent,backup).singleOrNull{it.snapshot.operationId==operationId}?.let{OperationJournalResult.Success(it)}?:OperationJournalResult.NotFound
            override suspend fun listNonTerminal():OperationJournalResult<List<VersionedOperationSnapshot>> = OperationJournalResult.Success(emptyList())
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
        val port=RepositoryRecoveryPanelCheckPort(local,journal,JournalRestoredPanelStartStatusPort(journal,local,RestoredPanelStartResultRegistry()),
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
            },sshFactory,{pin},{server,id,read->runtime.withRecoveryPanelReadLease(server,id,read)},{at})
        suspend fun choices()=port.choices(review.serverId,review.installationId,review.accessId,startId.value)
        suspend fun review()=port.review(review.serverId,review.installationId,review.accessId,startId.value,panel.id.value)
        suspend fun check()=port.check(requireNotNull(review()))
        fun privateRoute(){panel=panel.copy(route=WebPanelRoute.SshTunnel(access.id))}
    }
}
