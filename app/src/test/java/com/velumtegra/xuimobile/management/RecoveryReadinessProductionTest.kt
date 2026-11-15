package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
/** Actual production consumption, journal lineage and shared runtime lease; scripted sessions only. */
class RecoveryReadinessProductionTest {
    @Test fun localReviewNeverConnects()=runBlocking{val f=Fixture();assertNotNull(f.review());assertEquals(0,f.connects);assertEquals(0,f.inspections)}
    @Test fun exactReadClosesSessionWithoutJournalWrite()=runBlocking{val f=Fixture();val before=f.comparisonParent;assertTrue(f.read() is RecoveryReadinessResult.Observed);assertEquals(before,f.comparisonParent);assertEquals(1,f.inspections);assertEquals(1,f.sshClosed)}
    @Test fun pendingComparisonCannotReview()=runBlocking{val f=Fixture();f.comparisonParent=f.comparisonParent.copy(snapshot=f.comparisonParent.snapshot.copy(status=OperationStatus.RUNNING));assertNull(f.review())}
    @Test fun failedComparisonCannotReview()=runBlocking{val f=Fixture();f.comparisonParent=f.comparisonParent.copy(snapshot=f.comparisonParent.snapshot.copy(status=OperationStatus.FAILED));assertNull(f.review())}
    @Test fun uncertainSameServerBarrierCannotBeClearedOrBypassed()=runBlocking{val f=Fixture();f.others=listOf(f.comparisonParent.copy(snapshot=f.comparisonParent.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED)));assertNull(f.review());assertEquals(1,f.others.size);assertEquals(0,f.connects)}
    @Test fun unrelatedServerBarrierDoesNotReplaceExactAuthority()=runBlocking{val f=Fixture();f.others=listOf(f.comparisonParent.copy(snapshot=f.comparisonParent.snapshot.copy(target=OperationTarget.InstallationTarget(ServerId("other"),ServerAccessId("other-access"),XuiInstallationId("other-install")))));assertTrue(f.read() is RecoveryReadinessResult.Observed)}
    @Test fun discardedTokenNeverConnects()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.discard(r);f.port.read(r);assertEquals(0,f.connects)}
    @Test fun consumedTokenCannotReplay()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.read(r);f.port.read(r);assertEquals(1,f.connects)}
    @Test fun exactExpiryBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.at=f.at.plusSeconds(90);f.port.read(r);assertEquals(0,f.connects)}
    @Test fun clockRollbackBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.at=f.at.minusSeconds(1);f.port.read(r);assertEquals(0,f.connects)}
    @Test fun publicReviewTamperingBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.port.read(r.copy(sshLabel="another"));assertEquals(0,f.connects)}
    @Test fun comparisonRevisionDriftBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.comparisonParent=f.comparisonParent.copy(revision=OperationRevision(88));f.port.read(r);assertEquals(0,f.connects)}
    @Test fun isolatedParentRevisionDriftBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.checkedParent=f.checkedParent.copy(revision=OperationRevision(88));f.port.read(r);assertEquals(0,f.connects)}
    @Test fun backupRevisionDriftBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.backup=f.backup.copy(revision=OperationRevision(88));f.port.read(r);assertEquals(0,f.connects)}
    @Test fun credentialReferenceDriftBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.currentReview=f.review.copy(access=f.access.copy(auth=SshAuthRef.Password(SecretId("changed"))));f.port.read(r);assertEquals(0,f.connects)}
    @Test fun hostPinDriftBlocks()=runBlocking{val f=Fixture();val r=f.review()!!;f.currentReview=f.review.copy(access=f.access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:changed")));f.port.read(r);assertEquals(0,f.connects)}
    @Test fun sourceDriftDuringReadSuppressesLateProof()=runBlocking{val f=Fixture();f.afterInspect={f.comparisonParent=f.comparisonParent.copy(revision=OperationRevision(99))};assertTrue(f.read() is RecoveryReadinessResult.Unavailable);assertEquals(1,f.sshClosed)}
    @Test fun futureProofCannotPublish()=runBlocking{val f=Fixture();f.proofTime={f.at.plusSeconds(1)};assertTrue(f.read() is RecoveryReadinessResult.Unavailable)}
    @Test fun staleProofCannotPublish()=runBlocking{val f=Fixture();f.proofTime={f.at.minusSeconds(1)};assertTrue(f.read() is RecoveryReadinessResult.Unavailable)}
    @Test fun foreignTargetProofCannotPublish()=runBlocking{val f=Fixture();f.foreign=true;assertTrue(f.read() is RecoveryReadinessResult.Unavailable)}
    @Test fun wrongRevisionProofCannotPublish()=runBlocking{val f=Fixture();f.wrongRevision=true;assertTrue(f.read() is RecoveryReadinessResult.Unavailable)}
    @Test fun missingProofDoesNotInventCoverage()=runBlocking{val f=Fixture();f.available=false;assertTrue(f.read() is RecoveryReadinessResult.Unavailable);assertEquals(1,f.sshClosed)}
    @Test fun sharedRuntimeLeaseBlocksAndReleases()=runBlocking{val f=Fixture();val r=f.review()!!;val held=f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("competing")){f.port.read(r)};assertTrue(held is RecoveryReadinessResult.Unavailable);assertEquals(0,f.connects);assertEquals(true,f.runtime.withRecoveryPanelReadLease(f.installation.serverId,OperationId("next")){true})}
    @Test fun cancellationClosesSessionAndConsumesReview()=runBlocking{val f=Fixture();f.cancel=true;val r=f.review()!!;assertTrue(runCatching{f.port.read(r)}.exceptionOrNull() is CancellationException);assertEquals(1,f.sshClosed);f.port.read(r);assertEquals(1,f.connects)}
    @Test fun reviewQuotaIsBounded()=runBlocking{val f=Fixture();repeat(8){assertNotNull(f.review())};assertNull(f.review());assertEquals(0,f.connects)}
    @Test fun newReviewAfterReadIsSeparateExplicitRead()=runBlocking{val f=Fixture();assertTrue(f.read() is RecoveryReadinessResult.Observed);assertTrue(f.read() is RecoveryReadinessResult.Observed);assertEquals(2,f.connects);assertEquals(2,f.sshClosed)}
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
        var checkedParent = VersionedOperationSnapshot(OperationSnapshot(checkId, OperationType.INSTALLATION_RESTORE_CHECK,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(3))
        private val comparisonId=OperationId("source-comparison")
        private val comparisonBinding=RestoreCompatibilityBindingPolicy.bind(comparisonId,installation,access,checkedParent,backup)
        var comparisonParent=VersionedOperationSnapshot(OperationSnapshot(comparisonId,OperationType.RESTORE_COMPATIBILITY,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(4))

        var others:List<VersionedOperationSnapshot> = emptyList()
        var connects=0;var inspections=0;var sshClosed=0;var available=true;var foreign=false;var wrongRevision=false;var cancel=false
        var proofTime:()->Instant={at};var afterInspect:()->Unit={}
        val scope=ManagementScope(comparisonId,server,access.id,installation.id)
        val local=ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(currentReview)}
        val journal=object:OperationJournal{
            override suspend fun get(operationId:OperationId):OperationJournalResult<VersionedOperationSnapshot> =
                listOf(comparisonParent,checkedParent,backup).singleOrNull{it.snapshot.operationId==operationId}?.let{OperationJournalResult.Success(it)}?:OperationJournalResult.NotFound
            override suspend fun listNonTerminal():OperationJournalResult<List<VersionedOperationSnapshot>> =OperationJournalResult.Success(others)
            override suspend fun create(initial:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot> =error("No journal writes")
            override suspend fun advance(operationId:OperationId,expectedRevision:OperationRevision,next:OperationSnapshot):OperationJournalResult<VersionedOperationSnapshot> =error("No barrier clearing or journal writes")
            override suspend fun history(operationId:OperationId):OperationJournalResult<List<OperationJournalEntry>> =error("No history fallback")
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
        val port=RepositoryRecoveryReadinessPort(local,journal,factory,{s,id,read->runtime.withRecoveryPanelReadLease(s,id,read)},
            {scope,b,revision,installation,session->
                inspections++;assertTrue(session.isOpen);assertEquals(this.installation,installation)
                if(cancel)throw CancellationException("fixture")
                afterInspect()
                val groups=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,0,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
                if(!available)null else RecoveryReadinessEvidence(if(foreign)scope.copy(serverId=ServerId("foreign"))else scope,b,if(wrongRevision)revision+1 else revision,
                    "3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups,3,3,0,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.PRESENT,RecoveryQuiescence.REQUIRED,"2".repeat(64),proofTime())
            },{at})
        suspend fun review()=port.review(scope)
        suspend fun read()=port.read(requireNotNull(review()))
    }
}
