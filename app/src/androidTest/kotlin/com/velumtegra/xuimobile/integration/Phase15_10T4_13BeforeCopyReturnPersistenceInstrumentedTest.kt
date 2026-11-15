package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.data.db.*
import com.velumtegra.xuimobile.core.data.mapping.toEntity
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.management.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Unique local Room journals only; no service, current app database, archive or SSH. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_13BeforeCopyReturnPersistenceInstrumentedTest{
    private val context:Context=ApplicationProvider.getApplicationContext()
    private val at=Instant.parse("2026-10-18T18:00:00Z")
    @Test fun sameRowCheckpointPersistsOriginalChainAndPrivateCopyHashes()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val c=initial(r,j);val b=BeforeCopyReturnBinding.parse(j.get(c.snapshot.operationId).success().snapshot.checkpoint.phaseName)!!.second;assertEquals(OperationType.WORKING_DATABASE_RESTORE,c.snapshot.type);assertEquals(0L,b.originalRevision);assertEquals("1".repeat(64),b.beforeDatabaseSha256);assertTrue(j.recentInspections(r.installation.serverId,r.installation.id).success().isEmpty())}}
    @Test fun reopenedReturnCanOnlyReconcileAndKeepsBarrier()=runBlocking{
        val name=name();var db:VelumDatabase?=null
        try{val first=VelumDatabaseFactory.open(context,name);db=first;val r=seed(first);val c=initial(r,RoomOperationJournal(first));first.close();val second=VelumDatabaseFactory.open(context,name);db=second;val loaded=RoomOperationJournal(second).get(c.snapshot.operationId).success();val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(loaded,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed);assertEquals(RecoveryAction.RECONCILE_READ_ONLY,plan.action);assertTrue(DurableServerMutationBarrierPolicy.evaluate(r.installation.serverId,listOf(loaded.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)}finally{db?.close();context.deleteDatabase(name)}
    }
    @Test fun staleCopyCheckpointCannotOverwriteReadbackRevision()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val c=initial(r,j);val b=BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)!!.second;val verified=c.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED),CheckpointSemantics.POST_VERIFY_REQUIRED,at));j.advance(c.snapshot.operationId,c.revision,verified).success();assertTrue(j.advance(c.snapshot.operationId,c.revision,c.snapshot) is OperationJournalResult.StaleRevision)}}
    @Test fun verifiedStoppedReadbackRemainsNonterminalAndCannotUseOldWriter()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val c=initial(r,j);val b=BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)!!.second;val next=j.advance(c.snapshot.operationId,c.revision,c.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED),CheckpointSemantics.POST_VERIFY_REQUIRED,at))).success();assertEquals(OperationStatus.RECONCILIATION_REQUIRED,next.snapshot.status);assertNull(WorkingDatabaseRestoreBinding.parse(next.snapshot.checkpoint.phaseName));assertEquals(1,j.listNonTerminal().success().size);
        val comparisons=object:RestoreCompatibilityStatusPort{
            override suspend fun source(server:String,installation:String,access:String,source:String):RestoreCompatibilitySourceReview?=null
            override suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCompatibilityObservation?=null
            override suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String> = emptyList()
        }
        val o=JournalWorkingDatabaseRestoreStatusPort(j,ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(r)},comparisons,WorkingDatabaseRestoreResultRegistry()).read(r.serverId,r.installationId,r.accessId,next.snapshot.operationId.value)!!
        assertTrue(o.mayInspectBeforeCopy);assertTrue(o.mayReturnBeforeCopy);assertFalse(o.mayCheck);assertFalse(o.mayStartService);assertNull(o.receipt);
assertTrue(DurableServerMutationBarrierPolicy.evaluate(r.installation.serverId,listOf(next.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)}}
    private suspend fun initial(r:ManagementRestartReview,j:OperationJournal):VersionedOperationSnapshot{
        val backupId=OperationId("backup");val source=InstallationBackupBindingPolicy.bind(backupId,r.installation,r.access,"3.10.0",UpdateServerArchitecture.AMD64)
        val target=OperationTarget.InstallationTarget(r.installation.serverId,r.access.id,r.installation.id)
        val backup=j.create(OperationSnapshot(backupId,OperationType.INSTALLATION_BACKUP,target,OperationStatus.SUCCEEDED,OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val checkId=OperationId("check");val checkedBinding=RestoreCheckBindingPolicy.bind(checkId,r.installation,r.access,backup,"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
        val check=j.create(OperationSnapshot(checkId,OperationType.INSTALLATION_RESTORE_CHECK,target,OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val id=OperationId("compare");val b=RestoreCompatibilityBindingPolicy.bind(id,r.installation,r.access,check,backup)
        val comparison=j.create(OperationSnapshot(id,OperationType.RESTORE_COMPATIBILITY,target,OperationStatus.SUCCEEDED,OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val restoreId=OperationId("restore-db");val restoredBinding=WorkingDatabaseRestoreBindingPolicy.bind(restoreId,r.installation,r.access,comparison,check,backup)
        val original=j.create(OperationSnapshot(restoreId,OperationType.WORKING_DATABASE_RESTORE,target,OperationStatus.RECONCILIATION_REQUIRED,OperationCheckpoint(restoredBinding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),CheckpointSemantics.POST_VERIFY_REQUIRED,at),at,at)).success()
        val evidence=BeforeCopyEvidence(ManagementScope(restoreId,r.installation.serverId,r.access.id,r.installation.id),restoredBinding,"1".repeat(64),"2".repeat(64),4096,BeforeCopyService.INACTIVE,BeforeCopyCurrent.DIFFERENT,BeforeCopyStructure.MATCH,BeforeCopyCompletion.PARTIAL,at)
        val returned=requireNotNull(BeforeCopyReturnPolicy.bind(original,evidence,at))
        return j.advance(restoreId,original.revision,original.snapshot.copy(checkpoint=OperationCheckpoint(returned.phaseName(BeforeCopyReturnPhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,at))).success()
    }
    private suspend fun seed(db: VelumDatabase): ManagementRestartReview {
        val s = Server(ServerId("fixture-server"), "Fixture VPS", at.minusSeconds(60))
        val a = ServerAccess(ServerAccessId("fixture-ssh"), s.id, SshEndpoint("fixture.invalid", 22), "root",
            SshAuthRef.Password(SecretId("nonexistent-fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
        val i = XuiInstallation(XuiInstallationId("fixture-install"), s.id, InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, at))
        db.serverDao().insert(s.toEntity(RecordRevision(0))); db.serverAccessDao().insert(a.toEntity())
        db.installationDao().insert(i.toEntity(RecordRevision(0)))
        return ManagementRestartReview(s.displayName, i, a)
    }
    private fun name() = "phase15_10t4_13_" + UUID.randomUUID().toString() + ".db"
    private suspend fun withDatabase(block: suspend (VelumDatabase) -> Unit) {
        val name = name(); val db = VelumDatabaseFactory.open(context, name)
        try { block(db) } finally { db.close(); context.deleteDatabase(name) }
    }
    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected valid journal result: $this")
    }
}
