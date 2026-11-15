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
class Phase15_10T4_10RestoredPanelStartPersistenceInstrumentedTest{
    private val context:Context=ApplicationProvider.getApplicationContext()
    private val at=Instant.parse("2026-10-18T18:00:00Z")
    @Test fun pendingWriteTypeAndFullSourceChainPersistWithoutInspectionHistory()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val s=initial(r,j);j.create(s).success();val c=j.get(s.operationId).success();assertEquals(OperationType.RESTORED_PANEL_START,c.snapshot.type);assertNotNull(RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName));assertTrue(j.recentInspections(r.installation.serverId,r.installation.id).success().isEmpty())}}
    @Test fun reopenedUncertainOperationRequiresReadbackAndRetainsMutationBarrier()=runBlocking{
        val name=name();var db:VelumDatabase?=null
        try{val first=VelumDatabaseFactory.open(context,name);db=first;val r=seed(first);val j=RoomOperationJournal(first);val s=initial(r,j);val b=RestoredPanelStartBinding.parse(s.checkpoint.phaseName)!!.second;j.create(s.copy(status=OperationStatus.RECONCILIATION_REQUIRED,checkpoint=OperationCheckpoint(b.phaseName(RestoredPanelStartPhase.UNCERTAIN),CheckpointSemantics.POST_VERIFY_REQUIRED,at))).success();first.close()
            val second=VelumDatabaseFactory.open(context,name);db=second;val c=RoomOperationJournal(second).get(s.operationId).success();val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(c,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed);assertEquals(RecoveryAction.RECONCILE_READ_ONLY,plan.action);assertTrue(DurableServerMutationBarrierPolicy.evaluate(r.installation.serverId,listOf(c.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)
        }finally{db?.close();context.deleteDatabase(name)}
    }
    @Test fun staleCancellationCannotOverwriteCompletedReadback()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val s=initial(r,j);val b=RestoredPanelStartBinding.parse(s.checkpoint.phaseName)!!.second;j.create(s).success();j.advance(s.operationId,OperationRevision(0),s.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(b.phaseName(RestoredPanelStartPhase.VERIFIED),CheckpointSemantics.TERMINAL,at))).success();assertTrue(j.advance(s.operationId,OperationRevision(0),s.copy(status=OperationStatus.CANCELLED,checkpoint=OperationCheckpoint(b.phaseName(RestoredPanelStartPhase.CANCELLED),CheckpointSemantics.TERMINAL,at))) is OperationJournalResult.StaleRevision)}}
    @Test fun emptyRegistryCannotInventPreviousCopyOrCurrentServiceState()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val s=initial(r,j);val b=RestoredPanelStartBinding.parse(s.checkpoint.phaseName)!!.second;j.create(s.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(b.phaseName(RestoredPanelStartPhase.VERIFIED),CheckpointSemantics.TERMINAL,at))).success();val o=JournalRestoredPanelStartStatusPort(j,ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(r)},RestoredPanelStartResultRegistry()).read(r.serverId,r.installationId,r.accessId,s.operationId.value)!!;assertTrue(o.terminal);assertNull(o.receipt);assertFalse(o.mayCheck)}}
    private suspend fun initial(r:ManagementRestartReview,j:OperationJournal):OperationSnapshot{
        val backupId=OperationId("backup");val source=InstallationBackupBindingPolicy.bind(backupId,r.installation,r.access,"3.10.0",UpdateServerArchitecture.AMD64)
        val target=OperationTarget.InstallationTarget(r.installation.serverId,r.access.id,r.installation.id)
        val backup=j.create(OperationSnapshot(backupId,OperationType.INSTALLATION_BACKUP,target,OperationStatus.SUCCEEDED,OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val checkId=OperationId("check");val checkedBinding=RestoreCheckBindingPolicy.bind(checkId,r.installation,r.access,backup,"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
        val check=j.create(OperationSnapshot(checkId,OperationType.INSTALLATION_RESTORE_CHECK,target,OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val id=OperationId("compare");val b=RestoreCompatibilityBindingPolicy.bind(id,r.installation,r.access,check,backup)
        val comparison=j.create(OperationSnapshot(id,OperationType.RESTORE_COMPATIBILITY,target,OperationStatus.SUCCEEDED,OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val restoreId=OperationId("restore-db");val restoredBinding=WorkingDatabaseRestoreBindingPolicy.bind(restoreId,r.installation,r.access,comparison,check,backup)
        val restored=j.create(OperationSnapshot(restoreId,OperationType.WORKING_DATABASE_RESTORE,target,OperationStatus.SUCCEEDED,OperationCheckpoint(restoredBinding.phaseName(WorkingDatabaseRestorePhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val startId=OperationId("start-panel");val binding=RestoredPanelStartBindingPolicy.bind(startId,r.installation,r.access,restored,comparison,check,backup)
        return OperationSnapshot(startId,OperationType.RESTORED_PANEL_START,target,OperationStatus.RUNNING,OperationCheckpoint(binding.phaseName(RestoredPanelStartPhase.PENDING),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at)
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
    private fun name() = "phase15_10t4_10_" + UUID.randomUUID().toString() + ".db"
    private suspend fun withDatabase(block: suspend (VelumDatabase) -> Unit) {
        val name = name(); val db = VelumDatabaseFactory.open(context, name)
        try { block(db) } finally { db.close(); context.deleteDatabase(name) }
    }
    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected valid journal result: $this")
    }
}
