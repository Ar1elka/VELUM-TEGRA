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

/** Unique local Room databases only. No primary app database, SSH, backup file or server. */
@RunWith(AndroidJUnit4::class)

class Phase15_10T4_8RestoreCompatibilityPersistenceInstrumentedTest {
    private val context:Context=ApplicationProvider.getApplicationContext()
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    @Test fun newReadOnlyTypeAndSourceChainPersistWithoutInspectionHistory()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val s=initial(r,j);j.create(s).success();val stored=j.get(s.operationId).success();assertEquals(OperationType.RESTORE_COMPATIBILITY,stored.snapshot.type);assertEquals(CheckpointSemantics.READ_ONLY,stored.snapshot.checkpoint.semantics);assertNotNull(RestoreCompatibilityBinding.parse(stored.snapshot.checkpoint.phaseName));assertTrue(j.recentInspections(r.installation.serverId,r.installation.id).success().isEmpty())}}
    @Test fun reopeningPendingReadDoesNotReplayIt()=runBlocking{
        val name=name();var db:VelumDatabase?=null
        try{val first=VelumDatabaseFactory.open(context,name);db=first;val r=seed(first);val s=initial(r,RoomOperationJournal(first));RoomOperationJournal(first).create(s).success();first.close()
            val second=VelumDatabaseFactory.open(context,name);db=second;val stored=RoomOperationJournal(second).get(s.operationId).success();val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(stored,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed);assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER,plan.action)
        }finally{db?.close();context.deleteDatabase(name)}
    }
    @Test fun staleCancelCannotOverwriteCompletedComparison()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val s=initial(r,j);val b=RestoreCompatibilityBinding.parse(s.checkpoint.phaseName)!!.second;j.create(s).success();val done=s.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at));j.advance(s.operationId,OperationRevision(0),done).success();assertTrue(j.advance(s.operationId,OperationRevision(0),s.copy(status=OperationStatus.CANCELLED,checkpoint=OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.CANCELLED),CheckpointSemantics.TERMINAL,at)))is OperationJournalResult.StaleRevision);assertEquals(OperationStatus.SUCCEEDED,j.get(s.operationId).success().snapshot.status)}}
    @Test fun emptyRegistryCannotInventCompatibilityAfterDurableCompletion()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val s=initial(r,j);val b=RestoreCompatibilityBinding.parse(s.checkpoint.phaseName)!!.second;j.create(s.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at))).success();val o=JournalRestoreCompatibilityStatusPort(j,ManagementRestartLocalPort{_,_,_->ManagementRestartLocalReview.Ready(r)},RestoreCompatibilityResultRegistry()).read(r.serverId,r.installationId,r.accessId,s.operationId.value)!!;assertTrue(o.terminal);assertNull(o.report);assertFalse(o.fresh);assertFalse(o.mayRetry)}}
    private suspend fun initial(r:ManagementRestartReview,j:OperationJournal):OperationSnapshot{
        val backupId=OperationId("backup");val source=InstallationBackupBindingPolicy.bind(backupId,r.installation,r.access,"3.10.0",UpdateServerArchitecture.AMD64)
        val target=OperationTarget.InstallationTarget(r.installation.serverId,r.access.id,r.installation.id)
        val backup=j.create(OperationSnapshot(backupId,OperationType.INSTALLATION_BACKUP,target,OperationStatus.SUCCEEDED,OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val checkId=OperationId("check");val restored=RestoreCheckBindingPolicy.bind(checkId,r.installation,r.access,backup,"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
        val check=j.create(OperationSnapshot(checkId,OperationType.INSTALLATION_RESTORE_CHECK,target,OperationStatus.SUCCEEDED,OperationCheckpoint(restored.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val id=OperationId("compare");val b=RestoreCompatibilityBindingPolicy.bind(id,r.installation,r.access,check,backup)
        return OperationSnapshot(id,OperationType.RESTORE_COMPATIBILITY,target,OperationStatus.RUNNING,OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.PENDING),CheckpointSemantics.READ_ONLY,at),at,at)
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
    private fun name() = "phase15_10t4_8_" + UUID.randomUUID().toString() + ".db"
    private suspend fun withDatabase(block: suspend (VelumDatabase) -> Unit) {
        val name = name(); val db = VelumDatabaseFactory.open(context, name)
        try { block(db) } finally { db.close(); context.deleteDatabase(name) }
    }
    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected valid journal result: $this")
    }
}
