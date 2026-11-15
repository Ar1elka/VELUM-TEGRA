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

/** Unique local Room only. No actual user files, service or SSH. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_16KnownFileRestorePersistenceInstrumentedTest{
    private val context:Context=ApplicationProvider.getApplicationContext()
    private val at=Instant.parse("2026-10-21T18:00:00Z")
    @Test fun fileOperationAndFullLineagePersistWithoutNewSchema()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val c=initial(r,j);val loaded=j.get(c.snapshot.operationId).success();assertEquals(c,loaded);assertEquals(OperationType.KNOWN_FILE_RESTORE,loaded.snapshot.type);val b=KnownFileRestoreBinding.parse(loaded.snapshot.checkpoint.phaseName)!!.second;assertEquals("compare",b.comparisonOperationId.value);assertEquals("backup",b.comparison.source.sourceOperationId.value);assertEquals(1,b.changedFiles);assertTrue(j.recentInspections(r.installation.serverId,r.installation.id).success().isEmpty())}}
    @Test fun processDeathPreservesBarrierAndCannotRestoreConsent()=runBlocking{
        val name=name();var db:VelumDatabase?=null
        try{val first=VelumDatabaseFactory.open(context,name);db=first;val r=seed(first);val c=initial(r,RoomOperationJournal(first));first.close();val second=VelumDatabaseFactory.open(context,name);db=second;val loaded=RoomOperationJournal(second).get(c.snapshot.operationId).success();val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(loaded,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed);assertEquals(RecoveryAction.RECONCILE_READ_ONLY,plan.action);assertTrue(DurableServerMutationBarrierPolicy.evaluate(r.installation.serverId,listOf(loaded.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)}finally{db?.close();context.deleteDatabase(name)}
    }
    @Test fun staleCasCannotOverwriteReturnIntent()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val c=initial(r,j);val b=KnownFileRestoreBinding.parse(c.snapshot.checkpoint.phaseName)!!.second;val n=c.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(KnownFileRestorePhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,at));j.advance(c.snapshot.operationId,c.revision,n).success();assertTrue(j.advance(c.snapshot.operationId,c.revision,c.snapshot) is OperationJournalResult.StaleRevision);assertEquals(KnownFileRestorePhase.RETURNING,KnownFileRestoreBinding.parse(j.get(c.snapshot.operationId).success().snapshot.checkpoint.phaseName)!!.first)}}
    @Test fun independentReadbackTerminalDoesNotInventProcessLocalProof()=runBlocking{withDatabase{db->val r=seed(db);val j=RoomOperationJournal(db);val c=initial(r,j);val b=KnownFileRestoreBinding.parse(c.snapshot.checkpoint.phaseName)!!.second;val terminal=j.advance(c.snapshot.operationId,c.revision,c.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(b.phaseName(KnownFileRestorePhase.APPLIED),CheckpointSemantics.TERMINAL,at))).success();assertTrue(j.listNonTerminal().success().isEmpty());assertEquals(c.snapshot.startedAt,terminal.snapshot.startedAt);assertEquals(2,j.history(c.snapshot.operationId).success().size);val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(terminal,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed);assertFalse(terminal.snapshot.checkpoint.phaseName.contains("DATABASE_LOGICAL"));assertFalse(terminal.snapshot.checkpoint.phaseName.contains("MANIFEST"))}}
    private suspend fun initial(r:ManagementRestartReview,j:OperationJournal):VersionedOperationSnapshot{
        val backupId=OperationId("backup");val source=InstallationBackupBindingPolicy.bind(backupId,r.installation,r.access,"3.10.0",UpdateServerArchitecture.AMD64)
        val target=OperationTarget.InstallationTarget(r.installation.serverId,r.access.id,r.installation.id)
        val backup=j.create(OperationSnapshot(backupId,OperationType.INSTALLATION_BACKUP,target,OperationStatus.SUCCEEDED,OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val checkId=OperationId("check");val checkedBinding=RestoreCheckBindingPolicy.bind(checkId,r.installation,r.access,backup,"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
        val check=j.create(OperationSnapshot(checkId,OperationType.INSTALLATION_RESTORE_CHECK,target,OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val id=OperationId("compare");val b=RestoreCompatibilityBindingPolicy.bind(id,r.installation,r.access,check,backup)
        val comparison=j.create(OperationSnapshot(id,OperationType.RESTORE_COMPATIBILITY,target,OperationStatus.SUCCEEDED,OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val groups=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,1,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
        val e=RecoveryReadinessEvidence(ManagementScope(id,r.installation.serverId,r.access.id,r.installation.id),b,comparison.revision.value,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups,3,3,1,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.EMPTY,RecoveryQuiescence.STOPPED,"2".repeat(64),at)
        val fileId=OperationId("files");val binding=KnownFileRestorePolicy.bind(fileId,r.installation,r.access,comparison,check,backup,e,at)!!
        return j.create(OperationSnapshot(fileId,OperationType.KNOWN_FILE_RESTORE,target,OperationStatus.RECONCILIATION_REQUIRED,OperationCheckpoint(binding.phaseName(KnownFileRestorePhase.APPLYING),CheckpointSemantics.POST_VERIFY_REQUIRED,at),at,at)).success()
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
    private fun name() = "phase15_10t4_16_" + UUID.randomUUID().toString() + ".db"
    private suspend fun withDatabase(block: suspend (VelumDatabase) -> Unit) {
        val name = name(); val db = VelumDatabaseFactory.open(context, name)
        try { block(db) } finally { db.close(); context.deleteDatabase(name) }
    }
    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected valid journal result: $this")
    }
}
