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
class Phase15_10T4_7RestoreCheckPersistenceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val at = Instant.parse("2026-10-18T06:00:00Z")
    @Test fun newTypeAndExactBindingPersistThroughSameJournalWithoutInspectionHistory() = runBlocking {
        withDatabase { db ->
            val review = seed(db); val journal = RoomOperationJournal(db); val initial = initial(review, journal)
            val b = RestoreCheckBinding.parse(initial.checkpoint.phaseName)!!.second
            journal.create(initial).success()
            val copying = initial.copy(checkpoint = OperationCheckpoint(b.phaseName(RestoreCheckPhase.COPYING), CheckpointSemantics.MUTATION_IN_FLIGHT, at))
            journal.advance(initial.operationId, OperationRevision(0), copying).success()
            val verified = copying.copy(status = OperationStatus.SUCCEEDED,
                checkpoint = OperationCheckpoint(b.phaseName(RestoreCheckPhase.VERIFIED), CheckpointSemantics.TERMINAL, at))
            val stored = journal.advance(initial.operationId, OperationRevision(1), verified).success()
            assertEquals(OperationType.INSTALLATION_RESTORE_CHECK, stored.snapshot.type)
            assertTrue(RestoreCheckBindingPolicy.matches(stored, review.installation, review.access, journal.get(OperationId("source-backup")).success()))
            assertEquals(3, journal.history(initial.operationId).success().size)
            assertTrue(journal.recentInspections(review.installation.serverId, review.installation.id).success().isEmpty())
        }
    }
    @Test fun reopenRetainsUncertainMutationBarrierWithoutRecreatingAuthority() = runBlocking {
        val name = name(); var database: VelumDatabase? = null
        try {
            val first = VelumDatabaseFactory.open(context, name); database = first
            val r = seed(first); val s = initial(r, RoomOperationJournal(first)); val b = RestoreCheckBinding.parse(s.checkpoint.phaseName)!!.second
            RoomOperationJournal(first).create(s.copy(status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(b.phaseName(RestoreCheckPhase.UNCERTAIN), CheckpointSemantics.POST_VERIFY_REQUIRED, at))).success()
            first.close()
            val reopened = VelumDatabaseFactory.open(context, name); database = reopened
            val stored = RoomOperationJournal(reopened).get(s.operationId).success()
            val plan = ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(stored, OperationDurabilityValidation.Valid, RecoveryExitProvenance.PROCESS_DEATH))
            assertFalse(plan.automaticAllowed); assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plan.action)
            assertTrue(DurableServerMutationBarrierPolicy.evaluate(r.installation.serverId, listOf(stored.snapshot)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)
        } finally { database?.close(); context.deleteDatabase(name) }
    }
    @Test fun staleCancelCasCannotOverwriteDurableCopyingCheckpoint() = runBlocking {
        withDatabase { db ->
            val r = seed(db); val s = initial(r, RoomOperationJournal(db)); val b = RestoreCheckBinding.parse(s.checkpoint.phaseName)!!.second
            val j = RoomOperationJournal(db); j.create(s).success()
            j.advance(s.operationId, OperationRevision(0), s.copy(checkpoint =
                OperationCheckpoint(b.phaseName(RestoreCheckPhase.COPYING), CheckpointSemantics.MUTATION_IN_FLIGHT, at))).success()
            val stale = j.advance(s.operationId, OperationRevision(0), s.copy(status = OperationStatus.CANCELLED,
                checkpoint = OperationCheckpoint(b.phaseName(RestoreCheckPhase.CANCELLED), CheckpointSemantics.TERMINAL, at)))
            assertTrue(stale is OperationJournalResult.StaleRevision)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, j.get(s.operationId).success().snapshot.checkpoint.semantics)
        }
    }
    @Test fun emptyProcessRegistryCannotInventReceiptFromVerifiedDurableCompletion() = runBlocking {
        withDatabase { db ->
            val r = seed(db); val s = initial(r, RoomOperationJournal(db)); val b = RestoreCheckBinding.parse(s.checkpoint.phaseName)!!.second
            val j = RoomOperationJournal(db)
            j.create(s.copy(status = OperationStatus.SUCCEEDED,
                checkpoint = OperationCheckpoint(b.phaseName(RestoreCheckPhase.VERIFIED), CheckpointSemantics.TERMINAL, at))).success()
            val status = JournalRestoreCheckStatusPort(j, ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(r) },
                RestoreCheckResultRegistry()).read(r.serverId, r.installationId, r.accessId, s.operationId.value)!!
            assertTrue(status.terminal); assertFalse(status.mayCheck); assertFalse(status.mayCancel); assertNull(status.receipt)
            assertEquals(1, j.history(s.operationId).success().size)
        }
    }
    private suspend fun initial(r: ManagementRestartReview, journal: OperationJournal): OperationSnapshot {
        val sourceId = OperationId("source-backup")
        val source = InstallationBackupBindingPolicy.bind(sourceId, r.installation, r.access, "3.10.0", UpdateServerArchitecture.AMD64)
        val parent = journal.create(OperationSnapshot(sourceId, OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(r.installation.serverId,r.access.id,r.installation.id),OperationStatus.SUCCEEDED,
            OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at)).success()
        val id = OperationId("restore-check")
        val b = RestoreCheckBindingPolicy.bind(id,r.installation,r.access,parent,"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
        return OperationSnapshot(id,OperationType.INSTALLATION_RESTORE_CHECK,parent.snapshot.target,OperationStatus.RUNNING,
            OperationCheckpoint(b.phaseName(RestoreCheckPhase.REVIEWED),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at)
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
    private fun name() = "phase15_10t4_7_" + UUID.randomUUID().toString() + ".db"
    private suspend fun withDatabase(block: suspend (VelumDatabase) -> Unit) {
        val name = name(); val db = VelumDatabaseFactory.open(context, name)
        try { block(db) } finally { db.close(); context.deleteDatabase(name) }
    }
    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected valid journal result: $this")
    }
}
