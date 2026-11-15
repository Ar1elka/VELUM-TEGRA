package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.mapping.toEntity
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Unique temporary Room databases and metadata references only; no SecretStore or network. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T2InspectionHistoryPersistenceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val time = Instant.parse("2026-10-15T12:00:00Z")

    @Test fun exactInventoryIncludesCompletedChecksAndExcludesForeignTargetsAndMutations() = runBlocking {
        withDatabase { db ->
            val target = seed(db, "main")
            val foreign = seed(db, "foreign")
            val journal = RoomOperationJournal(db)
            journal.create(snapshot("quick", target)).success()
            journal.create(snapshot("deep", target, OperationType.DEEP_DIAGNOSTIC)).success()
            journal.create(snapshot("foreign", foreign)).success()
            val otherInstall = installation("other-install", target.serverId)
            db.installationDao().insert(otherInstall.toEntity(RecordRevision(0)))
            journal.create(snapshot("other-install-op", target.copy(installationId = otherInstall.id))).success()
            val mutation = snapshot("restart", target, OperationType.RESTART).copy(status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("RESTART_IN_FLIGHT", CheckpointSemantics.RESTART_IN_FLIGHT, time.plusSeconds(1)))
            journal.create(mutation).success()
            val rows = journal.recentInspections(target.serverId, target.installationId).success()
            assertEquals(setOf("quick", "deep"), rows.map { it.snapshot.operationId.value }.toSet())
            assertTrue(journal.recentInspections(foreign.serverId, target.installationId).success().isEmpty())
            assertEquals(1, journal.history(OperationId("restart")).success().size)
            assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT,
                journal.get(OperationId("restart")).success().snapshot.checkpoint.semantics)
        }
    }

    @Test fun inventoryIsBoundedAndOrderedWithoutAppendingJournalEntries() = runBlocking {
        withDatabase { db ->
            val target = seed(db, "bounded")
            val journal = RoomOperationJournal(db)
            for (i in 0..54) journal.create(snapshot("op-$i", target, at = time.plusSeconds(i.toLong()))).success()
            val tieTime = time.plusSeconds(100)
            journal.create(snapshot("tie-z", target, at = tieTime)).success()
            journal.create(snapshot("tie-a", target, at = tieTime)).success()
            journal.create(snapshot("nano-newest", target, at = tieTime.plusNanos(1))).success()
            val rows = journal.recentInspections(target.serverId, target.installationId).success()
            assertEquals(51, rows.size)
            assertEquals(listOf("nano-newest", "tie-a", "tie-z", "op-54"), rows.take(4).map { it.snapshot.operationId.value })
            assertEquals(1, journal.history(OperationId("nano-newest")).success().size)
            assertEquals(OperationRevision(0), journal.get(OperationId("nano-newest")).success().revision)
            val page = JournalManagementInspectionHistoryPort(journal).readExact(
                target.serverId.value, target.installationId.value) as InspectionHistoryRead.Page
            assertEquals(50, page.entries.size)
            assertTrue(page.hasOlder)
        }
    }

    @Test fun corruptCandidateStopsThePageInsteadOfClaimingAnEmptyOrSuccessfulHistory() = runBlocking {
        withDatabase { db ->
            val target = seed(db, "corrupt")
            val journal = RoomOperationJournal(db)
            journal.create(snapshot("broken", target)).success()
            assertEquals(1, db.operationDao().deleteJournalForOperation("broken"))
            assertTrue(journal.recentInspections(target.serverId, target.installationId) is OperationJournalResult.Corruption)
            assertEquals(InspectionHistoryRead.Unavailable, JournalManagementInspectionHistoryPort(journal)
                .readExact(target.serverId.value, target.installationId.value))
        }
    }

    @Test fun reopenRetainsCompletedHistoryWithoutReconstructingDiagnosticFacts() = runBlocking {
        val name = databaseName()
        var database: VelumDatabase? = null
        try {
            val opened = VelumDatabaseFactory.open(context, name)
            database = opened
            val target = seed(opened, "reopened")
            RoomOperationJournal(opened).create(snapshot("saved-deep", target, OperationType.DEEP_DIAGNOSTIC)).success()
            opened.close()
            val reopened = VelumDatabaseFactory.open(context, name)
            database = reopened
            val journal = RoomOperationJournal(reopened)
            val page = JournalManagementInspectionHistoryPort(journal).readExact(target.serverId.value,
                target.installationId.value) as InspectionHistoryRead.Page
            assertEquals("saved-deep", page.entries.single().operationId)
            val status = ManagementInspectionStatusReader(ManagementResultProjector(journal, ManagementResultRegistry()),
                DeepDiagnosticResultProjector(journal, DeepDiagnosticResultRegistry()), journal)
                .status(InspectionKind.DEEP_DIAGNOSTIC, "saved-deep", target.serverId.value,
                    target.installationId.value, target.serverAccessId.value)
            assertTrue(status.terminal)
            assertNull(status.detail)
            assertNull(status.serviceState)
            assertNull(status.observedAt)
            assertEquals(time.plusSeconds(1), status.completedAt)
        } finally {
            database?.close()
            context.deleteDatabase(name)
        }
    }

    private fun databaseName() = "phase15_10t2_history_" + UUID.randomUUID().toString() + ".db"

    private suspend fun withDatabase(block: suspend (VelumDatabase) -> Unit) {
        val name = databaseName()
        val database = VelumDatabaseFactory.open(context, name)
        try { block(database) } finally { database.close(); context.deleteDatabase(name) }
    }

    private suspend fun seed(db: VelumDatabase, suffix: String): OperationTarget.InstallationTarget {
        val server = Server(ServerId("server-$suffix"), "History fixture", time.minusSeconds(10))
        val access = ServerAccess(ServerAccessId("ssh-$suffix"), server.id, SshEndpoint("fixture.invalid", 22),
            "operator", SshAuthRef.Password(SecretId("nonexistent-fixture-reference-$suffix")), HostKeyFingerprint("SHA256:fixture"))
        val installation = installation("install-$suffix", server.id)
        db.serverDao().insert(server.toEntity(RecordRevision(0)))
        db.serverAccessDao().insert(access.toEntity())
        db.installationDao().insert(installation.toEntity(RecordRevision(0)))
        return OperationTarget.InstallationTarget(server.id, access.id, installation.id)
    }

    private fun installation(id: String, server: ServerId) = XuiInstallation(XuiInstallationId(id), server,
        InstallationOwnership.ADOPTED, InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui",
            "/etc/x-ui/x-ui.db", null), InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui",
            "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", time.minusSeconds(5)))

    private fun snapshot(id: String, target: OperationTarget.InstallationTarget,
        type: OperationType = OperationType.QUICK_INSPECT, at: Instant = time) = OperationSnapshot(
        OperationId(id), type, target, OperationStatus.SUCCEEDED,
        OperationCheckpoint(if (type == OperationType.DEEP_DIAGNOSTIC) "DEEP_DIAGNOSTIC_RESULT" else "QUICK_INSPECT_RESULT",
            CheckpointSemantics.TERMINAL, at.plusSeconds(1)), at, at.plusSeconds(1))

    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected a validated journal result, got $this")
    }
}
