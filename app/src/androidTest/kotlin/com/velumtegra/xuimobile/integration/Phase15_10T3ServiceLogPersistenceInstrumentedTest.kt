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

/** New operation storage codes through actual unique Room databases; never the app database. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T3ServiceLogPersistenceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val time = Instant.parse("2026-10-15T18:00:00Z")
    @Test fun logReadPersistsThroughSameJournalAndIsExcludedFromInspectionHistory() = runBlocking {
        withDatabase { db ->
            val target = seed(db, "logs")
            val journal = RoomOperationJournal(db)
            val initial = operation(target)
            journal.create(initial).success()
            val done = initial.copy(status = OperationStatus.SUCCEEDED,
                checkpoint = OperationCheckpoint("SERVICE_LOG_READ_RESULT", CheckpointSemantics.TERMINAL, time.plusSeconds(1)),
                updatedAt = time.plusSeconds(1))
            journal.advance(initial.operationId, OperationRevision(0), done).success()
            val stored = journal.get(initial.operationId).success()
            assertEquals(OperationType.SERVICE_LOG_READ, stored.snapshot.type)
            assertEquals(target, stored.snapshot.target)
            assertEquals(OperationRevision(1), stored.revision)
            assertEquals(2, journal.history(initial.operationId).success().size)
            assertTrue(journal.recentInspections(target.serverId, target.installationId).success().isEmpty())
        }
    }
    @Test fun reopeningRetainsFailedOperationWithoutInventingEventsOrReplayingIt() = runBlocking {
        val name = databaseName()
        var database: VelumDatabase? = null
        try {
            val opened = VelumDatabaseFactory.open(context, name); database = opened
            val target = seed(opened, "reopened")
            val journal = RoomOperationJournal(opened)
            val initial = operation(target)
            journal.create(initial).success()
            val failed = initial.copy(status = OperationStatus.FAILED,
                checkpoint = OperationCheckpoint("SERVICE_LOG_READ_FAILED", CheckpointSemantics.TERMINAL, time.plusSeconds(1)),
                updatedAt = time.plusSeconds(1))
            journal.advance(initial.operationId, OperationRevision(0), failed).success()
            opened.close()
            val reopened = VelumDatabaseFactory.open(context, name); database = reopened
            val stored = RoomOperationJournal(reopened)
            val result = JournalServiceLogStatusPort(stored, ServiceLogResultRegistry()).read(target.serverId.value,
                target.installationId.value, ServiceLogPointer(initial.operationId.value, target.serverAccessId.value))
            assertTrue(result.terminal)
            assertNull(result.snapshot)
            assertEquals(2, stored.history(initial.operationId).success().size)
            assertTrue(stored.listNonTerminal().success().isEmpty())
        } finally { database?.close(); context.deleteDatabase(name) }
    }
    private fun operation(target: OperationTarget.InstallationTarget) = OperationSnapshot(OperationId("service-logs"),
        OperationType.SERVICE_LOG_READ, target, OperationStatus.RUNNING,
        OperationCheckpoint("SERVICE_LOG_READ", CheckpointSemantics.READ_ONLY, time), time, time)

    private fun databaseName() = "phase15_10t3_logs_" + UUID.randomUUID().toString() + ".db"

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

    private fun <T> OperationJournalResult<T>.success(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected a validated journal result, got $this")
    }
}
