package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class WorkingDatabaseRestoreRegisteredTest {
    private val at = Instant.parse("2026-10-18T06:00:00Z")
    private val server = ServerId("server")
    private val access = ServerAccess(ServerAccessId("ssh"), server, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("fixture-ref")), HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("install"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
    private val target = OperationTarget.InstallationTarget(server, access.id, installation.id)
    private val backup = snap("backup", OperationType.INSTALLATION_BACKUP, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
        InstallationBackupBindingPolicy.bind(OperationId("backup"), installation, access, "3.10.0", UpdateServerArchitecture.AMD64).phaseName(InstallationBackupPhase.VERIFIED), 2)
    private val check = snap("check", OperationType.INSTALLATION_RESTORE_CHECK, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
        RestoreCheckBindingPolicy.bind(OperationId("check"), installation, access, backup, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3).phaseName(RestoreCheckPhase.VERIFIED), 3)
    private val comparison = snap("comparison", OperationType.RESTORE_COMPATIBILITY, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
        RestoreCompatibilityBindingPolicy.bind(OperationId("comparison"), installation, access, check, backup).phaseName(RestoreCompatibilityPhase.OBSERVED), 4)
    private fun pending(id: String, bindAccess: ServerAccess = access, accessId: ServerAccessId = access.id) = VersionedOperationSnapshot(
        OperationSnapshot(OperationId(id), OperationType.WORKING_DATABASE_RESTORE, OperationTarget.InstallationTarget(server, accessId, installation.id),
            OperationStatus.RUNNING, OperationCheckpoint(WorkingDatabaseRestoreBindingPolicy.bind(OperationId(id), installation, bindAccess, comparison, check, backup)
                .phaseName(WorkingDatabaseRestorePhase.PENDING), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at), OperationRevision(0))
    private fun snap(id: String, type: OperationType, status: OperationStatus, semantics: CheckpointSemantics, phase: String, revision: Long) =
        VersionedOperationSnapshot(OperationSnapshot(OperationId(id), type, target, status, OperationCheckpoint(phase, semantics, at), at, at), OperationRevision(revision))

    private class Journal(val rows: Map<String, VersionedOperationSnapshot>, val nonTerminal: OperationJournalResult<List<VersionedOperationSnapshot>>) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot) = throw AssertionError("write")
        override suspend fun get(operationId: OperationId) = rows[operationId.value]?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = nonTerminal
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot) = throw AssertionError("write")
        override suspend fun history(operationId: OperationId) = throw AssertionError("history")
    }
    private val unused = object : RestoreCompatibilityStatusPort {
        override suspend fun source(server: String, installation: String, access: String, source: String) = throw AssertionError("ssh/source")
        override suspend fun read(server: String, installation: String, access: String, operation: String) = throw AssertionError("read")
        override suspend fun unfinished(server: String, installation: String, access: String, source: String) = throw AssertionError("unfinished")
    }
    private fun port(rows: List<VersionedOperationSnapshot>, currentAccess: ServerAccess = access, nonTerminal: OperationJournalResult<List<VersionedOperationSnapshot>> = OperationJournalResult.Success(rows)): WorkingDatabaseRestoreStatusPort {
        val all = (listOf(backup, check, comparison) + rows).associateBy { it.snapshot.operationId.value }
        val review = ManagementRestartReview("VPS", installation, currentAccess)
        return JournalWorkingDatabaseRestoreStatusPort(Journal(all, nonTerminal), { _, _, _ -> ManagementRestartLocalReview.Ready(review) }, unused, WorkingDatabaseRestoreResultRegistry())
    }

    @Test fun listsOnlyExactlyProvenUnfinishedRecordsWithTheirOwnComparisonId() = runBlocking {
        val good = pending("wdb-good")
        val list = port(listOf(good)).registered("server", "install", "ssh")!!
        assertEquals(listOf("wdb-good"), list.map { it.operationId }); assertEquals("comparison", list.single().sourceOperationId)
    }
    @Test fun otherAccessChangedSshAndMissingParentAreNeverListedOrSubstituted() = runBlocking {
        val foreign = pending("wdb-foreign", accessId = ServerAccessId("other"))
        assertEquals(emptyList<String>(), port(listOf(foreign)).registered("server", "install", "ssh")!!.map { it.operationId })
        val good = pending("wdb-good")
        val moved = access.copy(endpoint = SshEndpoint("moved.invalid", 22))
        assertEquals(emptyList<String>(), port(listOf(good), currentAccess = moved).registered("server", "install", "ssh")!!.map { it.operationId })
        val orphan = pending("wdb-orphan").let { it.copy(snapshot = it.snapshot.copy(checkpoint = it.snapshot.checkpoint.copy(phaseName = it.snapshot.checkpoint.phaseName.replace("comparison", "missing")))) }
        assertEquals(emptyList<String>(), port(listOf(orphan)).registered("server", "install", "ssh")!!.map { it.operationId })
        assertNull(port(listOf(good)).registered("server", "install", "other"))
    }
    @Test fun unreadableJournalIsNullNotEmpty() = runBlocking {
        assertNull(port(listOf(pending("wdb-good")), nonTerminal = OperationJournalResult.Corruption("x")).registered("server", "install", "ssh"))
    }

    private fun verifiedRestore(): VersionedOperationSnapshot {
        val pending = pending("wdb-verified")
        val binding = requireNotNull(WorkingDatabaseRestoreBinding.parse(pending.snapshot.checkpoint.phaseName)).second
        return pending.copy(snapshot = pending.snapshot.copy(status = OperationStatus.SUCCEEDED,
            checkpoint = OperationCheckpoint(binding.phaseName(WorkingDatabaseRestorePhase.VERIFIED), CheckpointSemantics.TERMINAL, at)),
            revision = OperationRevision(1))
    }
    private fun pendingStart(restore: VersionedOperationSnapshot) = snap("start", OperationType.RESTORED_PANEL_START,
        OperationStatus.RUNNING, CheckpointSemantics.MUTATION_NOT_STARTED,
        RestoredPanelStartBindingPolicy.bind(OperationId("start"), installation, access, restore, comparison, check, backup)
            .phaseName(RestoredPanelStartPhase.PENDING), 0)

    @Test fun unfinishedPanelStartIsReachedThroughItsExactVerifiedRestore() = runBlocking {
        val restore = verifiedRestore(); val start = pendingStart(restore)
        val registered = port(listOf(restore, start), nonTerminal = OperationJournalResult.Success(listOf(start)))
            .registered("server", "install", "ssh")!!
        assertEquals(listOf("wdb-verified"), registered.map { it.operationId })
        assertEquals("comparison", registered.single().sourceOperationId)
        assertTrue(registered.single().text.contains("результат не проверен"))
    }
    @Test fun startWithoutTheExactParentOrWithForeignAccessIsNotListed() = runBlocking {
        val restore = verifiedRestore(); val start = pendingStart(restore)
        for (rows in listOf(listOf(start), listOf(restore.copy(revision = OperationRevision(2)), start),
            listOf(restore, start.copy(snapshot = start.snapshot.copy(target = OperationTarget.InstallationTarget(server, ServerAccessId("other"), installation.id)))))) {
            val nonTerminal = rows.filter { it.snapshot.type == OperationType.RESTORED_PANEL_START }
            assertTrue(port(rows, nonTerminal = OperationJournalResult.Success(nonTerminal)).registered("server", "install", "ssh")!!.isEmpty())
        }
    }
}
