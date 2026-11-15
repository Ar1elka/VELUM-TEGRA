package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class RestoreCheckVerifiedFallbackTest {
    private val at = Instant.parse("2026-10-18T06:00:00Z")
    private val server = ServerId("server")
    private val access = ServerAccess(ServerAccessId("ssh"), server, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("fixture-ref")), HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("install"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, at.minusSeconds(60)))
    private val review = ManagementRestartReview("VPS", installation, access)
    private val target = OperationTarget.InstallationTarget(server, access.id, installation.id)

    private fun backup(id: String, revision: Long = 2, bindAccess: ServerAccess = access): VersionedOperationSnapshot {
        val b = InstallationBackupBindingPolicy.bind(OperationId(id), installation, bindAccess, "3.10.0", UpdateServerArchitecture.AMD64)
        return VersionedOperationSnapshot(OperationSnapshot(OperationId(id), OperationType.INSTALLATION_BACKUP, target, OperationStatus.SUCCEEDED,
            OperationCheckpoint(b.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, at), at, at), OperationRevision(revision))
    }
    private fun check(id: String, parent: VersionedOperationSnapshot, phase: RestoreCheckPhase = RestoreCheckPhase.VERIFIED,
        status: OperationStatus = OperationStatus.SUCCEEDED, semantics: CheckpointSemantics = CheckpointSemantics.TERMINAL,
        bindAccess: ServerAccess = access, minute: Long = 1): VersionedOperationSnapshot {
        val binding = RestoreCheckBindingPolicy.bind(OperationId(id), installation, bindAccess, parent, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3)
        val t = at.plusSeconds(60 * minute)
        return VersionedOperationSnapshot(OperationSnapshot(OperationId(id), OperationType.INSTALLATION_RESTORE_CHECK, target, status,
            OperationCheckpoint(binding.phaseName(phase), semantics, t), t, t), OperationRevision(3))
    }
    private class Journal(val rows: MutableMap<String, VersionedOperationSnapshot>, var nonTerminal: OperationJournalResult<List<VersionedOperationSnapshot>>) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot) = throw AssertionError("write")
        override suspend fun get(operationId: OperationId) = rows[operationId.value]?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = nonTerminal
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot) = throw AssertionError("write")
        override suspend fun history(operationId: OperationId) = throw AssertionError("history")
    }
    private val local = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(review) }
    private fun port(journal: Journal, inventoryRows: List<VersionedOperationSnapshot>, prefixes: MutableList<String> = mutableListOf()) =
        JournalRestoreCheckStatusPort(journal, local, RestoreCheckResultRegistry(), verified = RestoreCheckResultInventory { _, _, _, prefix ->
            prefixes += prefix; OperationJournalResult.Success(inventoryRows)
        })

    @Test fun picksNewestExactlyBoundVerifiedResultAndAsksWithExactParentPrefix() = runBlocking {
        val parent = backup("archive"); val prefixes = mutableListOf<String>()
        val good = check("good", parent, minute = 1); val newer = check("newer", parent, minute = 2)
        val journal = Journal(mutableMapOf("archive" to parent), OperationJournalResult.Success(emptyList()))
        assertEquals("newer", port(journal, listOf(newer, good), prefixes).latestVerified("server", "install", "ssh", "archive"))
        val parentBinding = requireNotNull(InstallationBackupBinding.parse(parent.snapshot.checkpoint.phaseName)).second
        assertEquals("RCB1_VERIFIED:AMD64:3.10.0:archive:2:${parentBinding.digest}:", prefixes.single())
    }
    @Test fun rejectsOtherRevisionOtherArchiveChangedSshAndNonVerifiedRows() = runBlocking {
        val parent = backup("archive"); val journal = Journal(mutableMapOf("archive" to parent), OperationJournalResult.Success(emptyList()))
        val staleParent = backup("archive", revision = 1); val other = backup("other")
        val oldAccess = access.copy(username = "other")
        val oldParent = backup("archive", bindAccess = oldAccess)
        val rows = listOf(check("rev", staleParent), check("foreign", other), check("ssh", oldParent, bindAccess = oldAccess),
            check("failed", parent, phase = RestoreCheckPhase.FAILED, status = OperationStatus.FAILED),
            check("running", parent, phase = RestoreCheckPhase.COPYING, status = OperationStatus.RUNNING, semantics = CheckpointSemantics.MUTATION_IN_FLIGHT))
        assertNull(port(journal, rows).latestVerified("server", "install", "ssh", "archive"))
    }
    @Test fun parentChangedOrMissingOrInventoryUnreadableGivesNothing() = runBlocking {
        val parent = backup("archive"); val row = check("good", parent)
        assertNull(port(Journal(mutableMapOf(), OperationJournalResult.Success(emptyList())), listOf(row)).latestVerified("server", "install", "ssh", "archive"))
        val unreadable = JournalRestoreCheckStatusPort(Journal(mutableMapOf("archive" to parent), OperationJournalResult.Success(emptyList())), local,
            RestoreCheckResultRegistry(), verified = RestoreCheckResultInventory { _, _, _, _ -> OperationJournalResult.Corruption("x") })
        assertNull(unreadable.latestVerified("server", "install", "ssh", "archive"))
        assertNull(port(Journal(mutableMapOf("archive" to parent), OperationJournalResult.Success(emptyList())), listOf(row)).latestVerified("server", "install", "other", "archive"))
    }
    @Test fun unfinishedReadErrorIsNullNotEmptyAndUnfinishedExactMatchesStillListed() = runBlocking {
        val parent = backup("archive")
        val failing = Journal(mutableMapOf("archive" to parent), OperationJournalResult.Corruption("x"))
        assertNull(port(failing, emptyList()).unfinishedChecked("server", "install", "ssh", "archive"))
        assertEquals(emptyList<String>(), port(failing, emptyList()).unfinished("server", "install", "ssh", "archive"))
        val pending = check("pending", parent, phase = RestoreCheckPhase.REVIEWED, status = OperationStatus.RUNNING, semantics = CheckpointSemantics.MUTATION_NOT_STARTED)
        val ok = Journal(mutableMapOf("archive" to parent), OperationJournalResult.Success(listOf(pending, check("foreign", backup("other")))))
        assertEquals(listOf("pending"), port(ok, emptyList()).unfinishedChecked("server", "install", "ssh", "archive"))
    }
}
