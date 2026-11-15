package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class BackupArchiveHistoryTest {
    private val at = Instant.parse("2026-01-01T00:00:00Z")
    private val server = ServerId("server")
    private val access = ServerAccess(ServerAccessId("access"), server, SshEndpoint("host.invalid", 22), "operator",
        SshAuthRef.Password(SecretId("secret-ref")), HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("installation"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at))
    private val review = ManagementRestartReview("VPS", installation, access)

    private fun row(id: String, minute: Long = 0, type: OperationType = OperationType.INSTALLATION_BACKUP,
        phase: InstallationBackupPhase = InstallationBackupPhase.VERIFIED, status: OperationStatus = OperationStatus.SUCCEEDED,
        semantics: CheckpointSemantics = CheckpointSemantics.TERMINAL, bindAccess: ServerAccess = access,
        target: OperationTarget = OperationTarget.InstallationTarget(server, access.id, installation.id)): VersionedOperationSnapshot {
        val start = at.plusSeconds(minute * 60)
        val binding = InstallationBackupBindingPolicy.bind(OperationId(id), installation, bindAccess, "3.10.0", UpdateServerArchitecture.AMD64)
        return VersionedOperationSnapshot(OperationSnapshot(OperationId(id), type, target, status,
            OperationCheckpoint(binding.phaseName(phase), semantics, start.plusSeconds(5)), start, start.plusSeconds(5)), OperationRevision(2))
    }
    private fun ids(rows: List<VersionedOperationSnapshot>) = BackupArchiveHistoryPolicy.accepted(rows, review).map { it.operationId }

    @Test fun keepsOnlyExactVerifiedInstallationArchivesNewestFirst() {
        val rows = listOf(row("old", 0), row("new", 5),
            row("db", 6, type = OperationType.DATABASE_BACKUP), row("failed", 7, phase = InstallationBackupPhase.FAILED, status = OperationStatus.FAILED),
            row("unverified", 8, phase = InstallationBackupPhase.FINISHED, semantics = CheckpointSemantics.POST_VERIFY_REQUIRED, status = OperationStatus.RECONCILIATION_REQUIRED),
            row("otherAccess", 9, target = OperationTarget.InstallationTarget(server, ServerAccessId("other"), installation.id)),
            row("otherInstall", 9, target = OperationTarget.InstallationTarget(server, access.id, XuiInstallationId("other"))),
            row("changedSsh", 10, bindAccess = access.copy(username = "someone-else")))
        assertEquals(listOf("new", "old"), ids(rows))
    }
    @Test fun changedCurrentSshAccessDropsPreviouslyVerifiedRows() {
        val rows = listOf(row("a"))
        assertEquals(listOf("a"), ids(rows))
        assertTrue(BackupArchiveHistoryPolicy.accepted(rows, review.copy(access = access.copy(endpoint = SshEndpoint("moved.invalid", 22)))).isEmpty())
    }
    @Test fun boundedToTenAndDuplicatesCollapse() {
        val rows = (0L until 12L).map { row("id$it", it) } + row("id3", 3)
        val result = ids(rows)
        assertEquals(10, result.size); assertEquals("id11", result.first()); assertEquals(1, result.count { it == "id3" })
    }
    @Test fun portIsUnavailableOnCorruptionOrChangedLocalReviewAndNeverTouchesOtherRows() = runBlocking {
        val local = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(review) }
        val ok = JournalBackupArchiveHistoryPort({ _, _, _ -> OperationJournalResult.Success(listOf(row("a"))) }, local)
        assertEquals(1, (ok.readExact("server", "installation", "access") as BackupArchiveHistoryRead.Page).entries.size)
        assertEquals("a".take(8), (ok.readExact("server", "installation", "access") as BackupArchiveHistoryRead.Page).entries.single().shortId)
        assertEquals(BackupArchiveHistoryRead.Unavailable, JournalBackupArchiveHistoryPort({ _, _, _ -> OperationJournalResult.Corruption("x") }, local)
            .readExact("server", "installation", "access"))
        assertEquals(BackupArchiveHistoryRead.Unavailable, ok.readExact("server", "installation", "other-access"))
        var calls = 0
        val drifting = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(if (calls++ == 0) review else review.copy(access = access.copy(username = "x"))) }
        assertEquals(BackupArchiveHistoryRead.Unavailable, JournalBackupArchiveHistoryPort({ _, _, _ -> OperationJournalResult.Success(listOf(row("a"))) }, drifting)
            .readExact("server", "installation", "access"))
    }
}
