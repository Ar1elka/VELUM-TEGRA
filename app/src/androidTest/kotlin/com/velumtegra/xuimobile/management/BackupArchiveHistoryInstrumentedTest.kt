package com.velumtegra.xuimobile.management

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real [BackupArchiveHistorySection] + real [ManagementBackupArchiveHistoryViewModel] + the production
 * [JournalBackupArchiveHistoryPort]/[BackupArchiveHistoryPolicy] over a fake journal and a fake local review.
 * "Return" here means the composable leaves and re-enters composition (new ViewModel); it is NOT an
 * Activity recreation or a real navigation. No SSH, network, secrets or database.
 */
@RunWith(AndroidJUnit4::class)
class BackupArchiveHistoryInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val at = Instant.parse("2026-01-01T00:00:00Z")
    private val server = ServerId("server")
    private fun access(id: String, user: String) = ServerAccess(ServerAccessId(id), server, SshEndpoint("$id.invalid", 22), user,
        SshAuthRef.Password(SecretId("secret-ref-$id")), HostKeyFingerprint("SHA256:fixture-$id"))
    private val own = access("access-own", "operator")
    private val other = access("access-other", "someone-else")
    private val installation = XuiInstallation(XuiInstallationId("installation"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at))

    private fun row(id: String, minute: Long, forAccess: ServerAccess): VersionedOperationSnapshot {
        val start = at.plusSeconds(minute * 60)
        val binding = InstallationBackupBindingPolicy.bind(OperationId(id), installation, forAccess, "3.10.0", UpdateServerArchitecture.AMD64)
        return VersionedOperationSnapshot(OperationSnapshot(OperationId(id), OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(server, forAccess.id, installation.id), OperationStatus.SUCCEEDED,
            OperationCheckpoint(binding.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, start.plusSeconds(5)),
            start, start.plusSeconds(5)), OperationRevision(2))
    }

    // The fake journal deliberately returns rows of BOTH profiles for every query: only the production policy filters.
    private val journalRows = listOf(row("own-a-001", 1, own), row("own-b-002", 2, own), row("foreign-001", 3, other))
    private var inventoryReads = 0
    private val port = JournalBackupArchiveHistoryPort(
        { _, _, _ -> inventoryReads++; OperationJournalResult.Success(journalRows) },
        { _, _, accessId -> ManagementRestartLocalReview.Ready(
            ManagementRestartReview("Fixture", installation, listOf(own, other).first { it.id.value == accessId })) },
    )

    private val selected = mutableListOf<String>()

    private fun host(accessId: String, shown: androidx.compose.runtime.MutableState<Boolean>) = compose.setContent {
        if (shown.value) {
            val vm = remember(accessId) { ManagementBackupArchiveHistoryViewModel("server", "installation", accessId, port) }
            BackupArchiveHistorySection(vm, onSelect = { selected += it })
        }
    }

    private fun AndroidComposeTestRule<*, *>.awaitTag(tag: String) =
        waitUntil(10_000) { onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    private fun AndroidComposeTestRule<*, *>.count(tag: String) = onAllNodesWithTag(tag).fetchSemanticsNodes().size

    @Test fun ownArchivesShownSelectionPassesExactIdAndHistoryReappearsAfterComposableRecreation() {
        val shown = mutableStateOf(true)
        host(own.id.value, shown)
        compose.awaitTag("backup_archive_own-a-001")
        compose.onNodeWithTag("backup_archive_own-b-002").assertExists()
        // The other SSH profile's row is rejected by the production policy.
        assertEquals(0, compose.count("backup_archive_foreign-001"))
        compose.onNodeWithTag("backup_archive_own-a-001")
            .assertTextContains("Копия от ", substring = true)
            .assert(!hasText("own-a-00", substring = true))
        compose.runOnIdle { assertEquals(emptyList<String>(), selected) } // listing alone selects nothing

        compose.onNodeWithTag("backup_archive_own-b-002").performClick()
        compose.runOnIdle { assertEquals(listOf("own-b-002"), selected) }

        // Leave and re-enter composition: a fresh ViewModel re-reads the local journal and shows the history again.
        val readsBefore = inventoryReads
        compose.runOnIdle { shown.value = false }
        compose.waitUntil(10_000) { compose.count("backup_archives") == 0 }
        compose.runOnIdle { shown.value = true }
        compose.awaitTag("backup_archive_own-a-001")
        compose.onNodeWithTag("backup_archive_own-b-002").assertExists()
        assertEquals(0, compose.count("backup_archive_foreign-001"))
        compose.runOnIdle {
            assertEquals(listOf("own-b-002"), selected) // re-entry never auto-selects
            assertTrue(inventoryReads > readsBefore)
        }
    }

    @Test fun otherSshProfileSeesOnlyItsOwnArchivesNotTheFirstProfilesRows() {
        host(other.id.value, mutableStateOf(true))
        compose.awaitTag("backup_archive_foreign-001")
        assertEquals(0, compose.count("backup_archive_own-a-001"))
        assertEquals(0, compose.count("backup_archive_own-b-002"))
        compose.runOnIdle { assertEquals(emptyList<String>(), selected) }
    }
}
