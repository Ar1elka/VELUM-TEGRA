package com.velumtegra.xuimobile.management

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import java.util.Collections
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real [PendingWorkingRestoreSection], [ManagementWorkingDatabaseRestoreScreen] and
 * [ManagementWorkingDatabaseRestoreViewModel] (pinned mode) over the production
 * [JournalWorkingDatabaseRestoreStatusPort] with a fake journal. The host below only switches between the two
 * composables with a state variable; it is a TEST host, NOT the production MainActivity navigation, and "reopen"
 * means leave/re-enter composition with a NEW ViewModel and empty SavedStateHandle, not an Activity restart.
 * Fixtures follow WorkingDatabaseRestoreRegisteredTest. No SSH, network, secrets or database.
 */
@RunWith(AndroidJUnit4::class)
class PinnedWorkingRestoreInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val at = Instant.parse("2026-10-18T06:00:00Z")
    private val server = ServerId("server")
    private val access = ServerAccess(ServerAccessId("ssh"), server, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("fixture-ref")), HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("install"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
    private val review = ManagementRestartReview("VPS", installation, access)
    private val target = OperationTarget.InstallationTarget(server, access.id, installation.id)
    private fun snap(id: String, type: OperationType, status: OperationStatus, semantics: CheckpointSemantics, phase: String, revision: Long) =
        VersionedOperationSnapshot(OperationSnapshot(OperationId(id), type, target, status, OperationCheckpoint(phase, semantics, at), at, at), OperationRevision(revision))
    private val backup = snap("backup", OperationType.INSTALLATION_BACKUP, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
        InstallationBackupBindingPolicy.bind(OperationId("backup"), installation, access, "3.10.0", UpdateServerArchitecture.AMD64).phaseName(InstallationBackupPhase.VERIFIED), 2)
    private val check = snap("check", OperationType.INSTALLATION_RESTORE_CHECK, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
        RestoreCheckBindingPolicy.bind(OperationId("check"), installation, access, backup, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3).phaseName(RestoreCheckPhase.VERIFIED), 3)
    private val comparison = snap("comparison", OperationType.RESTORE_COMPATIBILITY, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
        RestoreCompatibilityBindingPolicy.bind(OperationId("comparison"), installation, access, check, backup).phaseName(RestoreCompatibilityPhase.OBSERVED), 4)
    private fun pending(id: String) = VersionedOperationSnapshot(
        OperationSnapshot(OperationId(id), OperationType.WORKING_DATABASE_RESTORE, target, OperationStatus.RUNNING,
            OperationCheckpoint(WorkingDatabaseRestoreBindingPolicy.bind(OperationId(id), installation, access, comparison, check, backup)
                .phaseName(WorkingDatabaseRestorePhase.PENDING), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at), OperationRevision(0))

    private val good = pending("wdb-good")
    private val other = pending("wdb-other")
    private val rows = Collections.synchronizedMap(linkedMapOf(
        "backup" to backup, "check" to check, "comparison" to comparison, "wdb-good" to good, "wdb-other" to other))

    /** Read-only journal: any write fails the test loudly. */
    private inner class Journal : OperationJournal {
        override suspend fun create(initial: OperationSnapshot) = throw AssertionError("write")
        override suspend fun get(operationId: OperationId) = rows[operationId.value]?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = OperationJournalResult.Success(listOf(good, other))
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot) = throw AssertionError("write")
        override suspend fun history(operationId: OperationId) = throw AssertionError("history")
    }
    private val noComparisons = object : RestoreCompatibilityStatusPort {
        override suspend fun source(server: String, installation: String, access: String, source: String): RestoreCompatibilitySourceReview? = null
        override suspend fun read(server: String, installation: String, access: String, operation: String): RestoreCompatibilityObservation? = null
        override suspend fun unfinished(server: String, installation: String, access: String, source: String) = emptyList<String>()
    }
    private val local = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(review) }

    /** Records which exact records the screen reads; the production port does the real work. */
    private val events: MutableList<String> = Collections.synchronizedList(mutableListOf())
    private val statuses = object : WorkingDatabaseRestoreStatusPort {
        private val inner = JournalWorkingDatabaseRestoreStatusPort(Journal(), local, noComparisons, WorkingDatabaseRestoreResultRegistry())
        override suspend fun source(server: String, installation: String, access: String, source: String) = inner.source(server, installation, access, source)
        override suspend fun read(server: String, installation: String, access: String, operation: String): WorkingDatabaseRestoreObservation? {
            events += "read:$operation"; return inner.read(server, installation, access, operation)
        }
        override suspend fun unfinished(server: String, installation: String, access: String, source: String): List<String> {
            events += "unfinished"; return inner.unfinished(server, installation, access, source)
        }
        override suspend fun registered(server: String, installation: String, access: String): List<WorkingDatabaseRestoreRegistered>? {
            events += "registered"; return inner.registered(server, installation, access)
        }
    }

    /** Any call here would be a launch/cancel/check; none may happen without a confirmation click. */
    private val actionCalls = mutableListOf<String>()
    private val actions = object : WorkingDatabaseRestoreActionPort {
        override suspend fun startConfirmed(review: ManagementRestartReview, source: WorkingDatabaseRestoreSourceReview): WorkingDatabaseRestoreStart { actionCalls += "start"; return WorkingDatabaseRestoreStart.Blocked("fixture") }
        override suspend fun checkConfirmed(review: ManagementRestartReview, source: WorkingDatabaseRestoreSourceReview, operation: String): String? { actionCalls += "check"; return null }
        override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? { actionCalls += "cancel"; return null }
    }

    private val opened = mutableListOf<Pair<String, String>>()

    private fun showHost() = compose.setContent {
        val current = remember { mutableStateOf<Pair<String, String>?>(null) }
        val pinned = current.value
        if (pinned == null) {
            val list = remember { ManagementPendingWorkingRestoreViewModel("server", "install", "ssh", statuses) }
            PendingWorkingRestoreSection(list, onOpen = { op, src -> opened += op to src; current.value = op to src })
        } else {
            val vm = remember { ManagementWorkingDatabaseRestoreViewModel(SavedStateHandle(), "server", "install", "ssh", pinned.second, local, statuses, pinned.first) }
            ManagementWorkingDatabaseRestoreScreen(vm, actions, onBack = { current.value = null })
        }
    }

    private fun AndroidComposeTestRule<*, *>.awaitTag(tag: String) =
        waitUntil(10_000) { onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    private fun AndroidComposeTestRule<*, *>.count(tag: String) = onAllNodesWithTag(tag).fetchSemanticsNodes().size

    @Test fun registeredRecordOpensPinnedWithExactIdsAndStaysPinnedAfterReopenWithoutLaunching() {
        showHost()
        compose.awaitTag("pending_working_restore_wdb-good")
        compose.onNodeWithTag("pending_working_restore_wdb-other").assertExists() // another operation exists
        compose.runOnIdle { assertEquals(emptyList<String>(), actionCalls); events.clear() }

        repeat(2) { round ->
            compose.onNodeWithTag("pending_working_restore_wdb-good").performClick()
            compose.runOnIdle { assertEquals(round + 1, opened.size); assertEquals("wdb-good" to "comparison", opened.last()) }
            compose.awaitTag("working_db_status")
            compose.onNodeWithTag("working_db_pinned").assertTextContains("уже начатое восстановление", substring = true)
            compose.onNodeWithTag("working_db_status").assertTextContains("отправка изменения не подтверждена", substring = true)
            assertEquals(0, compose.count("working_db_restore")) // no way to start a new restore from a pinned record
            compose.onNodeWithTag("working_db_cancel").assertExists() // available, but only shown, never run on entry
            compose.runOnIdle {
                assertEquals(emptyList<String>(), actionCalls)
                // Pinned VM reads only its own record and never substitutes another via the unfinished list.
                assertTrue(events.contains("read:wdb-good"))
                assertFalse(events.contains("read:wdb-other"))
                assertFalse(events.contains("unfinished"))
            }
            compose.onNodeWithTag("working_db_back").performClick()
            compose.awaitTag("pending_working_restore_wdb-good")
            compose.runOnIdle { assertEquals(emptyList<String>(), actionCalls) }
        }
    }

    @Test fun pinnedRecordThatBecomesUnreadableIsNotReplacedByAnotherPendingRecord() {
        showHost()
        compose.awaitTag("pending_working_restore_wdb-good")
        rows.remove("wdb-good") // the exact record disappears after the list was read; wdb-other is still pending
        compose.runOnIdle { events.clear() }
        compose.onNodeWithTag("pending_working_restore_wdb-good").performClick()
        val unavailable = "Точная запись или исходная копия недоступна."
        // The immediate read and the next local poll can emit different notices.
        compose.waitUntil(10_000) { compose.onAllNodesWithText(unavailable).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("working_db_notice").assertTextContains(unavailable)
        assertEquals(0, compose.count("working_db_status"))
        assertEquals(0, compose.count("working_db_restore"))
        compose.runOnIdle {
            assertEquals(emptyList<String>(), actionCalls)
            assertTrue(events.contains("read:wdb-good"))
            assertFalse(events.contains("read:wdb-other"))
            assertFalse(events.contains("unfinished"))
        }
    }
}
