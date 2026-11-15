package com.velumtegra.xuimobile.integration

import android.os.Build
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * Disposable-emulator-only smoke through the REAL MainActivity and its normal UI entry points:
 * Management tab -> installation -> SSH profile -> Backup -> previously verified archive ->
 * restore-check screen -> back to the backup screen; then a NEW Activity repeats the route.
 *
 * Hard opt-in (nothing is written before all of it holds):
 *  - instrumentation argument `velumDisposableAvd=true` (otherwise the test is SKIPPED via Assume),
 *  - exact applicationId `com.velumtegra.xuimobile.acceptance`,
 *  - Android Emulator signs (ranchu/goldfish hardware or emulator fingerprint).
 *
 * Seeding writes ONLY fixture rows with the `acc-fixture-` prefix into the app's own Room database through
 * the production Room repositories (fixed ids, idempotent). Existing rows are accepted only if they are equal to
 * our fixture; anything else fails the test. Nothing is ever deleted: the journal and the SSH access cannot be
 * removed through public APIs, so the fixture rows stay in this isolated emulator instance on purpose.
 * The SSH access refers to a SecretId that has no stored secret; nothing here reads or needs a secret.
 * No SSH, no network, no confirmation button is pressed.
 */
@RunWith(AndroidJUnit4::class)
class AcceptanceBackupToRestoreCheckRouteSmokeTest {
    @get:Rule val compose = createEmptyComposeRule()

    private val at = Instant.parse("2026-01-01T00:00:00Z")
    private val server = Server(ServerId("acc-fixture-server"), "ACC-FIXTURE VPS", at)
    private val fingerprint = HostKeyFingerprint("SHA256:" + Base64.getEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest("acc-fixture-host-key".toByteArray())))
    private val access = ServerAccess(ServerAccessId("acc-fixture-access"), server.id, SshEndpoint("acc-fixture.invalid", 22),
        "acc-fixture-user", SshAuthRef.Password(SecretId("acc-fixture-secret-ref")), fingerprint)
    private val installation = XuiInstallation(XuiInstallationId("acc-fixture-install"), server.id, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at))
    private val management = ManagementAccess(installation.id, access.id)
    private val archiveId = "acc-fixture-backup-1"
    private val archive: OperationSnapshot = run {
        val binding = InstallationBackupBindingPolicy.bind(OperationId(archiveId), installation, access, "3.10.0", UpdateServerArchitecture.AMD64)
        OperationSnapshot(OperationId(archiveId), OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(server.id, access.id, installation.id), OperationStatus.SUCCEEDED,
            OperationCheckpoint(binding.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, at), at, at)
    }

    @Before fun optInAndSeed() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("velumDisposableAvd=true is required; skipped", args.getString("velumDisposableAvd") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("Wrong applicationId: refusing to touch any data", "com.velumtegra.xuimobile.acceptance", context.packageName)
        val emulator = Build.HARDWARE.lowercase() in setOf("ranchu", "goldfish") ||
            Build.FINGERPRINT.lowercase().let { it.startsWith("generic") || "emulator" in it || "ranchu" in it || "goldfish" in it }
        assertTrue("Not an Android Emulator (HARDWARE=${Build.HARDWARE}, FINGERPRINT=${Build.FINGERPRINT}): refusing to write", emulator)
        // Seed BEFORE the Activity (and thus the app's runtime graph) is started.
        withDatabase { db -> runBlocking { seed(db); seedPinned(db) } }
    }

    // Separate fixture scope B (own server/installation/SSH profile) for the registered working-database restore:
    // verified backup -> verified restore-check -> comparison -> PENDING working restore. Scope A is untouched.
    private val bServer = Server(ServerId("acc-fixture-b-server"), "ACC-FIXTURE-B VPS", at)
    private val bAccess = ServerAccess(ServerAccessId("acc-fixture-b-access"), bServer.id, SshEndpoint("acc-fixture-b.invalid", 22),
        "acc-fixture-b-user", SshAuthRef.Password(SecretId("acc-fixture-b-secret-ref")), fingerprint)
    private val bInstallation = installation.copy(id = XuiInstallationId("acc-fixture-b-install"), serverId = bServer.id)
    private val bLink = ManagementAccess(bInstallation.id, bAccess.id)
    private val bTarget = OperationTarget.InstallationTarget(bServer.id, bAccess.id, bInstallation.id)
    private val bBackupId = "acc-fixture-b-backup"
    private val bCheckId = "acc-fixture-b-check"
    private val bComparisonId = "acc-fixture-b-comparison"
    private val bPendingId = "acc-fixture-b-wdb-pending"
    private var pinnedRows: List<VersionedOperationSnapshot> = emptyList()

    private suspend fun seedPinned(db: VelumDatabase) {
        val servers = RoomServerRepository(db)
        val installs = RoomXuiInstallationRepository(db)
        val accesses = RoomServerAccessRepository(db)
        val links = RoomManagementAccessRepository(db)
        val journal = RoomOperationJournal(db)
        ensure("B server", { (servers.get(bServer.id) as? RepositoryResult.Success)?.value?.value }, { servers.create(bServer) }, bServer)
        ensure("B installation", { (installs.get(bInstallation.id) as? RepositoryResult.Success)?.value?.value }, { installs.create(bInstallation) }, bInstallation)
        ensure("B ssh access", { (accesses.get(bAccess.id) as? RepositoryResult.Success)?.value }, { RoomCredentialReferenceWriter(db).createServerAccess(bAccess) }, bAccess)
        ensure("B management link", { (links.get(bInstallation.id, bAccess.id) as? RepositoryResult.Success)?.value }, { links.create(bLink) }, bLink)
        suspend fun row(id: String, type: OperationType, status: OperationStatus, semantics: CheckpointSemantics, phase: String): VersionedOperationSnapshot {
            val snapshot = OperationSnapshot(OperationId(id), type, bTarget, status, OperationCheckpoint(phase, semantics, at), at, at)
            ensure("B journal $id", { (journal.get(snapshot.operationId) as? OperationJournalResult.Success)?.value?.snapshot }, { journal.create(snapshot) }, snapshot)
            return (journal.get(snapshot.operationId) as OperationJournalResult.Success).value
        }
        val backup = row(bBackupId, OperationType.INSTALLATION_BACKUP, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
            InstallationBackupBindingPolicy.bind(OperationId(bBackupId), bInstallation, bAccess, "3.10.0", UpdateServerArchitecture.AMD64).phaseName(InstallationBackupPhase.VERIFIED))
        val check = row(bCheckId, OperationType.INSTALLATION_RESTORE_CHECK, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
            RestoreCheckBindingPolicy.bind(OperationId(bCheckId), bInstallation, bAccess, backup, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3).phaseName(RestoreCheckPhase.VERIFIED))
        val comparison = row(bComparisonId, OperationType.RESTORE_COMPATIBILITY, OperationStatus.SUCCEEDED, CheckpointSemantics.TERMINAL,
            RestoreCompatibilityBindingPolicy.bind(OperationId(bComparisonId), bInstallation, bAccess, check, backup).phaseName(RestoreCompatibilityPhase.OBSERVED))
        val pending = row(bPendingId, OperationType.WORKING_DATABASE_RESTORE, OperationStatus.RUNNING, CheckpointSemantics.MUTATION_NOT_STARTED,
            WorkingDatabaseRestoreBindingPolicy.bind(OperationId(bPendingId), bInstallation, bAccess, comparison, check, backup).phaseName(WorkingDatabaseRestorePhase.PENDING))
        pinnedRows = listOf(backup, check, comparison, pending)
    }

    private fun <T> withDatabase(block: (VelumDatabase) -> T): T {
        val db = VelumDatabaseFactory.open(InstrumentationRegistry.getInstrumentation().targetContext)
        try { return block(db) } finally { db.close() }
    }

    private suspend fun seed(db: VelumDatabase) {
        val servers = RoomServerRepository(db)
        val installs = RoomXuiInstallationRepository(db)
        val accesses = RoomServerAccessRepository(db)
        val links = RoomManagementAccessRepository(db)
        val journal = RoomOperationJournal(db)
        ensure("server", { (servers.get(server.id) as? RepositoryResult.Success)?.value?.value }, { servers.create(server) }, server)
        ensure("installation", { (installs.get(installation.id) as? RepositoryResult.Success)?.value?.value }, { installs.create(installation) }, installation)
        ensure("ssh access", { (accesses.get(access.id) as? RepositoryResult.Success)?.value }, { RoomCredentialReferenceWriter(db).createServerAccess(access) }, access)
        ensure("management link", { (links.get(installation.id, access.id) as? RepositoryResult.Success)?.value }, { links.create(management) }, management)
        ensure("archive", { (journal.get(archive.operationId) as? OperationJournalResult.Success)?.value?.snapshot }, { journal.create(archive) }, archive)
    }

    /** Existing data must be exactly ours; otherwise fail. Nothing is overwritten or deleted. */
    private suspend fun <T : Any> ensure(label: String, read: suspend () -> T?, create: suspend () -> Any, expected: T) {
        val existing = read()
        if (existing != null) { assertEquals("Existing $label is not our fixture", expected, existing); return }
        create()
        assertEquals("Could not create fixture $label", expected, read())
    }

    private fun exists(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
    private fun await(tag: String) = compose.waitUntil(30_000) { exists(tag) }
    private fun tap(tag: String) { await(tag); compose.onNodeWithTag(tag).performScrollTo().performClick() }

    private fun walkRoute() {
        await("nav_management")
        compose.onNodeWithTag("nav_management").performClick()
        tap("inventory_management_review_${installation.id.value}")
        tap("management_home_access_${access.id.value}")
        tap("management_home_backup")
        tap("backup_archive_$archiveId")
        await("restore_check_source") // review + source loaded from the exact archive
        assertTrue(!exists("restore_check_confirm")) // no confirmation dialog, nothing to confirm
        compose.onNodeWithTag("restore_check_ssh").assertTextContains("acc-fixture-user@", substring = true)
        tap("restore_check_back")
        await("backup_archive_$archiveId") // back on the backup screen, history still listed
        assertTrue(!exists("restore_check_root"))
    }

    @Test fun backupToRestoreCheckRouteWorksInTwoSuccessiveActivities() {
        repeat(2) {
            ActivityScenario.launch(MainActivity::class.java).use { walkRoute() }
        }
        // The journal still holds exactly our terminal archive and nothing of ours became unfinished.
        withDatabase { db -> runBlocking {
            val journal = RoomOperationJournal(db)
            assertEquals(archive, (journal.get(archive.operationId) as OperationJournalResult.Success).value.snapshot)
            val unfinished = (journal.listNonTerminal() as OperationJournalResult.Success).value
            assertTrue(unfinished.none { (it.snapshot.target as? OperationTarget.InstallationTarget)?.installationId == installation.id })
        } }
    }

    private fun walkPinnedRoute() {
        await("nav_management")
        compose.onNodeWithTag("nav_management").performClick() // bottom bar is not scrollable: direct click
        tap("inventory_management_review_${bInstallation.id.value}")
        tap("management_home_access_${bAccess.id.value}")
        tap("management_home_backup")
        // Previously verified restore-check result of the archive offers the comparison button; it is only shown, never pressed.
        tap("backup_archive_$bBackupId")
        await("restore_check_compare")
        assertTrue(!exists("restore_check_confirm"))
        tap("restore_check_back")
        // Open the registered working-database restore twice from the backup screen: always pinned, never a new restore.
        repeat(2) {
            tap("pending_working_restore_$bPendingId")
            await("working_db_pinned")
            await("working_db_status")
            compose.onNodeWithTag("working_db_status").assertTextContains("отправка изменения не подтверждена", substring = true)
            assertTrue(!exists("working_db_restore"))
            assertTrue(!exists("working_db_confirm") && !exists("working_db_dismiss"))
            tap("working_db_back") // check/cancel/confirm are never pressed
            await("pending_working_restore_$bPendingId")
            assertTrue(!exists("working_db_root"))
        }
    }

    @Test fun registeredWorkingRestoreReopensPinnedInTwoSuccessiveActivitiesWithoutChangingTheJournal() {
        repeat(2) {
            ActivityScenario.launch(MainActivity::class.java).use { walkPinnedRoute() }
        }
        // Independent check: our scope-B rows are identical (same revision) and the PENDING one is still the only unfinished record of B.
        withDatabase { db -> runBlocking {
            val journal = RoomOperationJournal(db)
            pinnedRows.forEach { expected ->
                assertEquals(expected, (journal.get(expected.snapshot.operationId) as OperationJournalResult.Success).value)
            }
            val unfinished = (journal.listNonTerminal() as OperationJournalResult.Success).value
                .filter { (it.snapshot.target as? OperationTarget.InstallationTarget)?.installationId == bInstallation.id }
            assertEquals(listOf(pinnedRows.last()), unfinished)
        } }
    }
}
