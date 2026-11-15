package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Memory-only UI. Creation and check action ports are counters, never SSH or a real backup. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_4DatabaseBackupSlotDisplayInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val time = Instant.parse("2026-10-17T01:00:00Z")
    private val clock = AtomicReference(time.plusSeconds(5))
    private val installation = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, time))
    private val access = ServerAccess(ServerAccessId("ssh"), installation.serverId, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
    private val review = ManagementRestartReview("Fixture VPS", installation, access)
    private val local = AtomicReference<ManagementRestartLocalReview>(ManagementRestartLocalReview.Ready(review))
    private val scope = ManagementScope(OperationId("source"), installation.serverId, access.id, installation.id)
    private val report = AtomicReference<UpdatePreflightSnapshot?>(UpdatePreflightSnapshot(scope, UpdateRootStatus.DIRECT_ROOT,
        UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0",
        ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, time, UpdateServerArchitecture.AMD64,
        UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
            UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
            DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, time)))
    private val creates = AtomicInteger()
    private val checks = AtomicInteger()
    private val cancels = AtomicInteger()
    private val observation = AtomicReference(DatabaseBackupObservation("backup", "Запрос зарегистрирован.", false, mayCancel = true))
    private var read: suspend () -> DatabaseBackupObservation? = { observation.get() }
    private var create: suspend () -> DatabaseBackupStart = { DatabaseBackupStart.Recorded("backup") }
    private val actions = object : DatabaseBackupActionPort {
        override suspend fun createConfirmed(review: ManagementRestartReview, source: UpdatePreflightPointer): DatabaseBackupStart {
            assertEquals(this@Phase15_10T4_4DatabaseBackupSlotDisplayInstrumentedTest.review, review)
            assertEquals(UpdatePreflightPointer("source", "ssh"), source); creates.incrementAndGet(); return create()
        }
        override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? {
            assertEquals("backup", operation); checks.incrementAndGet(); return null
        }
        override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? {
            cancels.incrementAndGet(); observation.set(DatabaseBackupObservation("backup", "Отменён до копирования.", true)); return null
        }
    }
    private val slotEvidence = AtomicReference<BackupSlotInventory?>(null)
    private val statuses = object : DatabaseBackupStatusPort {
        override fun slots(review: ManagementRestartReview): BackupSlotInventory? {
            assertEquals("server", review.serverId)
            return slotEvidence.get()
        }
        override suspend fun read(server: String, installation: String, access: String, operation: String): DatabaseBackupObservation? {
            assertEquals(listOf("server", "install", "ssh", "backup"), listOf(server, installation, access, operation)); return read()
        }
        override suspend fun unfinished(server: String, installation: String, access: String) = emptyList<String>()
    }
    private fun model(saved: SavedStateHandle) = ManagementDatabaseBackupViewModel(saved, "server", "install", "ssh",
        UpdatePreflightPointer("source", "ssh"), ManagementRestartLocalPort { _, _, _ -> local.get() },
        UpdatePreflightStatusPort { _, _, _ -> UpdatePreflightStatus("fixture", true, report.get()) }, statuses, now = { clock.get() })
    private fun show(saved: SavedStateHandle = SavedStateHandle()): ManagementDatabaseBackupViewModel {
        val model = model(saved)
        compose.setContent { VelumTegraTheme { ManagementDatabaseBackupScreen(model, actions, {}) } }
        compose.waitUntil(10_000) { !model.state.value.loading }
        return model
    }
    private fun restored() = SavedStateHandle(mapOf("dbb_server" to "server", "dbb_installation" to "install", "dbb_access" to "ssh", "dbb_operation" to "backup"))
    private fun click(tag: String) = compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)

    @Test fun pr3DatabaseUnknownSlotsShowNoObservation() {
        show()
        await("database_backup_slots")
        compose.onNodeWithTag("database_backup_slots")
            .assertTextContains("не наблюдалась", substring = true)
        assertEquals(0, creates.get())
        assertEquals(0, checks.get())
    }

    @Test fun pr3DatabaseFullCapacityIsLastCheckResultWithoutCleanup() {
        slotEvidence.set(BackupSlotInventory.Known(4, 4, time))
        show()
        await("database_backup_slots")
        compose.onNodeWithTag("database_backup_slots")
            .assertTextContains("4 из 4", substring = true)
        compose.onNodeWithTag("database_backup_slots")
            .assertTextContains("проверит хранилище снова", substring = true)
        assertEquals(0, creates.get())
        assertEquals(0, checks.get())
    }

    @Test fun pr3DatabaseUnavailableSlotsDoNotReportFree() {
        slotEvidence.set(BackupSlotInventory.Unavailable(time))
        show()
        await("database_backup_slots")
        compose.onNodeWithTag("database_backup_slots")
            .assertTextContains("не означает, что слоты свободны", substring = true)
        assertEquals(0, creates.get())
        assertEquals(0, checks.get())
    }
}
