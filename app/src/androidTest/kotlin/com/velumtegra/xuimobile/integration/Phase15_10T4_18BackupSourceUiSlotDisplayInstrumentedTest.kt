package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import com.velumtegra.xuimobile.readiness.*
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

/** Presentation regression cases only. Counter ports cannot connect to SSH or create files. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_18BackupSourceUiSlotDisplayInstrumentedTest {
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
            DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, time), known(scope)))
    private fun known(scope: ManagementScope) = RecoveryFileInventory(scope,
        RecoveryFileGroup.values().associateWith { group -> when(group) {
            RecoveryFileGroup.RUNTIME -> RecoveryFileGroupObservation(2, 8192)
            RecoveryFileGroup.SERVICE -> RecoveryFileGroupObservation(1, 4096)
            else -> RecoveryFileGroupObservation(0, 0)
        } }, 3, 12288, emptySet(), "c".repeat(64), time, "e".repeat(64))
    private val creates = AtomicInteger()
    private val checks = AtomicInteger()
    private val cancels = AtomicInteger()
    private val observation = AtomicReference(InstallationBackupObservation("backup", "Запрос зарегистрирован.", false, mayCancel = true))
    private var read: suspend () -> InstallationBackupObservation? = { observation.get() }
    private var create: suspend () -> InstallationBackupStart = { InstallationBackupStart.Recorded("backup") }
    private val actions = object : InstallationBackupActionPort {
        override suspend fun createConfirmed(review: ManagementRestartReview, source: UpdatePreflightPointer): InstallationBackupStart {
            assertEquals(this@Phase15_10T4_18BackupSourceUiSlotDisplayInstrumentedTest.review, review)
            assertEquals(UpdatePreflightPointer("source", "ssh"), source); creates.incrementAndGet(); return create()
        }
        override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? {
            assertEquals("backup", operation); checks.incrementAndGet(); return null
        }
        override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? {
            cancels.incrementAndGet(); observation.set(InstallationBackupObservation("backup", "Отменён до копирования.", true)); return null
        }
    }
    private val slotEvidence = AtomicReference<BackupSlotInventory?>(null)
    private val statuses = object : InstallationBackupStatusPort {
        override fun slots(review: ManagementRestartReview): BackupSlotInventory? {
            assertEquals("server", review.serverId)
            return slotEvidence.get()
        }
        override suspend fun read(server: String, installation: String, access: String, operation: String): InstallationBackupObservation? {
            assertEquals(listOf("server", "install", "ssh", "backup"), listOf(server, installation, access, operation)); return read()
        }
        override suspend fun unfinished(server: String, installation: String, access: String) = emptyList<String>()
    }
    private fun model(saved: SavedStateHandle) = ManagementInstallationBackupViewModel(saved, "server", "install", "ssh",
        UpdatePreflightPointer("source", "ssh"), ManagementRestartLocalPort { _, _, _ -> local.get() },
        UpdatePreflightStatusPort { _, _, _ -> UpdatePreflightStatus("fixture", true, report.get()) }, statuses, now = { clock.get() })
    private fun show(saved: SavedStateHandle = SavedStateHandle()): ManagementInstallationBackupViewModel {
        val model = model(saved)
        compose.setContent { VelumTegraTheme { ManagementInstallationBackupScreen(model, actions, {}) } }
        compose.waitUntil(10_000) { !model.state.value.loading }
        return model
    }
    private fun restored() = SavedStateHandle(mapOf("ibb_server" to "server", "ibb_installation" to "install", "ibb_access" to "ssh", "ibb_operation" to "backup"))
    private fun click(tag: String) = compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)

    @Test fun pr3UnknownSlotsDoNotClaimAnyFreeCapacity() {
        show()
        await("installation_backup_slots")
        compose.onNodeWithTag("installation_backup_slots")
            .assertTextContains("не наблюдалась", substring = true)
        assertEquals(0, creates.get())
        assertEquals(0, checks.get())
    }

    @Test fun pr3KnownTwoOfFourSlotsRenderWithoutBackupExecution() {
        slotEvidence.set(BackupSlotInventory.Known(2, 4, time))
        show()
        await("installation_backup_slots")
        compose.onNodeWithTag("installation_backup_slots")
            .assertTextContains("2 из 4", substring = true)
        compose.onNodeWithTag("installation_backup_slots")
            .assertTextContains("незавершённые", substring = true)
        assertEquals(0, creates.get())
        assertEquals(0, checks.get())
    }

    @Test fun pr3UnavailableSlotsNeverPretendToBeFree() {
        slotEvidence.set(BackupSlotInventory.Unavailable(time))
        show()
        await("installation_backup_slots")
        compose.onNodeWithTag("installation_backup_slots")
            .assertTextContains("не удалось прочитать", substring = true)
        compose.onNodeWithTag("installation_backup_slots")
            .assertTextContains("не означает, что слоты свободны", substring = true)
        assertEquals(0, creates.get())
        assertEquals(0, checks.get())
    }
}
