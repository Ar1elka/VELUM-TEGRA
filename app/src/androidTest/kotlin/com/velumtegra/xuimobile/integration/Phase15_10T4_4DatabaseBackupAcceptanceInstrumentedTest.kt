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
class Phase15_10T4_4DatabaseBackupAcceptanceInstrumentedTest {
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
            assertEquals(this@Phase15_10T4_4DatabaseBackupAcceptanceInstrumentedTest.review, review)
            assertEquals(UpdatePreflightPointer("source", "ssh"), source); creates.incrementAndGet(); return create()
        }
        override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? {
            assertEquals("backup", operation); checks.incrementAndGet(); return null
        }
        override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? {
            cancels.incrementAndGet(); observation.set(DatabaseBackupObservation("backup", "Отменён до копирования.", true)); return null
        }
    }
    private val statuses = object : DatabaseBackupStatusPort {
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

    @Test fun openingAndLocalRefreshCannotCreateOrInspectRemoteArtifact() {
        show(); click("database_backup_refresh"); assertEquals(0, creates.get()); assertEquals(0, checks.get())
        absent("database_backup_confirm"); absent("database_backup_hash")
    }
    @Test fun scopeExplainsPrivateDatabaseOnlyAndIncompleteFullRecovery() {
        show(); compose.onNodeWithTag("database_backup_scope").assertTextContains("сертификаты сюда не входят", substring = true)
        compose.onNodeWithTag("database_backup_ssh").assertTextContains("root@fixture.invalid:22", substring = true)
    }
    @Test fun reviewDoesNotCreateUntilExplicitConfirmation() {
        show(); click("database_backup_create"); await("database_backup_confirm"); assertEquals(0, creates.get())
        compose.onNodeWithTag("database_backup_confirm").performClick()
        compose.waitUntil(10_000) { creates.get() == 1 }; await("database_backup_status"); assertEquals(0, checks.get())
    }
    @Test fun dismissingCreationReviewSendsNoAction() {
        show(); click("database_backup_create"); await("database_backup_dismiss")
        compose.onNodeWithTag("database_backup_dismiss").performClick(); assertEquals(0, creates.get()); absent("database_backup_confirm")
    }
    @Test fun duplicateConfirmCannotCreateTwiceWhileFirstHandoffSuspends() {
        val gate = CompletableDeferred<DatabaseBackupStart>(); create = { gate.await() }
        val model = show(); click("database_backup_create"); compose.onNodeWithTag("database_backup_confirm").performClick()
        compose.waitUntil(10_000) { creates.get() == 1 }
        compose.runOnIdle { model.confirm(actions); model.requestCreate() }
        assertEquals(1, creates.get()); absent("database_backup_confirm")
        compose.runOnIdle { gate.complete(DatabaseBackupStart.Recorded("backup")) }
        await("database_backup_status")
    }
    @Test fun staleSourceDisablesNewCreation() {
        clock.set(time.plusSeconds(301)); show(); compose.onNodeWithTag("database_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
    @Test fun sourceLostFromProcessMemoryCannotInventCreationAuthority() {
        report.set(null); show(); compose.onNodeWithTag("database_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
    @Test fun failedSourceIntegrityDisablesNewCreation() {
        report.set(report.get()!!.copy(recovery = report.get()!!.recovery!!.copy(integrity = DeepDiagnosticDatabaseIntegrityStatus.FAILED)))
        show(); compose.onNodeWithTag("database_backup_create").assertIsNotEnabled()
    }
    @Test fun removedLocalTargetHidesPreviouslyAvailableControls() {
        local.set(ManagementRestartLocalReview.Unavailable("Removed")); show(); absent("database_backup_create"); await("database_backup_notice")
    }
    @Test fun sshChangedAfterReviewBlocksAction() {
        show(); click("database_backup_create"); local.set(ManagementRestartLocalReview.Ready(review.copy(access = access.copy(username = "other"))))
        compose.onNodeWithTag("database_backup_confirm").performClick(); await("database_backup_notice")
        assertEquals(0, creates.get())
    }
    @Test fun reportExpiringInsideConfirmationCannotStartCopy() {
        show(); click("database_backup_create"); clock.set(time.plusSeconds(301))
        compose.onNodeWithTag("database_backup_confirm").performClick(); await("database_backup_notice")
        assertEquals(0, creates.get())
    }
    @Test fun restoringUncertainPointerDoesNotReplayOrAutomaticallyVerify() {
        observation.set(DatabaseBackupObservation("backup", "Не подтверждено.", false, mayCheck = true))
        show(restored()); await("database_backup_check"); assertEquals(0, checks.get()); assertEquals(0, creates.get())
    }
    @Test fun resultCheckHasSeparateConsentAndNeverCallsCreation() {
        observation.set(DatabaseBackupObservation("backup", "Не подтверждено.", false, mayCheck = true))
        show(restored()); click("database_backup_check"); await("database_backup_confirm"); assertEquals(0, checks.get())
        compose.onNodeWithTag("database_backup_confirm").performClick()
        compose.waitUntil(10_000) { checks.get() == 1 }; assertEquals(0, creates.get())
    }
    @Test fun pendingCancellationNeverCallsCreateOrRemoteCheck() {
        show(restored()); click("database_backup_cancel_pending")
        compose.waitUntil(10_000) { cancels.get() == 1 }; assertEquals(0, creates.get()); assertEquals(0, checks.get())
    }
    @Test fun journalCompletionWithoutReceiptShowsNoInventedHashOrSize() {
        observation.set(DatabaseBackupObservation("backup", "Журнал подтверждает завершение. Детали не сохранились.", true))
        show(restored()); await("database_backup_status"); absent("database_backup_hash"); absent("database_backup_size"); assertEquals(0, checks.get())
    }
    @Test fun actualTypedReceiptShowsItsOwnBytesAndHash() {
        val b = DatabaseBackupBinding("3.10.0", UpdateServerArchitecture.AMD64, "a".repeat(64))
        val receipt = DatabaseBackupReceipt(scope.copy(operationId = OperationId("backup")), b, "b".repeat(64), 4096, time)
        observation.set(DatabaseBackupObservation("backup", "Копия базы подтверждена.", true, receipt = receipt))
        show(restored()); await("database_backup_hash")
        compose.onNodeWithTag("database_backup_hash").assertTextContains("b".repeat(64), substring = true)
        compose.onNodeWithTag("database_backup_size").assertTextContains("4096", substring = true)
    }
    @Test fun lateStatusAfterLeavingForegroundCannotExposeOldReceipt() {
        val gate = CompletableDeferred<DatabaseBackupObservation?>()
        read = { withContext(NonCancellable) { gate.await() } }
        val model = show(restored())
        compose.runOnIdle { model.leaveForeground(); gate.complete(DatabaseBackupObservation("backup", "Late proof", true)) }
        compose.waitForIdle(); absent("database_backup_status"); assertEquals(0, checks.get())
    }
    @Test fun foreignSourceCannotUseHealthyFactsFromAnotherOperation() {
        val foreign = scope.copy(operationId = OperationId("foreign"))
        report.set(report.get()!!.copy(scope = foreign, recovery = report.get()!!.recovery!!.copy(scope = foreign)))
        show(); compose.onNodeWithTag("database_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
}
