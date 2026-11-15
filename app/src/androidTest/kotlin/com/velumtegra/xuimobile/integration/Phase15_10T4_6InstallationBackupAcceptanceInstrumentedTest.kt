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

/** Memory-only UI. Creation and check action ports are counters, never SSH or a real backup. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_6InstallationBackupAcceptanceInstrumentedTest {
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
            assertEquals(this@Phase15_10T4_6InstallationBackupAcceptanceInstrumentedTest.review, review)
            assertEquals(UpdatePreflightPointer("source", "ssh"), source); creates.incrementAndGet(); return create()
        }
        override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? {
            assertEquals("backup", operation); checks.incrementAndGet(); return null
        }
        override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? {
            cancels.incrementAndGet(); observation.set(InstallationBackupObservation("backup", "Отменён до копирования.", true)); return null
        }
    }
    private val statuses = object : InstallationBackupStatusPort {
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

    @Test fun recoveryLinkPassesExactSourceWithoutCreatingOrReadingRemoteArtifact() {
        val selected = AtomicReference<UpdatePreflightPointer?>(null)
        val preparation = ManagementUpdatePreparationViewModel(SavedStateHandle(), "server", "install", "ssh",
            ManagementLocalReviewPort { _, _ -> error("Navigation must not read repositories") },
            UpdatePreflightStatusPort { _, _, _ -> error("Navigation must not read status") },
            object : SshReadinessPort {
                override suspend fun listForExactServer(serverId: String): LocalSshAccessList = error("No SSH list")
                override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult = error("No SSH preview")
            }, now = { clock.get() })
        val pointer = UpdatePreflightPointer("source", "ssh")
        compose.setContent { VelumTegraTheme {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                UpdateRecoveryReadinessSection(preparation, ManagementUpdatePreparationState(pointer = pointer), report.get()!!,
                    onInstallationBackup = { selected.set(it) })
            }
        } }
        click("installation_backup_open")
        assertEquals(pointer, selected.get()); assertEquals(0, creates.get()); assertEquals(0, checks.get())
    }
    @Test fun absentFileInventoryDisablesNewArchive() {
        report.set(report.get()!!.copy(recoveryFiles = null))
        show(); compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
    @Test fun unresolvedReferenceDisablesNewArchive() {
        report.set(report.get()!!.copy(recoveryFiles = known(scope).copy(issues = setOf(RecoveryFileIssue.UNKNOWN_REFERENCE), knownSetDigest = null, sourceSetDigest = null)))
        show(); compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
    @Test fun openingAndLocalRefreshCannotCreateOrInspectRemoteArtifact() {
        show(); click("installation_backup_refresh"); assertEquals(0, creates.get()); assertEquals(0, checks.get())
        absent("installation_backup_confirm"); absent("installation_backup_hash")
    }
    @Test fun scopeExplainsKnownFilesPrivacyAndUnverifiedRestore() {
        show(); compose.onNodeWithTag("installation_backup_scope").assertTextContains("Восстановление и откат версии ещё не проверены", substring = true)
        compose.onNodeWithTag("installation_backup_ssh").assertTextContains("root@fixture.invalid:22", substring = true)
    }
    @Test fun reviewDoesNotCreateUntilExplicitConfirmation() {
        show(); click("installation_backup_create"); await("installation_backup_confirm"); assertEquals(0, creates.get())
        compose.onNodeWithTag("installation_backup_confirm").performClick()
        compose.waitUntil(10_000) { creates.get() == 1 }; await("installation_backup_status"); assertEquals(0, checks.get())
    }
    @Test fun dismissingCreationReviewSendsNoAction() {
        show(); click("installation_backup_create"); await("installation_backup_dismiss")
        compose.onNodeWithTag("installation_backup_dismiss").performClick(); assertEquals(0, creates.get()); absent("installation_backup_confirm")
    }
    @Test fun duplicateConfirmCannotCreateTwiceWhileFirstHandoffSuspends() {
        val gate = CompletableDeferred<InstallationBackupStart>(); create = { gate.await() }
        val model = show(); click("installation_backup_create"); compose.onNodeWithTag("installation_backup_confirm").performClick()
        compose.waitUntil(10_000) { creates.get() == 1 }
        compose.runOnIdle { model.confirm(actions); model.requestCreate() }
        assertEquals(1, creates.get()); absent("installation_backup_confirm")
        compose.runOnIdle { gate.complete(InstallationBackupStart.Recorded("backup")) }
        await("installation_backup_status")
    }
    @Test fun staleSourceDisablesNewCreation() {
        clock.set(time.plusSeconds(301)); show(); compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
    @Test fun sourceLostFromProcessMemoryCannotInventCreationAuthority() {
        report.set(null); show(); compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
    @Test fun failedSourceIntegrityDisablesNewCreation() {
        report.set(report.get()!!.copy(recovery = report.get()!!.recovery!!.copy(integrity = DeepDiagnosticDatabaseIntegrityStatus.FAILED)))
        show(); compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled()
    }
    @Test fun removedLocalTargetHidesPreviouslyAvailableControls() {
        local.set(ManagementRestartLocalReview.Unavailable("Removed")); show(); absent("installation_backup_create"); await("installation_backup_notice")
    }
    @Test fun sshChangedAfterReviewBlocksAction() {
        show(); click("installation_backup_create"); local.set(ManagementRestartLocalReview.Ready(review.copy(access = access.copy(username = "other"))))
        compose.onNodeWithTag("installation_backup_confirm").performClick(); await("installation_backup_notice")
        assertEquals(0, creates.get())
    }
    @Test fun reportExpiringInsideConfirmationCannotStartCopy() {
        show(); click("installation_backup_create"); clock.set(time.plusSeconds(301))
        compose.onNodeWithTag("installation_backup_confirm").performClick(); await("installation_backup_notice")
        assertEquals(0, creates.get())
    }
    @Test fun restoringUncertainPointerDoesNotReplayOrAutomaticallyVerify() {
        observation.set(InstallationBackupObservation("backup", "Не подтверждено.", false, mayCheck = true))
        show(restored()); await("installation_backup_check"); assertEquals(0, checks.get()); assertEquals(0, creates.get())
    }
    @Test fun resultCheckHasSeparateConsentAndNeverCallsCreation() {
        observation.set(InstallationBackupObservation("backup", "Не подтверждено.", false, mayCheck = true))
        show(restored()); click("installation_backup_check"); await("installation_backup_confirm"); assertEquals(0, checks.get())
        compose.onNodeWithTag("installation_backup_confirm").performClick()
        compose.waitUntil(10_000) { checks.get() == 1 }; assertEquals(0, creates.get())
    }
    @Test fun pendingCancellationNeverCallsCreateOrRemoteCheck() {
        show(restored()); click("installation_backup_cancel_pending")
        compose.waitUntil(10_000) { cancels.get() == 1 }; assertEquals(0, creates.get()); assertEquals(0, checks.get())
    }
    @Test fun journalCompletionWithoutReceiptShowsNoInventedHashOrSize() {
        observation.set(InstallationBackupObservation("backup", "Журнал подтверждает завершение. Детали не сохранились.", true))
        show(restored()); await("installation_backup_status"); absent("installation_backup_hash"); absent("installation_backup_size"); assertEquals(0, checks.get())
    }
    @Test fun actualTypedReceiptShowsItsOwnBytesAndHash() {
        val b = InstallationBackupBinding("3.10.0", UpdateServerArchitecture.AMD64, "a".repeat(64))
        val receipt = InstallationBackupReceipt(scope.copy(operationId = OperationId("backup")), b, "b".repeat(64), 4096, time, "c".repeat(64), 3, "d".repeat(64))
        observation.set(InstallationBackupObservation("backup", "Копия базы подтверждена.", true, receipt = receipt))
        show(restored()); await("installation_backup_hash")
        compose.onNodeWithTag("installation_backup_hash").assertTextContains("b".repeat(64), substring = true)
        compose.onNodeWithTag("installation_backup_size").assertTextContains("4096", substring = true)
    }
    @Test fun lateStatusAfterLeavingForegroundCannotExposeOldReceipt() {
        val gate = CompletableDeferred<InstallationBackupObservation?>()
        read = { withContext(NonCancellable) { gate.await() } }
        val model = show(restored())
        compose.runOnIdle { model.leaveForeground(); gate.complete(InstallationBackupObservation("backup", "Late proof", true)) }
        compose.waitForIdle(); absent("installation_backup_status"); assertEquals(0, checks.get())
    }
    @Test fun foreignSourceCannotUseHealthyFactsFromAnotherOperation() {
        val foreign = scope.copy(operationId = OperationId("foreign"))
        report.set(report.get()!!.copy(scope = foreign, recovery = report.get()!!.recovery!!.copy(scope = foreign), recoveryFiles = known(foreign)))
        show(); compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled(); assertEquals(0, creates.get())
    }
}
