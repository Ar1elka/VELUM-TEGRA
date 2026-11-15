package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.readiness.*
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

/** Memory-only source/plan UI. No backup, restore, download, real SSH or primary database. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_3RecoveryReadinessAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val time = Instant.parse("2026-10-17T00:00:00Z")
    private val clock = AtomicReference(time.plusSeconds(5))
    private val scope = ManagementScope(OperationId("prepared"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("install"))
    private val local = AtomicReference<LocalManagementReview>(LocalManagementReview.Ready(
        "Fixture VPS", "server", "install", "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("ssh")))
    private val profile = AtomicReference(LocalSshAccessSummary("ssh", "fixture.invalid", 22, "operator", "Пароль", "SHA256:fixture", "ref-digest"))
    private fun source() = UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
        UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
        DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, time)
    private val report = AtomicReference<UpdatePreflightSnapshot?>(UpdatePreflightSnapshot(scope,
        UpdateRootStatus.DIRECT_ROOT, UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT,
        "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, time, UpdateServerArchitecture.AMD64, source()))
    private val starts = AtomicInteger()
    private val journalReads = AtomicInteger()
    private var read: suspend () -> UpdatePreflightStatus = { status() }
    private fun status() = UpdatePreflightStatus("Проверка завершена", true, report.get())
    private val localPort = ManagementLocalReviewPort { server, install ->
        assertEquals("server", server); assertEquals("install", install); local.get()
    }
    private val readiness = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String): LocalSshAccessList = error("No broad lookup")
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
            assertEquals("server", serverId); assertEquals("ssh", accessId)
            return LocalSshReadinessResult.MetadataPresent(profile.get())
        }
    }
    private val statuses = UpdatePreflightStatusPort { server, install, pointer ->
        assertEquals("server", server); assertEquals("install", install); assertEquals(UpdatePreflightPointer("prepared", "ssh"), pointer)
        journalReads.incrementAndGet(); read()
    }
    private val actions = UpdatePreflightActionPort { _, _, _ ->
        starts.incrementAndGet(); UpdatePreflightStart.Blocked("No remote fixture action")
    }

    @Test fun openingRestoredSourceDoesNotStartAnyRemoteWorkOrOpenAPlan() {
        show(); await("recovery_readiness_checked"); absent("recovery_plan_dialog"); assertEquals(0, starts.get())
    }
    @Test fun databaseFactsReflectTheTypedSourceWithoutACompletedCopyClaim() {
        show()
        compose.onNodeWithTag("recovery_database_size").assertTextContains("4096", substring = true)
        compose.onNodeWithTag("recovery_database_integrity").assertTextContains("проверка пройдена", substring = true)
        compose.onNodeWithTag("recovery_readiness_checked").assertTextContains("Этот отчёт не подтверждает созданную копию", substring = true)
        compose.onNodeWithTag("recovery_compatibility_pending").assertExists()
    }
    @Test fun planShowsExactServerSshVersionAndArchitectureAfterLocalRevalidation() {
        show(); request(); await("recovery_plan_dialog")
        compose.onNodeWithTag("recovery_plan_server").assertTextContains("Fixture VPS", substring = true)
        compose.onNodeWithTag("recovery_plan_ssh").assertTextContains("operator@fixture.invalid:22", substring = true)
        compose.onNodeWithTag("recovery_plan_version").assertTextContains("3.10.0", substring = true)
        compose.onNodeWithTag("recovery_plan_architecture").assertTextContains("x86_64 / amd64", substring = true)
        UpdateRecoveryRequirement.values().forEach { compose.onNodeWithTag("recovery_pending_" + it.name).assertTextContains("Не подтверждено", substring = true) }
        assertEquals(0, starts.get())
    }
    @Test fun closingTheDraftDoesNotCreateBackupRestoreOrUpdateAuthority() {
        show(); request(); await("recovery_plan_close"); compose.onNodeWithTag("recovery_plan_close").performClick()
        absent("recovery_plan_dialog"); assertEquals(0, starts.get())
    }
    @Test fun integrityFailureHasABlockingFindingAndNoDraft() {
        changeSource(source().copy(integrity = DeepDiagnosticDatabaseIntegrityStatus.FAILED))
        show(); request(); await("recovery_plan_notice"); absent("recovery_plan_dialog")
        compose.onNodeWithTag("recovery_blocker_DATABASE_INTEGRITY").assertExists()
    }
    @Test fun missingSchemaIsIndependentOfAnIntegrityPass() {
        changeSource(source().copy(schema = DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE))
        show(); request(); await("recovery_plan_notice"); absent("recovery_plan_dialog")
        compose.onNodeWithTag("recovery_blocker_DATABASE_SCHEMA").assertExists()
    }
    @Test fun missingToolsCannotTriggerAnInstallFallback() {
        changeSource(source().copy(tools = source().tools + (UpdateRecoveryTool.SQLITE3 to UpdateRecoveryToolState.MISSING)))
        show(); request(); await("recovery_plan_notice"); absent("recovery_plan_dialog"); assertEquals(0, starts.get())
        compose.onNodeWithTag("recovery_tools").assertTextContains("sqlite3", substring = true)
    }
    @Test fun changedDatabaseRequiresAnotherExplicitCheck() {
        changeSource(source().copy(database = UpdateRecoveryDatabaseState.CHANGED_DURING_READ, databaseBytes = null))
        show(); request(); await("recovery_plan_notice"); absent("recovery_plan_dialog")
        compose.onNodeWithTag("recovery_blocker_DATABASE_CHANGED").assertExists()
    }
    @Test fun unsafeDatabasePermissionsNeverBecomeAGreenCopyStatus() {
        changeSource(source().copy(database = UpdateRecoveryDatabaseState.UNSAFE_PERMISSIONS))
        show(); await("recovery_blocker_DATABASE_ACCESS"); absent("recovery_readiness_checked")
    }
    @Test fun missingRuntimeFilesRemainVisible() {
        changeSource(source().copy(runtime = UpdateRecoveryRuntimeState.UNAVAILABLE))
        show(); await("recovery_blocker_RUNTIME_FILES"); absent("recovery_readiness_checked")
    }
    @Test fun incompletePanelTlsPairBlocksThePlanWithoutExposingPrivatePaths() {
        changeSource(source().copy(panelTls = UpdateRecoveryPanelTlsState.INCOMPLETE))
        show(); await("recovery_blocker_PANEL_TLS")
        compose.onNodeWithTag("recovery_panel_tls").assertTextContains("неполная пара", substring = true)
    }
    @Test fun oldReportWithoutSourceRequiresANewExplicitRequest() {
        report.set(requireNotNull(report.get()).copy(recovery = null))
        show(); await("recovery_source_missing"); request(); await("recovery_plan_notice")
        absent("recovery_plan_dialog"); assertEquals(0, starts.get())
    }
    @Test fun expiredSourceCannotBePromotedFromARecentLocalStatusRead() {
        clock.set(time.plusSeconds(301))
        show(); request(); await("recovery_plan_notice"); absent("recovery_plan_dialog")
        compose.onNodeWithTag("recovery_blocker_STALE_OR_FUTURE_REPORT").assertExists()
        assertEquals(0, starts.get())
    }
    @Test fun sshProfileChangedBeforePlanRevalidationHidesPreviousFacts() {
        show(); profile.set(profile.get().copy(host = "changed.invalid")); request()
        await("update_preparation_unavailable"); absent("recovery_plan_dialog")
    }
    @Test fun lostExactJournalDetailCannotLeaveAReviewablePlan() {
        show(); report.set(null); request(); await("update_preparation_unavailable"); absent("recovery_plan_dialog")
    }
    @Test fun lateJournalReadAfterLeavingForegroundCannotShowAPlanOrReplayWork() {
        val model = show(); val pending = CompletableDeferred<UpdatePreflightStatus>()
        read = { withContext(NonCancellable) { pending.await() } }
        request(); compose.waitUntil(10_000) { journalReads.get() == 2 }
        compose.runOnIdle { model.leaveForeground(); pending.complete(status()); read = { status() } }
        compose.waitForIdle(); absent("recovery_plan_dialog")
        compose.runOnIdle { model.enterForeground() }; await("recovery_readiness_section")
        absent("recovery_plan_dialog"); assertEquals(0, starts.get())
    }
    @Test fun freshModelRestoresOnlyThePreflightPointerWithoutDraftOrRemoteWork() {
        val handle = saved(); val model = show(handle); request(); await("recovery_plan_dialog")
        lateinit var restored: ManagementUpdatePreparationViewModel
        compose.runOnIdle {
            model.leaveForeground(); restored = newModel(handle); restored.enterForeground()
        }
        compose.waitUntil(10_000) { restored.state.value.result != null }
        assertNull(restored.state.value.recoveryPlan); assertFalse(restored.state.value.recoveryReading)
        assertEquals(0, starts.get()); compose.runOnIdle { restored.leaveForeground() }
    }
    @Test fun duplicatePlanRequestsCannotRunAnotherLocalRevalidation() {
        val model = show(); val before = journalReads.get()
        compose.runOnIdle { model.requestRecoveryPlan(); model.requestRecoveryPlan() }
        await("recovery_plan_dialog"); assertEquals(before + 1, journalReads.get()); assertEquals(0, starts.get())
    }
    @Test fun arm64PlanReflectsTheServerArchitecture() {
        report.set(requireNotNull(report.get()).copy(architecture = UpdateServerArchitecture.ARM64))
        show(); request(); await("recovery_plan_architecture")
        compose.onNodeWithTag("recovery_plan_architecture").assertTextContains("aarch64 / arm64", substring = true)
    }
    @Test fun updatedPreflightReviewRequiresConsentForSourceChecks() {
        show(); compose.onNodeWithTag("update_preparation_request").performScrollTo().performClick()
        await("update_preparation_confirm"); assertEquals(0, starts.get())
        compose.onNodeWithTag("update_preparation_cancel").performClick(); assertEquals(0, starts.get())
    }

    private fun changeSource(value: UpdateRecoverySourceSnapshot) { report.set(requireNotNull(report.get()).copy(recovery = value)) }
    private fun newModel(handle: SavedStateHandle) = ManagementUpdatePreparationViewModel(handle, "server", "install", "ssh", localPort, statuses, readiness,
        now = { clock.get() })
    private fun show(handle: SavedStateHandle = saved()): ManagementUpdatePreparationViewModel {
        val model = newModel(handle)
        compose.setContent { VelumTegraTheme { ManagementUpdatePreparationScreen(model, actions, {}) } }
        await("recovery_readiness_section"); return model
    }
    private fun saved() = SavedStateHandle(mapOf("update_preflight_server" to "server", "update_preflight_installation" to "install",
        "update_preflight_access" to "ssh", "update_preflight_operation" to "prepared"))
    private fun request() = compose.onNodeWithTag("recovery_plan_request").performScrollTo().performClick()
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
}
