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

/** Memory inventory UI only. No files, archives, key bytes, network or actual SSH/VPS. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_5RecoveryFileInventoryAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val at = Instant.parse("2026-10-17T04:00:00Z")
    private val clock = AtomicReference(at.plusSeconds(1))
    private val scope = ManagementScope(OperationId("prepared"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("install"))
    private val local = AtomicReference<LocalManagementReview>(LocalManagementReview.Ready(
        "Fixture VPS", "server", "install", "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("ssh")))
    private val profile = AtomicReference(LocalSshAccessSummary("ssh", "fixture.invalid", 22, "operator", "Пароль", "SHA256:fixture", "ref-digest"))
    private fun files() = RecoveryFileInventory(scope, RecoveryFileGroup.values().associateWith {
        when (it) {
            RecoveryFileGroup.RUNTIME -> RecoveryFileGroupObservation(4, 300000)
            RecoveryFileGroup.SERVICE -> RecoveryFileGroupObservation(1, 200)
            RecoveryFileGroup.PANEL_TLS -> RecoveryFileGroupObservation(2, 4000)
            RecoveryFileGroup.XRAY_TLS -> RecoveryFileGroupObservation(2, 4000)
            RecoveryFileGroup.XRAY_DATA -> RecoveryFileGroupObservation(1, 50000)
        }
    }, 8, 354200, emptySet(), "a".repeat(64), at)
    private fun source() = UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
        UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
        DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.PAIR_PRESENT, at)
    private val report = AtomicReference<UpdatePreflightSnapshot?>(UpdatePreflightSnapshot(scope, UpdateRootStatus.DIRECT_ROOT,
        UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0",
        ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, at, UpdateServerArchitecture.AMD64, source(), files()))
    private val starts = AtomicInteger(); private val reads = AtomicInteger()
    private var read: suspend () -> UpdatePreflightStatus = { status() }
    private fun status() = UpdatePreflightStatus(text = "Fixture completed preparation", terminal = true, snapshot = report.get())
    private val statuses = UpdatePreflightStatusPort { server, install, pointer ->
        assertEquals("server", server); assertEquals("install", install); assertEquals(UpdatePreflightPointer("prepared", "ssh"), pointer)
        reads.incrementAndGet(); read()
    }
    private val readiness = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String): LocalSshAccessList = error("No broad lookup")
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
            assertEquals("server", serverId); assertEquals("ssh", accessId)
            return LocalSshReadinessResult.MetadataPresent(profile.get())
        }
    }
    private val actions = UpdatePreflightActionPort { _, _, _ -> starts.incrementAndGet(); UpdatePreflightStart.Blocked("Fixture blocked") }
    private val localPort = ManagementLocalReviewPort { server, install -> assertEquals("server", server); assertEquals("install", install); local.get() }

    @Test fun restoredInventoryDoesNotCreateConnectionsOrAnArchive() {
        show(); await("recovery_files_observed"); absent("recovery_file_details"); assertEquals(0, starts.get())
    }
    @Test fun groupsAndUniqueAggregateReflectTypedFactsWithoutDoubleCountingSharedTls() {
        show(); await("recovery_files_observed")
        compose.onNodeWithTag("recovery_files_observed").assertTextContains("8 · 354200", substring = true)
        compose.onNodeWithTag("recovery_file_group_PANEL_TLS").assertTextContains("файлов: 2 · 4000", substring = true)
        compose.onNodeWithTag("recovery_file_group_XRAY_DATA").assertTextContains("файлов: 1 · 50000", substring = true)
    }
    @Test fun observedInventoryNeverClaimsACreatedCopyOrVerifiedRestore() {
        show(); await("recovery_files_boundary")
        compose.onNodeWithTag("recovery_files_boundary").assertTextContains("а не сохранённая копия", substring = true)
        compose.onNodeWithTag("recovery_files_boundary").assertTextContains("не подтверждены", substring = true)
    }
    @Test fun oldAcceptedReportWithoutInventoryRequestsAnotherExplicitCheck() {
        report.set(requireNotNull(report.get()).copy(recoveryFiles = null))
        show(); await("recovery_files_missing"); absent("recovery_files_observed"); assertEquals(0, starts.get())
    }
    @Test fun exactlyFiveMinuteOldInventoryCannotRemainAFreshKnownSet() {
        clock.set(at.plusSeconds(300)); show(); await("recovery_files_stale"); absent("recovery_files_observed")
        absent("recovery_file_group_RUNTIME"); assertEquals(0, starts.get())
    }
    @Test fun futureObservationCannotBePresentedAsFresh() {
        clock.set(at.minusSeconds(1)); show(); await("recovery_files_stale"); absent("recovery_files_observed")
    }
    @Test fun unresolvedExternalReferenceIsVisibleAndDoesNotBecomeZeroDependencies() {
        issue(RecoveryFileIssue.UNKNOWN_REFERENCE); show(); await("recovery_file_issue_UNKNOWN_REFERENCE")
        compose.onNodeWithTag("recovery_file_issue_UNKNOWN_REFERENCE").assertTextContains("другие абсолютные пути", substring = true)
        absent("recovery_files_observed")
    }
    @Test fun serviceEnvironmentNeedsSeparateReview() {
        issue(RecoveryFileIssue.SERVICE_ENVIRONMENT); show(); await("recovery_file_issue_SERVICE_ENVIRONMENT")
        absent("recovery_files_observed"); assertEquals(0, starts.get())
    }
    @Test fun readFailureIsNotInventedAsAnEmptySuccessfulInventory() {
        report.set(requireNotNull(report.get()).copy(recoveryFiles = RecoveryFileInventory.unavailable(scope, RecoveryFileIssue.READ_UNAVAILABLE, at)))
        show(); await("recovery_file_issue_READ_UNAVAILABLE"); absent("recovery_files_observed")
    }
    @Test fun unsafePrivateFilesRemainBlockingFindings() {
        issue(RecoveryFileIssue.UNSAFE_FILE); show(); await("recovery_file_issue_UNSAFE_FILE"); absent("recovery_files_observed")
    }
    @Test fun changedReferencesRequireAnotherExplicitRead() {
        issue(RecoveryFileIssue.REFERENCES_CHANGED); show(); await("recovery_file_issue_REFERENCES_CHANGED"); assertEquals(0, starts.get())
    }
    @Test fun limitsExplainWhyTheFileSetIsIncomplete() {
        issue(RecoveryFileIssue.LIMIT_EXCEEDED); show(); await("recovery_file_issue_LIMIT_EXCEEDED")
        compose.onNodeWithTag("recovery_file_issue_LIMIT_EXCEEDED").assertTextContains("96 файлов", substring = true)
        absent("recovery_files_observed")
    }
    @Test fun locallyRevalidatedPlanShowsEveryPendingArchiveAndRestoreProof() {
        show(); request(); await("recovery_file_details")
        RecoveryFileArtifactProof.values().forEach { compose.onNodeWithTag("recovery_file_pending_" + it.name).assertExists() }
        assertEquals(2, reads.get()); assertEquals(0, starts.get())
    }
    @Test fun closingPlanDoesNotAuthorizeOrDispatchAnyFileCopy() {
        show(); request(); await("recovery_plan_close"); compose.onNodeWithTag("recovery_plan_close").performClick()
        absent("recovery_file_details"); assertEquals(0, starts.get())
    }
    @Test fun editedLocalTargetSuppressesOldInventoryDuringPlanReview() {
        show(); local.set((local.get() as LocalManagementReview.Ready).copy(panelPort = 8443)); request()
        await("update_preparation_unavailable"); absent("recovery_file_details"); absent("recovery_file_inventory")
    }
    @Test fun leavingForegroundDropsLateInventoryReviewAndDoesNotReplay() {
        val model = show(); val pending = CompletableDeferred<UpdatePreflightStatus>()
        read = { withContext(NonCancellable) { pending.await() } }
        request(); compose.waitUntil(10_000) { reads.get() == 2 }
        compose.runOnIdle { model.leaveForeground(); pending.complete(status()); read = { status() } }
        compose.waitForIdle(); absent("recovery_file_details")
        compose.runOnIdle { model.enterForeground() }; await("recovery_file_inventory")
        absent("recovery_file_details"); assertEquals(0, starts.get())
    }
    @Test fun processDeathKeepsOnlyPointerAndCannotInventLostFileFacts() {
        val saved = saved(); val model = show(saved); request(); await("recovery_file_details")
        assertEquals(setOf("update_preflight_server", "update_preflight_installation", "update_preflight_access", "update_preflight_operation"), saved.keys())
        report.set(null)
        lateinit var restored: ManagementUpdatePreparationViewModel
        compose.runOnIdle { model.leaveForeground(); restored = newModel(saved); restored.enterForeground() }
        compose.waitUntil(10_000) { restored.state.value.result != null }
        assertNull(restored.state.value.result!!.snapshot); assertNull(restored.state.value.recoveryPlan)
        assertEquals(0, starts.get()); compose.runOnIdle { restored.leaveForeground() }
    }
    @Test fun duplicatePlanRequestsPerformOneLocalRevalidationAndNoRemoteWork() {
        val model = show(); val before = reads.get()
        compose.runOnIdle { model.requestRecoveryPlan(); model.requestRecoveryPlan() }
        await("recovery_file_details"); assertEquals(before + 1, reads.get()); assertEquals(0, starts.get())
    }

    private fun issue(issue: RecoveryFileIssue) { report.set(requireNotNull(report.get()).copy(recoveryFiles = files().copy(issues = setOf(issue), knownSetDigest = null))) }
    private fun newModel(saved: SavedStateHandle) = ManagementUpdatePreparationViewModel(saved, "server", "install", "ssh", localPort, statuses, readiness, now = { clock.get() })
    private fun show(saved: SavedStateHandle = saved()): ManagementUpdatePreparationViewModel {
        val model = newModel(saved)
        compose.setContent { VelumTegraTheme { ManagementUpdatePreparationScreen(model, actions, {}) } }
        await("recovery_file_inventory"); return model
    }
    private fun saved() = SavedStateHandle(mapOf("update_preflight_server" to "server", "update_preflight_installation" to "install", "update_preflight_access" to "ssh", "update_preflight_operation" to "prepared"))
    private fun request() = compose.onNodeWithTag("recovery_plan_request").performScrollTo().performClick()
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
}
