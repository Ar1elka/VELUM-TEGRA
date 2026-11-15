package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.readiness.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Memory-only UI fixtures. No server, SSH client, SecretStore or app production database. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_1UpdatePreparationAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val time = Instant.parse("2026-10-15T18:00:00Z")
    private val local = AtomicReference<LocalManagementReview>(LocalManagementReview.Ready(
        "Fixture VPS", "server", "install", "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("ssh")))
    private val profile = AtomicReference(LocalSshAccessSummary("ssh", "fixture.invalid", 22, "operator", "Пароль", "SHA256:fixture", "ref-digest"))
    private val starts = AtomicInteger()
    private val reads = ConcurrentLinkedQueue<String>()
    private val localPort = ManagementLocalReviewPort { server, install ->
        assertEquals("server", server); assertEquals("install", install); local.get()
    }
    private val readiness = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String): LocalSshAccessList = error("No broad metadata lookup")
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
            assertEquals("server", serverId); assertEquals("ssh", accessId)
            return LocalSshReadinessResult.MetadataPresent(profile.get())
        }
    }
    private val actions = UpdatePreflightActionPort { server, install, access ->
        assertEquals("server", server); assertEquals("install", install); assertEquals("ssh", access)
        UpdatePreflightStart.Registered(UpdatePreflightPointer("op-" + starts.incrementAndGet(), access))
    }
    private var response: suspend (UpdatePreflightPointer) -> UpdatePreflightStatus = { result(it) }
    private val statuses = UpdatePreflightStatusPort { server, install, pointer ->
        assertEquals("server", server); assertEquals("install", install); assertEquals("ssh", pointer.accessId)
        reads.add(pointer.operationId); response(pointer)
    }

    @Test fun openingReadsLocalMetadataAndNeverStartsOrReadsRemotePreflight() {
        show(); assertEquals(0, starts.get()); assertTrue(reads.isEmpty())
        absent("update_preparation_check_CURRENT_VERSION")
    }
    @Test fun dismissingReviewNeverDispatches() {
        show(); request(); compose.onNodeWithTag("update_preparation_cancel").performClick()
        assertEquals(0, starts.get()); assertTrue(reads.isEmpty())
    }
    @Test fun explicitConfirmationUsesExactReviewedTupleAndShowsObservedFacts() {
        show(); request(); confirm(); await("update_preparation_check_CURRENT_VERSION")
        assertEquals(1, starts.get()); assertEquals(listOf("op-1"), reads.toList())
        compose.onNodeWithTag("update_preparation_status").assertTextContains("Проверка установки завершена", substring = true)
    }
    @Test fun duplicateConfirmationCannotLaunchTwice() {
        val model = show(); request()
        compose.runOnIdle { model.confirmRead(actions); model.confirmRead(actions) }
        await("update_preparation_check_CURRENT_VERSION"); assertEquals(1, starts.get())
    }
    @Test fun restoredPointerReadsOnlyLocalStatusAndNeverReplaysOperation() {
        response = { UpdatePreflightStatus("Запрос завершён. Детали не сохранены.", true) }
        show(saved()); await("update_preparation_status")
        absent("update_preparation_check_CURRENT_VERSION")
        assertEquals(listOf("restored"), reads.toList()); assertEquals(0, starts.get())
    }
    @Test fun savedPointerForAnotherServerIsIgnored() {
        show(saved(server = "foreign")); assertTrue(reads.isEmpty()); assertEquals(0, starts.get())
    }
    @Test fun removedBindingBlocksActionAndHidesSavedFacts() {
        local.set((local.get() as LocalManagementReview.Ready).copy(accessIds = emptyList(), managementBindings = 0))
        show(saved(), ready = false); await("update_preparation_unavailable")
        absent("update_preparation_request"); assertTrue(reads.isEmpty()); assertEquals(0, starts.get())
    }
    @Test fun targetChangedDuringStatusReadCannotDiscloseTheLateSnapshot() {
        val delayed = CompletableDeferred<UpdatePreflightStatus>()
        response = { withContext(NonCancellable) { delayed.await() } }
        show(saved()); compose.waitUntil(10_000) { reads.size == 1 }
        compose.runOnIdle {
            local.set((local.get() as LocalManagementReview.Ready).copy(panelPort = 2054))
            delayed.complete(result(UpdatePreflightPointer("restored", "ssh")))
        }
        await("update_preparation_unavailable"); absent("update_preparation_check_CURRENT_VERSION")
    }
    @Test fun resultArrivingAfterLeavingForegroundIsNotProjected() {
        val delayed = CompletableDeferred<UpdatePreflightStatus>()
        response = { withContext(NonCancellable) { delayed.await() } }
        val model = show(saved()); compose.waitUntil(10_000) { reads.size == 1 }
        compose.runOnIdle { model.leaveForeground(); delayed.complete(result(UpdatePreflightPointer("restored", "ssh"))) }
        compose.waitForIdle(); absent("update_preparation_check_CURRENT_VERSION"); assertEquals(0, starts.get())
    }
    @Test fun sshProfileChangedAfterReviewBlocksConfirmationBeforeLaunch() {
        show(); request()
        profile.set(profile.get().copy(host = "changed.invalid"))
        confirm(); await("update_preparation_unavailable"); assertEquals(0, starts.get())
    }
    @Test fun statusPortCannotDisplayAnotherOperationsFacts() {
        response = { result(UpdatePreflightPointer("foreign-operation", "ssh")) }
        show(saved(), ready = false); await("update_preparation_unavailable"); absent("update_preparation_check_CURRENT_VERSION")
    }
    @Test fun newExplicitReadCreatesAnotherRequestWithoutReplayingTheOldId() {
        show(); request(); confirm(); await("update_preparation_check_CURRENT_VERSION")
        request(); confirm()
        compose.waitUntil(10_000) { reads.size == 2 }
        assertEquals(listOf("op-1", "op-2"), reads.toList()); assertEquals(2, starts.get())
    }

    @Test fun lateStartReturnCannotReplaceANewerExplicitRequestsPointer() {
        val delayed = CompletableDeferred<UpdatePreflightStart>()
        val attempts = AtomicInteger()
        val action = UpdatePreflightActionPort { _, _, _ ->
            if (attempts.incrementAndGet() == 1) withContext(NonCancellable) { delayed.await() }
            else UpdatePreflightStart.Registered(UpdatePreflightPointer("newer", "ssh"))
        }
        val model = show()
        compose.runOnIdle { model.requestRead(); model.confirmRead(action) }
        compose.waitUntil(10_000) { attempts.get() == 1 }
        compose.runOnIdle { model.leaveForeground(); model.enterForeground() }
        await("update_preparation_server")
        compose.runOnIdle { model.requestRead(); model.confirmRead(action) }
        compose.waitUntil(10_000) { model.state.value.pointer?.operationId == "newer" }
        compose.runOnIdle { delayed.complete(UpdatePreflightStart.Registered(UpdatePreflightPointer("older", "ssh"))) }
        compose.waitForIdle()
        assertEquals("newer", model.state.value.pointer?.operationId)
        assertFalse("older" in reads)
    }

    @Test fun managementHomeRequiresExactSshSelectionBeforeOpeningPreparation() {
        val opened = AtomicReference<String?>(null)
        val inspectionStatus = object : ManagementInspectionStatusPort {
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = error("No inspection requested")
            override suspend fun unfinishedExact(serverId: String, installationId: String) = emptyList<UnfinishedManagementInspection>()
        }
        val launcher = object : VisibleManagementInspectionsPort {
            override suspend fun start(kind: InspectionKind, serverId: String, installationId: String,
                serverAccessId: String): InspectionStart = error("Opening update preparation must not launch inspection")
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = error("No inspection requested")
        }
        val model = ManagementHomeViewModel(SavedStateHandle(), "server", "install", localPort, readiness,
            inspectionStatus, ManagementVersionReadPort { _, _, _ -> error("No version request") })
        compose.setContent { VelumTegraTheme { ManagementHomeScreen(model, launcher, {}, {}, {}, {},
            onUpdatePreparation = { opened.set(it) }) } }
        await("management_home_server")
        compose.onNodeWithTag("management_home_update_preparation").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("management_home_access_ssh").performScrollTo().performClick()
        compose.onNodeWithTag("management_home_update_preparation").performScrollTo().performClick()
        assertEquals("ssh", opened.get()); assertEquals(0, starts.get()); assertTrue(reads.isEmpty())
    }

    @Test fun allChecksPassedStillShowsThatNoUpdateWasStarted() {
        show(saved()); await("update_preparation_check_CURRENT_VERSION")
        compose.onNodeWithTag("update_preparation_verdict").assertTextContains("Предварительные проверки пройдены", substring = true)
        compose.onNodeWithTag("update_preparation_next_steps").performScrollTo()
        compose.onNodeWithText("Обновление не запускалось.").assertExists()
        assertEquals(0, starts.get()); assertEquals(1, reads.size)
    }
    @Test fun nonRootConnectionProducesBlockingVerdict() {
        response = { result(it, root = UpdateRootStatus.NOT_ROOT) }
        show(saved()); await("update_preparation_check_DIRECT_ROOT")
        compose.onNodeWithTag("update_preparation_verdict").assertTextContains("Нужно устранить замечания", substring = true)
        compose.onNodeWithText("Подключение без прав root").assertExists()
    }
    @Test fun nonstandardLayoutDoesNotInventVersionOrRootProof() {
        response = { result(it, root = UpdateRootStatus.UNOBSERVED, layout = UpdateLayoutStatus.UNSUPPORTED,
            definition = DeepDiagnosticServiceDefinitionStatus.UNREADABLE, version = null) }
        show(saved()); await("update_preparation_check_CURRENT_VERSION")
        compose.onNodeWithText("Версия не подтверждена").assertExists()
        compose.onNodeWithText("Права не проверены").assertExists()
        compose.onNodeWithTag("update_preparation_verdict").assertTextContains("Нужно устранить замечания", substring = true)
    }
    @Test fun changedSettingsRemainAVisibleBlockingFinding() {
        response = { result(it, baseline = ManagementBaselineStatus.Drift(setOf(ManagementBaselineDrift.PANEL_PORT))) }
        show(saved()); await("update_preparation_check_SAVED_SETTINGS")
        compose.onNodeWithText("Обнаружены изменения настроек").assertExists()
        compose.onNodeWithTag("update_preparation_verdict").assertTextContains("Нужно устранить замечания", substring = true)
    }
    @Test fun unavailableVersionDoesNotBecomeAnAssumedLatestRelease() {
        response = { result(it, version = null) }
        show(saved()); await("update_preparation_check_CURRENT_VERSION")
        compose.onNodeWithText("Версия не подтверждена").assertExists()
        assertEquals(0, starts.get()); assertEquals(1, reads.size)
    }

    private fun show(saved: SavedStateHandle = SavedStateHandle(), ready: Boolean = true): ManagementUpdatePreparationViewModel {
        val model = ManagementUpdatePreparationViewModel(saved, "server", "install", "ssh", localPort, statuses, readiness)
        compose.setContent { VelumTegraTheme { ManagementUpdatePreparationScreen(model, actions, {}) } }
        if (ready) await("update_preparation_server")
        return model
    }
    private fun request() {
        compose.onNodeWithTag("update_preparation_request").performScrollTo().performClick(); await("update_preparation_confirm")
    }
    private fun confirm() = compose.onNodeWithTag("update_preparation_confirm").performClick()
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun saved(server: String = "server") = SavedStateHandle(mapOf("update_preflight_server" to server, "update_preflight_installation" to "install",
        "update_preflight_access" to "ssh", "update_preflight_operation" to "restored"))
    private fun result(pointer: UpdatePreflightPointer, root: UpdateRootStatus = UpdateRootStatus.DIRECT_ROOT,
        layout: UpdateLayoutStatus = UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD,
        definition: DeepDiagnosticServiceDefinitionStatus = DeepDiagnosticServiceDefinitionStatus.CONSISTENT,
        version: String? = "3.0.0", baseline: ManagementBaselineStatus = ManagementBaselineStatus.Matched) =
        UpdatePreflightStatus("Проверка установки завершена. Обновление не запускалось.", true,
            UpdatePreflightSnapshot(ManagementScope(OperationId(pointer.operationId), ServerId("server"),
                ServerAccessId(pointer.accessId), XuiInstallationId("install")), root, layout, definition, version,
                ManagementServiceState.ACTIVE, baseline, time.plusSeconds(2)))
}
