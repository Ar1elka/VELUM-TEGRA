package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
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
class Phase15_10T3ServiceLogsAcceptanceInstrumentedTest {
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
    private val actions = ServiceLogActionPort { server, install, access ->
        assertEquals("server", server); assertEquals("install", install); assertEquals("ssh", access)
        ServiceLogStart.Registered(ServiceLogPointer("op-" + starts.incrementAndGet(), access))
    }
    private var response: suspend (ServiceLogPointer) -> ServiceLogStatus = { result(it) }
    private val statuses = ServiceLogStatusPort { server, install, pointer ->
        assertEquals("server", server); assertEquals("install", install); assertEquals("ssh", pointer.accessId)
        reads.add(pointer.operationId); response(pointer)
    }

    @Test fun openingReadsLocalMetadataAndNeverStartsOrReadsRemoteLogs() {
        show(); assertEquals(0, starts.get()); assertTrue(reads.isEmpty())
        absent("service_logs_entry_0")
    }
    @Test fun dismissingReviewNeverDispatches() {
        show(); request(); compose.onNodeWithTag("service_logs_cancel").performClick()
        assertEquals(0, starts.get()); assertTrue(reads.isEmpty())
    }
    @Test fun explicitConfirmationUsesExactReviewedTupleAndShowsSafeEvents() {
        show(); request(); confirm(); await("service_logs_entry_0")
        assertEquals(1, starts.get()); assertEquals(listOf("op-1"), reads.toList())
        compose.onNodeWithTag("service_logs_status").assertTextContains("События получены", substring = true)
    }
    @Test fun duplicateConfirmationCannotLaunchTwice() {
        val model = show(); request()
        compose.runOnIdle { model.confirmRead(actions); model.confirmRead(actions) }
        await("service_logs_entry_0"); assertEquals(1, starts.get())
    }
    @Test fun severityFilterUsesOnlyThisSnapshotWithoutStartingOrRequerying() {
        show(saved()); await("service_logs_entry_1")
        compose.onNodeWithTag("service_logs_warnings").performScrollTo().performClick().assertIsSelected()
        absent("service_logs_entry_1")
        assertEquals(0, starts.get()); assertEquals(1, reads.size)
    }
    @Test fun emptyJournalDoesNotClaimHealthyService() {
        response = { result(it, entries = emptyList()) }
        show(saved()); await("service_logs_empty")
        compose.onNodeWithTag("service_logs_empty").assertTextContains("не подтверждает отсутствие ошибок", substring = true)
    }
    @Test fun olderRecordFlagIsVisibleAndNeverTriggersPagination() {
        response = { result(it, older = true) }
        show(saved()); await("service_logs_older")
        assertEquals(1, reads.size); assertEquals(0, starts.get())
    }
    @Test fun restoredPointerReadsOnlyLocalStatusAndNeverReplaysOperation() {
        response = { ServiceLogStatus("Запрос завершён. Детали не сохранены.", true) }
        show(saved()); await("service_logs_status")
        absent("service_logs_entry_0")
        assertEquals(listOf("restored"), reads.toList()); assertEquals(0, starts.get())
    }
    @Test fun savedPointerForAnotherServerIsIgnored() {
        show(saved(server = "foreign")); assertTrue(reads.isEmpty()); assertEquals(0, starts.get())
    }
    @Test fun removedBindingBlocksActionAndHidesSavedEvents() {
        local.set((local.get() as LocalManagementReview.Ready).copy(accessIds = emptyList(), managementBindings = 0))
        show(saved(), ready = false); await("service_logs_unavailable")
        absent("service_logs_request"); assertTrue(reads.isEmpty()); assertEquals(0, starts.get())
    }
    @Test fun targetChangedDuringStatusReadCannotDiscloseTheLateSnapshot() {
        val delayed = CompletableDeferred<ServiceLogStatus>()
        response = { withContext(NonCancellable) { delayed.await() } }
        show(saved()); compose.waitUntil(10_000) { reads.size == 1 }
        compose.runOnIdle {
            local.set((local.get() as LocalManagementReview.Ready).copy(panelPort = 2054))
            delayed.complete(result(ServiceLogPointer("restored", "ssh")))
        }
        await("service_logs_unavailable"); absent("service_logs_entry_0")
    }
    @Test fun resultArrivingAfterLeavingForegroundIsNotProjected() {
        val delayed = CompletableDeferred<ServiceLogStatus>()
        response = { withContext(NonCancellable) { delayed.await() } }
        val model = show(saved()); compose.waitUntil(10_000) { reads.size == 1 }
        compose.runOnIdle { model.leaveForeground(); delayed.complete(result(ServiceLogPointer("restored", "ssh"))) }
        compose.waitForIdle(); absent("service_logs_entry_0"); assertEquals(0, starts.get())
    }
    @Test fun sshProfileChangedAfterReviewBlocksConfirmationBeforeLaunch() {
        show(); request()
        profile.set(profile.get().copy(host = "changed.invalid"))
        confirm(); await("service_logs_unavailable"); assertEquals(0, starts.get())
    }
    @Test fun statusPortCannotDisplayAnotherOperationsFacts() {
        response = { result(ServiceLogPointer("foreign-operation", "ssh")) }
        show(saved(), ready = false); await("service_logs_unavailable"); absent("service_logs_entry_0")
    }
    @Test fun newExplicitReadCreatesAnotherRequestWithoutReplayingTheOldId() {
        show(); request(); confirm(); await("service_logs_entry_0")
        request(); confirm()
        compose.waitUntil(10_000) { reads.size == 2 }
        assertEquals(listOf("op-1", "op-2"), reads.toList()); assertEquals(2, starts.get())
    }

    @Test fun lateStartReturnCannotReplaceANewerExplicitRequestsPointer() {
        val delayed = CompletableDeferred<ServiceLogStart>()
        val attempts = AtomicInteger()
        val action = ServiceLogActionPort { _, _, _ ->
            if (attempts.incrementAndGet() == 1) withContext(NonCancellable) { delayed.await() }
            else ServiceLogStart.Registered(ServiceLogPointer("newer", "ssh"))
        }
        val model = show()
        compose.runOnIdle { model.requestRead(); model.confirmRead(action) }
        compose.waitUntil(10_000) { attempts.get() == 1 }
        compose.runOnIdle { model.leaveForeground(); model.enterForeground() }
        await("service_logs_server")
        compose.runOnIdle { model.requestRead(); model.confirmRead(action) }
        compose.waitUntil(10_000) { model.state.value.pointer?.operationId == "newer" }
        compose.runOnIdle { delayed.complete(ServiceLogStart.Registered(ServiceLogPointer("older", "ssh"))) }
        compose.waitForIdle()
        assertEquals("newer", model.state.value.pointer?.operationId)
        assertFalse("older" in reads)
    }

    @Test fun managementHomeRequiresExactSshSelectionBeforeOpeningServiceEvents() {
        val opened = AtomicReference<String?>(null)
        val inspectionStatus = object : ManagementInspectionStatusPort {
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = error("No inspection requested")
            override suspend fun unfinishedExact(serverId: String, installationId: String) = emptyList<UnfinishedManagementInspection>()
        }
        val launcher = object : VisibleManagementInspectionsPort {
            override suspend fun start(kind: InspectionKind, serverId: String, installationId: String,
                serverAccessId: String): InspectionStart = error("Opening service events must not launch inspection")
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = error("No inspection requested")
        }
        val model = ManagementHomeViewModel(SavedStateHandle(), "server", "install", localPort, readiness,
            inspectionStatus, ManagementVersionReadPort { _, _, _ -> error("No version request") })
        compose.setContent { VelumTegraTheme { ManagementHomeScreen(model, launcher, {}, {}, {}, {},
            onServiceLogs = { opened.set(it) }) } }
        await("management_home_server")
        compose.onNodeWithTag("management_home_service_logs").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("management_home_access_ssh").performScrollTo().performClick()
        compose.onNodeWithTag("management_home_service_logs").performScrollTo().performClick()
        assertEquals("ssh", opened.get()); assertEquals(0, starts.get()); assertTrue(reads.isEmpty())
    }

    private fun show(saved: SavedStateHandle = SavedStateHandle(), ready: Boolean = true): ManagementServiceLogsViewModel {
        val model = ManagementServiceLogsViewModel(saved, "server", "install", "ssh", localPort, statuses, readiness)
        compose.setContent { VelumTegraTheme { ManagementServiceLogsScreen(model, actions, {}) } }
        if (ready) await("service_logs_server")
        return model
    }
    private fun request() {
        compose.onNodeWithTag("service_logs_request").performScrollTo().performClick(); await("service_logs_confirm")
    }
    private fun confirm() = compose.onNodeWithTag("service_logs_confirm").performClick()
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun saved(server: String = "server") = SavedStateHandle(mapOf("logs_server" to server, "logs_installation" to "install",
        "logs_access" to "ssh", "logs_operation" to "restored"))
    private fun result(pointer: ServiceLogPointer, older: Boolean = false, entries: List<ServiceLogEntry> = listOf(
        ServiceLogEntry(time, 3, ServiceLogCategory.TIMEOUT), ServiceLogEntry(time.plusSeconds(1), 6, ServiceLogCategory.OTHER_REDACTED))) =
        ServiceLogStatus("События получены.", true, ServiceLogSnapshot(ManagementScope(OperationId(pointer.operationId),
            ServerId("server"), ServerAccessId(pointer.accessId), XuiInstallationId("install")), entries, older, time.plusSeconds(2)))
}
