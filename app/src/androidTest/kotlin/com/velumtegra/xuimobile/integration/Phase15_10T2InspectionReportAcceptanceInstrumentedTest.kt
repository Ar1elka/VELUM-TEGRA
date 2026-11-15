package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.Lifecycle
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
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Memory-only Android UI. The history ViewModel has no launch/SSH/credential dependency. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T2InspectionReportAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val time = Instant.parse("2026-10-15T12:00:00Z")
    private val local = AtomicReference<LocalManagementReview>(LocalManagementReview.Ready(
        "Fixture VPS", "server-1", "install-1", "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("ssh-1")))
    private val page = AtomicReference<InspectionHistoryRead>(InspectionHistoryRead.Page(listOf(
        entry("quick", InspectionKind.QUICK_INSPECT), entry("deep", InspectionKind.DEEP_DIAGNOSTIC))))
    private val requested = ConcurrentLinkedQueue<String>()
    private val historyReads = AtomicInteger()
    private val localPort = ManagementLocalReviewPort { server, installation ->
        assertEquals("server-1", server); assertEquals("install-1", installation); local.get()
    }
    private val history = ManagementInspectionHistoryPort { server, installation ->
        assertEquals("server-1", server); assertEquals("install-1", installation)
        historyReads.incrementAndGet(); page.get()
    }
    private var response: suspend (String) -> InspectionStatus = { id ->
        if (id == "deep") report(DeepDiagnosticOverallStatus.CRITICAL) else report()
    }
    private val statuses = object : ManagementInspectionStatusPort {
        override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
            installationId: String, serverAccessId: String): InspectionStatus {
            assertEquals("server-1", serverId); assertEquals("install-1", installationId)
            assertEquals("ssh-1", serverAccessId); requested.add(operationId)
            return response(operationId)
        }
        override suspend fun unfinishedExact(serverId: String, installationId: String) =
            emptyList<UnfinishedManagementInspection>()
    }

    @Test fun openingHistoryReadsOnlyItsLocalInventory() {
        show()
        await("inspection_history_entry_quick")
        assertEquals(1, historyReads.get())
        assertEquals(emptyList<String>(), requested.toList())
    }

    @Test fun successfulInspectionWithActiveServiceStillShowsCriticalCertificateFinding() {
        show(); openReport("deep")
        compose.onNodeWithTag("inspection_report_overall").performScrollTo().assertTextEquals("Есть критические проблемы")
        compose.onNodeWithTag("inspection_report_service").performScrollTo().assertTextEquals("Служба: Работает")
        compose.onNodeWithTag("inspection_report_finding_CERTIFICATE_EXPIRED").performScrollTo()
            .assertTextEquals("Критично · Срок действия сертификата истёк")
        assertEquals(listOf("deep"), requested.toList())
    }

    @Test fun quickReportExplainsExactChangesAndEvidenceGaps() {
        response = { InspectionStatus("Проверка завершена", true, true, detail = InspectionReportDetail(
            ManagementIdentityStatus.Drift(setOf(ManagementIdentityDrift.MANAGED_MARKER_MISMATCH)),
            ManagementBaselineStatus.Insufficient(setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED)), time)) }
        show(); openReport("quick")
        compose.onNodeWithTag("inspection_report_identity_MANAGED_MARKER_MISMATCH").performScrollTo()
            .assertTextEquals("Метка управляемой установки отличается от сохранённой.")
        compose.onNodeWithTag("inspection_report_baseline_gap_PANEL_SETTINGS_UNOBSERVED").performScrollTo()
            .assertTextEquals("Настройки панели не удалось прочитать.")
        absent("inspection_report_overall")
    }

    @Test fun durableOnlyResultDoesNotInventServerHealthAfterProcessDeath() {
        response = { InspectionStatus("Диагностика завершена; подробности предыдущего процесса недоступны.",
            true, completedAt = time) }
        show(); openReport("deep")
        await("inspection_report_missing")
        absent("inspection_report_service")
        absent("inspection_report_overall")
        absent("inspection_report_finding_CERTIFICATE_EXPIRED")
    }

    @Test fun filterAndBackKeepTheSelectedHistoryKindWithoutStartingChecks() {
        show()
        compose.onNodeWithTag("inspection_history_filter_DEEP").performScrollTo().performClick()
        absent("inspection_history_entry_quick")
        openReport("deep")
        compose.onNodeWithTag("inspection_history_back").performScrollTo().performClick()
        compose.onNodeWithTag("inspection_history_filter_DEEP").performScrollTo().assertIsSelected()
        absent("inspection_history_entry_quick")
        assertEquals(listOf("deep"), requested.toList())
    }

    @Test fun foreignSavedScopeDoesNotFallBackToTheNewestOperation() {
        show(saved("old-operation", server = "foreign-server"))
        assertEquals(emptyList<String>(), requested.toList())
        absent("inspection_history_report")
    }

    @Test fun exactSavedPointerReadsThatOlderOperationEvenOutsideTheLatestPage() {
        show(saved("older-operation"))
        await("inspection_history_report")
        assertEquals(listOf("older-operation"), requested.toList())
    }

    @Test fun savedUnlinkedAccessCannotReadDetailedResults() {
        show(saved("old-operation", access = "unlinked-ssh"))
        await("inspection_history_notice")
        assertEquals(emptyList<String>(), requested.toList())
        absent("inspection_history_report")
    }

    @Test fun lateOldReportCannotReplaceANewSelection() {
        val delayed = CompletableDeferred<InspectionStatus>()
        response = { id -> if (id == "quick") withContext(NonCancellable) { delayed.await() }
            else report(DeepDiagnosticOverallStatus.HEALTHY) }
        val model = show()
        compose.onNodeWithTag("inspection_history_open_quick").performScrollTo().performClick()
        compose.waitUntil(10_000) { "quick" in requested }
        compose.runOnIdle { model.clearSelection() }
        openReport("deep")
        compose.runOnIdle { delayed.complete(report(DeepDiagnosticOverallStatus.CRITICAL)) }
        compose.waitForIdle()
        compose.onNodeWithTag("inspection_report_overall").performScrollTo()
            .assertTextEquals("По результатам диагностики проблем не выявлено")
        absent("inspection_report_finding_CERTIFICATE_EXPIRED")
    }

    @Test fun foregroundRevalidationClearsAReportWhenTheInstallationChanges() {
        show(); openReport("deep")
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        local.set(LocalManagementReview.Unavailable("Установка больше недоступна"))
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        await("inspection_history_unavailable")
        absent("inspection_history_report")
        absent("inspection_report_overall")
        assertEquals(listOf("deep"), requested.toList())
    }

    @Test fun inventoryFailureClearsOldRowsWithoutClaimingThereAreZeroChecks() {
        show(); page.set(InspectionHistoryRead.Unavailable)
        compose.onNodeWithTag("inspection_history_refresh").performScrollTo().performClick()
        await("inspection_history_notice")
        absent("inspection_history_entry_quick")
        absent("inspection_history_empty")
        assertEquals(emptyList<String>(), requested.toList())
    }

    @Test fun foreignInventoryPageCannotDisplayAnotherInstallationsRows() {
        page.set(InspectionHistoryRead.Page(listOf(entry("foreign", InspectionKind.QUICK_INSPECT,
            server = "foreign-server"))))
        show(); await("inspection_history_notice")
        absent("inspection_history_entry_foreign")
        assertEquals(emptyList<String>(), requested.toList())
    }

    @Test fun removedSshBindingKeepsSavedSummaryButDisablesDetailedRead() {
        page.set(InspectionHistoryRead.Page(listOf(entry("unlinked", InspectionKind.QUICK_INSPECT,
            access = "removed-ssh"))))
        show()
        compose.onNodeWithTag("inspection_history_open_unlinked").performScrollTo().assertIsNotEnabled()
        assertEquals(emptyList<String>(), requested.toList())
    }

    @Test fun lateInventoryCannotReplaceTheRefreshedPage() {
        val delayed = CompletableDeferred<InspectionHistoryRead>()
        val attempts = AtomicInteger()
        val reader = ManagementInspectionHistoryPort { _, _ ->
            if (attempts.incrementAndGet() == 1) withContext(NonCancellable) { delayed.await() }
            else InspectionHistoryRead.Page(listOf(entry("fresh", InspectionKind.QUICK_INSPECT)))
        }
        val model = show(historyPort = reader, waitForReady = false)
        compose.waitUntil(10_000) { attempts.get() == 1 }
        compose.runOnIdle { model.refresh() }
        await("inspection_history_entry_fresh")
        compose.runOnIdle { delayed.complete(InspectionHistoryRead.Page(listOf(entry("old", InspectionKind.QUICK_INSPECT)))) }
        compose.waitForIdle()
        absent("inspection_history_entry_old")
        assertEquals(0, requested.size)
    }

    @Test fun metadataChangedDuringAResultReadPreventsFactDisclosure() {
        val delayed = CompletableDeferred<InspectionStatus>()
        response = { withContext(NonCancellable) { delayed.await() } }
        show()
        compose.onNodeWithTag("inspection_history_open_quick").performScrollTo().performClick()
        compose.waitUntil(10_000) { "quick" in requested }
        compose.runOnIdle {
            local.set((local.get() as LocalManagementReview.Ready).copy(panelPort = 2054))
            delayed.complete(report(DeepDiagnosticOverallStatus.CRITICAL))
        }
        await("inspection_history_unavailable")
        absent("inspection_history_report")
        absent("inspection_report_finding_CERTIFICATE_EXPIRED")
    }

    @Test fun managementHomeExposesHistoryWithoutSshSelectionOrNetworkLaunch() {
        val opened = AtomicInteger()
        val readiness = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String): LocalSshAccessList =
                throw AssertionError("No broad access lookup")
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult =
                LocalSshReadinessResult.MetadataPresent(LocalSshAccessSummary("ssh-1", "fixture.invalid", 22,
                    "operator", "Пароль", "SHA256:fixture", "fixture-reference-digest"))
        }
        val launcher = object : VisibleManagementInspectionsPort {
            override suspend fun start(kind: InspectionKind, serverId: String, installationId: String,
                serverAccessId: String): InspectionStart = throw AssertionError("History must not launch")
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = throw AssertionError("No launch status fallback")
        }
        val model = ManagementHomeViewModel(SavedStateHandle(), "server-1", "install-1", localPort,
            readiness, statuses, ManagementVersionReadPort { _, _, _ -> throw AssertionError("No version request") })
        compose.setContent { VelumTegraTheme { ManagementHomeScreen(model, launcher, {}, {}, {}, {},
            onHistory = { opened.incrementAndGet() }) } }
        await("management_home_server")
        compose.onNodeWithTag("management_home_history").performScrollTo().performClick()
        assertEquals(1, opened.get())
        assertEquals(emptyList<String>(), requested.toList())
    }

    private fun show(saved: SavedStateHandle = SavedStateHandle(),
        historyPort: ManagementInspectionHistoryPort = history, waitForReady: Boolean = true): ManagementInspectionHistoryViewModel {
        val model = ManagementInspectionHistoryViewModel(saved, "server-1", "install-1", localPort, historyPort, statuses)
        compose.setContent { VelumTegraTheme { ManagementInspectionHistoryScreen(model, {}) } }
        if (waitForReady) await("inspection_history_server")
        return model
    }

    private fun await(tag: String) {
        compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun openReport(id: String) {
        compose.onNodeWithTag("inspection_history_open_" + id).performScrollTo().performClick()
        await("inspection_history_report")
    }
    private fun entry(id: String, kind: InspectionKind, access: String = "ssh-1", server: String = "server-1") =
        InspectionHistoryEntry(id, server, "install-1", access, kind, OperationStatus.SUCCEEDED, time, time.plusSeconds(1))
    private fun saved(operation: String, server: String = "server-1", access: String = "ssh-1") = SavedStateHandle(mapOf(
        "history_server" to server, "history_installation" to "install-1", "history_operation" to operation,
        "history_access" to access, "history_kind" to InspectionKind.DEEP_DIAGNOSTIC.name))
    private fun report(overall: DeepDiagnosticOverallStatus? = null) = InspectionStatus("Проверка завершена.", true,
        true, ManagementServiceState.ACTIVE, observedAt = time, detail = InspectionReportDetail(
            ManagementIdentityStatus.Matched, ManagementBaselineStatus.Matched, time.plusSeconds(1), overall,
            if (overall == DeepDiagnosticOverallStatus.CRITICAL) listOf(DeepDiagnosticFinding(
                DeepDiagnosticFindingCode.CERTIFICATE_EXPIRED, DeepDiagnosticSeverity.CRITICAL)) else emptyList()))
}
