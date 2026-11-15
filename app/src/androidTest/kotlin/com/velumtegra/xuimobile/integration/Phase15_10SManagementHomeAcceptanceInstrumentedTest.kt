package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.discovery.XuiVersionVerificationResult
import com.velumtegra.xuimobile.management.InspectionKind
import com.velumtegra.xuimobile.management.InspectionStart
import com.velumtegra.xuimobile.management.InspectionStatus
import com.velumtegra.xuimobile.management.LocalManagementReview
import com.velumtegra.xuimobile.management.ManagementHomeScreen
import com.velumtegra.xuimobile.management.ManagementHomeViewModel
import com.velumtegra.xuimobile.management.ManagementInspectionStatusPort
import com.velumtegra.xuimobile.management.ManagementLocalReviewPort
import com.velumtegra.xuimobile.management.ManagementVersionReadPort
import com.velumtegra.xuimobile.management.UnfinishedManagementInspection
import com.velumtegra.xuimobile.management.VisibleManagementInspectionsPort
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Android/Compose with memory-only ports. No SSH, credentials, repository writes or real VPS. */
@RunWith(AndroidJUnit4::class)
class Phase15_10SManagementHomeAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val launches = AtomicInteger()
    private val versions = AtomicInteger()
    private val statusReads = AtomicInteger()
    private val accessReads = AtomicInteger()
    private val access = LocalSshAccessSummary(
        "ssh-1", "fixture.invalid", 22, "operator", "Пароль",
        "SHA256:fixture", "fixture-reference-digest",
    )
    private val review = AtomicReference<LocalManagementReview>(LocalManagementReview.Ready(
        "Fixture VPS", "server-1", "install-1", "ADOPTED", "x-ui.service",
        2053, "/panel/", 1, listOf("ssh-1"),
    ))
    private val observedAt = Instant.parse("2026-10-14T10:00:00Z")
    private val local = ManagementLocalReviewPort { server, installation ->
        assertEquals("server-1", server)
        assertEquals("install-1", installation)
        review.get()
    }
    private val readiness = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String): LocalSshAccessList =
            throw AssertionError("Management home must use exact approved access IDs")
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
            assertEquals("server-1", serverId)
            assertEquals("ssh-1", accessId)
            accessReads.incrementAndGet()
            return LocalSshReadinessResult.MetadataPresent(access)
        }
    }
    private fun completed(service: ManagementServiceState = ManagementServiceState.ACTIVE) =
        InspectionStatus("Получено с VPS", true, true, service,
            "Установка подтверждена", "Совпадает", observedAt)

    private val statuses = object : ManagementInspectionStatusPort {
        override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
            installationId: String, serverAccessId: String): InspectionStatus {
            assertEquals("server-1", serverId)
            assertEquals("install-1", installationId)
            assertEquals("ssh-1", serverAccessId)
            statusReads.incrementAndGet()
            return completed()
        }
        override suspend fun unfinishedExact(serverId: String, installationId: String) =
            emptyList<UnfinishedManagementInspection>()
    }
    private val launcher = object : VisibleManagementInspectionsPort {
        override suspend fun start(kind: InspectionKind, serverId: String, installationId: String,
            serverAccessId: String): InspectionStart {
            assertEquals("server-1", serverId)
            assertEquals("install-1", installationId)
            assertEquals("ssh-1", serverAccessId)
            launches.incrementAndGet()
            return InspectionStart.Accepted("fixture-operation")
        }
        override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
            installationId: String, serverAccessId: String) =
            statuses.status(kind, operationId, serverId, installationId, serverAccessId)
    }
    private val version = ManagementVersionReadPort { server, installation, chosen ->
        assertEquals("server-1", server)
        assertEquals("install-1", installation)
        assertEquals(access, chosen)
        versions.incrementAndGet()
        XuiVersionVerificationResult.Observed("3.10.0")
    }

    private fun show(
        saved: SavedStateHandle = SavedStateHandle(),
        reader: ManagementInspectionStatusPort = statuses,
    ) {
        val model = ManagementHomeViewModel(saved, "server-1", "install-1", local, readiness, reader, version)
        compose.setContent {
            VelumTegraTheme {
                ManagementHomeScreen(model, launcher, {}, {}, {}, {})
            }
        }
        await("management_home_server")
    }

    private fun await(tag: String) {
        compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    }

    private fun chooseAccess() {
        compose.onNodeWithTag("management_home_access_ssh-1").performScrollTo().performClick()
    }

    @Test fun openingAndCancellingNeverLaunchNetwork() {
        show()
        compose.onNodeWithTag("management_home_service").assertTextEquals("Ещё не проверена")
        compose.onNodeWithTag("management_home_quick").assertIsNotEnabled()
        chooseAccess()
        compose.onNodeWithTag("management_home_quick").assertIsEnabled().performScrollTo().performClick()
        assertEquals(0, launches.get())
        assertEquals(0, versions.get())
        compose.onNodeWithTag("management_home_cancel").performClick()
        assertEquals(0, launches.get())
    }

    @Test fun oneConfirmationLaunchesExactCheckAndShowsItsObservedState() {
        show()
        chooseAccess()
        compose.onNodeWithTag("management_home_quick").performScrollTo().performClick()
        compose.onNodeWithTag("management_home_confirm").performClick()
        compose.waitUntil(10_000) { statusReads.get() > 0 }
        compose.waitForIdle()
        compose.onNodeWithTag("management_home_service").assertTextEquals("Работает")
        assertEquals(1, launches.get())
        assertEquals(0, versions.get())
    }

    @Test fun changedLocalTargetAfterReviewBlocksLaunch() {
        show()
        chooseAccess()
        compose.onNodeWithTag("management_home_quick").performScrollTo().performClick()
        review.set((review.get() as LocalManagementReview.Ready).copy(panelPort = 2087))
        compose.onNodeWithTag("management_home_confirm").performClick()
        await("management_home_notice")
        assertEquals(0, launches.get())
        assertEquals(0, versions.get())
    }

    @Test fun versionHasIndependentConsentAndDoesNotLaunchInspection() {
        show()
        chooseAccess()
        compose.onNodeWithTag("management_home_version").performScrollTo().performClick()
        assertEquals(0, versions.get())
        compose.onNodeWithTag("management_home_confirm").performClick()
        compose.waitUntil(10_000) { versions.get() == 1 }
        compose.waitForIdle()
        compose.onNodeWithTag("management_home_version_value").assertTextEquals("3.10.0")
        assertEquals(0, launches.get())
    }

    @Test fun savedExactOperationReadsJournalWithoutRelaunch() {
        show(savedPointer("existing-operation"))
        compose.waitUntil(10_000) { statusReads.get() > 0 }
        compose.waitForIdle()
        compose.onNodeWithTag("management_home_service").assertTextEquals("Работает")
        assertEquals(0, launches.get())
        assertEquals(0, versions.get())
    }

    @Test fun foreignSavedOperationIsNeverObserved() {
        show(savedPointer("foreign-operation", server = "other-server"))
        compose.waitForIdle()
        assertEquals(0, statusReads.get())
        assertEquals(0, launches.get())
        compose.onNodeWithTag("management_home_service").assertTextEquals("Ещё не проверена")
    }

    @Test fun foregroundReturnRevokesPendingConsentAndSelection() {
        show()
        chooseAccess()
        compose.onNodeWithTag("management_home_quick").performScrollTo().performClick()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        await("management_home_server")
        compose.onNodeWithTag("management_home_confirm").assertDoesNotExist()
        compose.onNodeWithTag("management_home_quick").assertIsNotEnabled()
        assertEquals(0, launches.get())
        assertEquals(0, versions.get())
    }

    @Test fun foreignLocalInstallationNeverAdvertisesAnAccess() {
        review.set((review.get() as LocalManagementReview.Ready).copy(serverId = "other-server"))
        val model = ManagementHomeViewModel(
            SavedStateHandle(), "server-1", "install-1", local, readiness, statuses, version,
        )
        compose.setContent { ManagementHomeScreen(model, launcher, {}, {}, {}, {}) }
        await("management_home_unavailable")
        assertEquals(0, accessReads.get())
        assertEquals(0, launches.get())
        compose.onNodeWithTag("management_home_access_ssh-1").assertDoesNotExist()
    }

    @Test fun latePriorOperationCannotReplaceNewlySelectedResult() {
        val delayed = CompletableDeferred<InspectionStatus>()
        val began = AtomicInteger()
        val reader = object : ManagementInspectionStatusPort {
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus {
                if (operationId == "old-operation") {
                    began.incrementAndGet()
                    return withContext(NonCancellable) { delayed.await() }
                }
                assertEquals("new-operation", operationId)
                return completed(ManagementServiceState.INACTIVE)
            }
            override suspend fun unfinishedExact(serverId: String, installationId: String) =
                listOf(UnfinishedManagementInspection(
                    "new-operation", InspectionKind.QUICK_INSPECT, "server-1", "install-1", "ssh-1", observedAt,
                ))
        }
        show(savedPointer("old-operation"), reader)
        compose.waitUntil(10_000) { began.get() == 1 }
        compose.onNodeWithTag("management_home_observe_new-operation").performScrollTo().performClick()
        await("management_home_result")
        compose.waitForIdle()
        compose.onNodeWithTag("management_home_service").assertTextEquals("Остановлена")
        delayed.complete(completed(ManagementServiceState.ACTIVE))
        compose.waitForIdle()
        compose.onNodeWithTag("management_home_service").assertTextEquals("Остановлена")
        assertEquals(0, launches.get())
    }

    private fun savedPointer(operation: String, server: String = "server-1") = SavedStateHandle(mapOf(
        "operation_server" to server, "operation_installation" to "install-1",
        "operation_id" to operation, "operation_access" to "ssh-1",
        "operation_kind" to InspectionKind.QUICK_INSPECT.name,
    ))
}
