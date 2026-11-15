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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.readiness.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real Android UI with memory-only ports. No SSH, credentials, repository writes or live VPS. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T1ManagementRestartAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val at = Instant.parse("2026-10-14T10:00:00Z")
    private val starts = AtomicInteger()
    private val checks = AtomicInteger()
    private val cancels = AtomicInteger()
    private val statusReads = AtomicInteger()
    private val server = ServerId("server-1")
    private val installation = XuiInstallation(XuiInstallationId("install-1"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db",
            2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
    private val access = ServerAccess(ServerAccessId("ssh-1"), server, SshEndpoint("fixture.invalid", 22), "operator",
        SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
    private val review = AtomicReference<ManagementRestartLocalReview>(ManagementRestartLocalReview.Ready(
        ManagementRestartReview("Fixture VPS", installation, access)))
    private val observations = ConcurrentHashMap<String, ManagementRestartObservation>()
    private val unfinished = AtomicReference<List<UnfinishedManagementRestart>>(emptyList())
    private val local = ManagementRestartLocalPort { s, i, a ->
        assertEquals("server-1", s); assertEquals("install-1", i); assertEquals("ssh-1", a)
        review.get()
    }
    private fun uncertain(id: String) = ManagementRestartObservation(id, "Результат ещё не подтверждён", false,
        mayCheckReadOnly = true, observedAt = at)
    private fun succeeded(id: String) = ManagementRestartObservation(id, "Служба подтверждена новым подключением", true,
        succeeded = true, observedAt = at.plusSeconds(3))
    private val statuses = object : ManagementRestartStatusPort {
        override suspend fun readExact(operationId: String, serverId: String, installationId: String, accessId: String): ManagementRestartObservation? {
            assertEquals("server-1", serverId); assertEquals("install-1", installationId); assertEquals("ssh-1", accessId)
            statusReads.incrementAndGet()
            return observations[operationId]
        }
        override suspend fun unfinishedExact(serverId: String, installationId: String, accessId: String) = unfinished.get()
    }
    private val actions = object : ManagementRestartActionPort {
        override suspend fun startConfirmed(reviewed: ManagementRestartReview): ManagementRestartStart {
            assertEquals((review.get() as ManagementRestartLocalReview.Ready).review, reviewed)
            starts.incrementAndGet()
            observations["fixture-operation"] = uncertain("fixture-operation")
            unfinished.set(listOf(UnfinishedManagementRestart("fixture-operation", at)))
            return ManagementRestartStart.Recorded("fixture-operation")
        }
        override suspend fun checkResultConfirmed(operationId: String, reviewed: ManagementRestartReview): String? {
            assertEquals("fixture-operation", operationId)
            assertEquals((review.get() as ManagementRestartLocalReview.Ready).review, reviewed)
            checks.incrementAndGet(); observations[operationId] = succeeded(operationId); unfinished.set(emptyList())
            return null
        }
        override suspend fun cancelBeforeDispatch(operationId: String, reviewed: ManagementRestartReview): String? {
            assertEquals("fixture-operation", operationId)
            cancels.incrementAndGet(); observations[operationId] = ManagementRestartObservation(operationId, "Запрос отменён до отправки", true)
            unfinished.set(emptyList()); return null
        }
    }
    private fun saved(id: String, savedServer: String = "server-1", savedAccess: String = "ssh-1") = SavedStateHandle(mapOf(
        "restart_server" to savedServer, "restart_installation" to "install-1", "restart_access" to savedAccess, "restart_operation" to id))
    private fun show(savedState: SavedStateHandle = SavedStateHandle(), reader: ManagementRestartStatusPort = statuses): ManagementRestartViewModel {
        val model = ManagementRestartViewModel(savedState, "server-1", "install-1", "ssh-1", local, reader)
        compose.setContent { VelumTegraTheme { ManagementRestartScreen(model, actions, {}) } }
        await("management_restart_server")
        return model
    }
    private fun await(tag: String) = compose.waitUntil(10_000) {
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
    }
    private fun beginReview() = compose.onNodeWithTag("management_restart_review").performScrollTo().performClick()
    private fun beginCheck() = compose.onNodeWithTag("management_restart_check_result").performScrollTo().performClick()
    private fun confirm() = compose.onNodeWithTag("management_restart_confirm").performClick()

    @Test fun openingAndCancellingReviewPerformNoAction() {
        show(); compose.onNodeWithTag("management_restart_ssh").assertTextEquals("operator@fixture.invalid:22")
        beginReview(); assertEquals(0, starts.get())
        compose.onNodeWithTag("management_restart_dismiss").performClick()
        assertEquals(0, starts.get()); assertEquals(0, checks.get()); assertEquals(0, cancels.get())
        assertEquals(0, statusReads.get())
    }

    @Test fun oneExactConfirmationStartsOnceAndDoesNotClaimSuccess() {
        val model = show(); beginReview(); confirm(); await("management_restart_result")
        compose.waitForIdle()
        compose.onNodeWithTag("management_restart_result_text").assertTextEquals("Результат ещё не подтверждён")
        compose.onNodeWithTag("management_restart_review").assertIsNotEnabled()
        compose.runOnIdle { model.confirm(actions) }
        assertEquals(1, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun resultVerificationRequiresSeparateConsentAndNeverStartsAgain() {
        show(); beginReview(); confirm(); await("management_restart_check_result")
        beginCheck(); assertEquals(1, starts.get()); assertEquals(0, checks.get())
        confirm(); compose.waitUntil(10_000) { checks.get() == 1 }; compose.waitForIdle()
        compose.onNodeWithTag("management_restart_result_text").assertTextEquals("Служба подтверждена новым подключением")
        assertEquals(1, starts.get()); assertEquals(1, checks.get())
    }

    @Test fun cancellingResultReviewCannotVerifyOrRestart() {
        observations["fixture-operation"] = uncertain("fixture-operation")
        show(saved("fixture-operation")); await("management_restart_check_result")
        beginCheck(); compose.onNodeWithTag("management_restart_dismiss").performClick()
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun metadataChangeAfterReviewBlocksStart() {
        show(); beginReview()
        review.set(ManagementRestartLocalReview.Ready(ManagementRestartReview("Fixture VPS",
            installation.copy(baseline = installation.baseline.copy(panelPort = 2443)), access)))
        confirm(); await("management_restart_notice")
        compose.onNodeWithTag("management_restart_notice").assertTextEquals("Цель изменилась после просмотра. Обновите сведения и подтвердите заново.")
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun foregroundReturnRevokesPendingReview() {
        show(); beginReview()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        await("management_restart_server")
        compose.onNodeWithTag("management_restart_confirm").assertDoesNotExist()
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun exactSavedOperationIsObservedWithoutReplay() {
        observations["fixture-operation"] = uncertain("fixture-operation")
        show(saved("fixture-operation")); await("management_restart_result")
        compose.onNodeWithTag("management_restart_result_text").assertTextEquals("Результат ещё не подтверждён")
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun foreignSavedServerNeverReadsItsJournalPointer() {
        show(saved("foreign-operation", savedServer = "other-server")); compose.waitForIdle()
        assertEquals(0, statusReads.get()); assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun foreignSavedAccessNeverReadsItsJournalPointer() {
        show(saved("foreign-operation", savedAccess = "other-access")); compose.waitForIdle()
        assertEquals(0, statusReads.get()); assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun onlyWaitingRequestOffersLocalCancellation() {
        observations["fixture-operation"] = ManagementRestartObservation("fixture-operation", "Ожидает запуска", false, mayCancelBeforeDispatch = true)
        show(saved("fixture-operation")); await("management_restart_cancel_request")
        compose.onNodeWithTag("management_restart_cancel_request").performScrollTo().performClick()
        compose.waitUntil(10_000) { cancels.get() == 1 }; compose.waitForIdle()
        compose.onNodeWithTag("management_restart_result_text").assertTextEquals("Запрос отменён до отправки")
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun unsafeOutcomeOffersReadOnlyCheckAndNoCancellation() {
        observations["fixture-operation"] = uncertain("fixture-operation")
        show(saved("fixture-operation")); await("management_restart_check_result")
        compose.onNodeWithTag("management_restart_cancel_request").assertDoesNotExist()
        compose.onNodeWithTag("management_restart_review").assertIsNotEnabled()
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun lateOldObservationCannotReplaceExplicitlySelectedOperation() {
        val delayed = CompletableDeferred<ManagementRestartObservation>()
        val began = AtomicInteger()
        val reader = object : ManagementRestartStatusPort {
            override suspend fun readExact(operationId: String, serverId: String, installationId: String, accessId: String): ManagementRestartObservation {
                if (operationId == "old-operation") { began.incrementAndGet(); return withContext(NonCancellable) { delayed.await() } }
                assertEquals("new-operation", operationId); return succeeded(operationId)
            }
            override suspend fun unfinishedExact(serverId: String, installationId: String, accessId: String) =
                listOf(UnfinishedManagementRestart("new-operation", at))
        }
        show(saved("old-operation"), reader); compose.waitUntil(10_000) { began.get() == 1 }
        compose.onNodeWithTag("management_restart_observe_new-operation").performScrollTo().performClick()
        await("management_restart_result"); compose.waitForIdle()
        delayed.complete(uncertain("old-operation")); compose.waitForIdle()
        compose.onNodeWithTag("management_restart_result_text").assertTextEquals("Служба подтверждена новым подключением")
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun foreignLocalReviewCannotOpenConfirmation() {
        review.set(ManagementRestartLocalReview.Ready(ManagementRestartReview("Other VPS",
            installation.copy(serverId = ServerId("other-server")), access)))
        val model = ManagementRestartViewModel(SavedStateHandle(), "server-1", "install-1", "ssh-1", local, statuses)
        compose.setContent { VelumTegraTheme { ManagementRestartScreen(model, actions, {}) } }
        await("management_restart_notice")
        compose.onNodeWithTag("management_restart_review").assertDoesNotExist()
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }

    @Test fun managementHomeRoutesOnlySelectedExactSshProfileToRestart() {
        val routed = AtomicReference<String?>(null)
        val summary = LocalSshAccessSummary("ssh-1", "fixture.invalid", 22, "operator", "Пароль", "SHA256:fixture", "fixture-reference-digest")
        val localHome = ManagementLocalReviewPort { s, i ->
            assertEquals("server-1", s); assertEquals("install-1", i)
            LocalManagementReview.Ready("Fixture VPS", "server-1", "install-1", "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("ssh-1"))
        }
        val readiness = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String): LocalSshAccessList = error("Exact linked profiles only")
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                assertEquals("server-1", serverId); assertEquals("ssh-1", accessId)
                return LocalSshReadinessResult.MetadataPresent(summary)
            }
        }
        val homeStatuses = object : ManagementInspectionStatusPort {
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = error("No inspection requested")
            override suspend fun unfinishedExact(serverId: String, installationId: String) = emptyList<UnfinishedManagementInspection>()
        }
        val launcher = object : VisibleManagementInspectionsPort {
            override suspend fun start(kind: InspectionKind, serverId: String, installationId: String, serverAccessId: String): InspectionStart =
                error("Routing must not start any operation")
            override suspend fun status(kind: InspectionKind, operationId: String, serverId: String,
                installationId: String, serverAccessId: String): InspectionStatus = error("No inspection requested")
        }
        val model = ManagementHomeViewModel(SavedStateHandle(), "server-1", "install-1", localHome, readiness, homeStatuses,
            ManagementVersionReadPort { _, _, _ -> error("Version must not be requested") })
        compose.setContent { VelumTegraTheme { ManagementHomeScreen(model, launcher, {}, {}, {}, {}, onRestart = { routed.set(it) }) } }
        await("management_home_server")
        compose.onNodeWithTag("management_home_restart").assertIsNotEnabled()
        compose.onNodeWithTag("management_home_access_ssh-1").performScrollTo().performClick()
        compose.onNodeWithTag("management_home_restart").performScrollTo().assertIsEnabled().performClick()
        assertEquals("ssh-1", routed.get())
        assertEquals(0, starts.get()); assertEquals(0, checks.get())
    }
}
