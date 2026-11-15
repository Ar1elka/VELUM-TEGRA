package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
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

/** Memory-only native UI fixtures. No GitHub download, SSH, VPS, SecretStore or primary database. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_2UpdatePackageAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val time = Instant.parse("2026-10-16T20:00:00Z")
    private val clock = AtomicReference(time.plusSeconds(5))
    private val local = AtomicReference<LocalManagementReview>(LocalManagementReview.Ready(
        "Fixture VPS", "server", "install", "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("ssh")))
    private val profile = AtomicReference(LocalSshAccessSummary("ssh", "fixture.invalid", 22, "operator", "Пароль", "SHA256:fixture", "ref-digest"))
    private val report = AtomicReference<UpdatePreflightSnapshot?>(UpdatePreflightSnapshot(
        ManagementScope(OperationId("prepared"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("install")),
        UpdateRootStatus.DIRECT_ROOT, UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD,
        DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0", ManagementServiceState.ACTIVE,
        ManagementBaselineStatus.Matched, time, UpdateServerArchitecture.AMD64))
    private val requests = ConcurrentLinkedQueue<UpdatePackageRequest>()
    private val discarded = ConcurrentLinkedQueue<UpdatePackageReceipt>()
    private val preflightStarts = AtomicInteger()
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
        assertEquals("server", server); assertEquals("install", install)
        assertEquals(UpdatePreflightPointer("prepared", "ssh"), pointer)
        UpdatePreflightStatus("Проверка завершена", true, report.get())
    }
    private val actions = UpdatePreflightActionPort { _, _, _ ->
        preflightStarts.incrementAndGet(); UpdatePreflightStart.Blocked("No fixture SSH action allowed")
    }
    private var download: suspend (UpdatePackageRequest) -> UpdatePackagePreparationResult = { verified(it) }
    private val packages = object : UpdatePackagePreparationPort {
        override suspend fun prepare(request: UpdatePackageRequest): UpdatePackagePreparationResult {
            requests += request; return download(request)
        }
        override fun discard(receipt: UpdatePackageReceipt) { discarded += receipt }
    }

    @Test fun openingRestoredReportDoesNotDownloadOrClaimACompletedBackup() {
        show(); await("update_package_section")
        compose.onNodeWithTag("update_package_architecture").assertTextContains("x86_64 / amd64", substring = true)
        compose.onNodeWithText("Резервная копия и восстановление ещё не подтверждены.").assertExists()
        absent("update_package_verified"); assertTrue(requests.isEmpty()); assertEquals(0, preflightStarts.get())
    }
    @Test fun packageReviewShowsExactTargetVersionAndArchitectureBeforeDownload() {
        show(); request()
        compose.onNodeWithTag("update_package_review_server").assertTextContains("Fixture VPS", substring = true)
        compose.onNodeWithText("3x-ui: 3.10.0 → 3.10.2").assertExists()
        compose.onNodeWithText("Архитектура: x86_64 / amd64").assertExists()
        assertTrue(requests.isEmpty())
    }
    @Test fun dismissingPackageReviewDoesNotDownload() {
        show(); request(); compose.onNodeWithTag("update_package_cancel_review").performClick()
        assertTrue(requests.isEmpty()); absent("update_package_verified")
    }
    @Test fun confirmedDownloadUsesExactReportAndShowsOnlyPackageVerification() {
        show(); request(); confirm(); await("update_package_verified")
        assertEquals(1, requests.size)
        assertEquals(report.get(), requests.single().report)
        assertEquals(ReviewedXuiUpdatePackage.V3_10_2_AMD64, requests.single().release)
        compose.onNodeWithTag("update_package_verified").assertTextContains("Пакет v3.10.2 проверен на устройстве", substring = true)
        assertEquals(0, preflightStarts.get())
    }
    @Test fun duplicateConfirmationCannotCreateAnotherDownload() {
        val model = show(); request()
        compose.runOnIdle { model.confirmPackage(); model.confirmPackage() }
        await("update_package_verified"); assertEquals(1, requests.size)
    }
    @Test fun unknownServerArchitectureCannotDefaultToAndroidArchitecture() {
        report.set(requireNotNull(report.get()).copy(architecture = null))
        show(); await("update_package_blocked"); absent("update_package_request"); assertTrue(requests.isEmpty())
    }
    @Test fun sameOrNewerVersionHasNoMisleadingUpgradeButton() {
        report.set(requireNotNull(report.get()).copy(currentVersion = "3.10.3"))
        show(); await("update_package_blocked"); absent("update_package_request"); assertTrue(requests.isEmpty())
    }
    @Test fun failedPreflightPreventsPackageSelection() {
        report.set(requireNotNull(report.get()).copy(root = UpdateRootStatus.NOT_ROOT))
        show(); await("update_package_blocked"); absent("update_package_request"); assertTrue(requests.isEmpty())
    }
    @Test fun expiredReportRequiresANewExplicitPreflight() {
        report.set(requireNotNull(report.get()).copy(observedAt = time.minusSeconds(601)))
        show(); await("update_package_blocked"); absent("update_package_request"); assertEquals(0, preflightStarts.get())
    }
    @Test fun integrityFailureIsVisibleAndDoesNotAutomaticallyRetry() {
        download = { UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.INTEGRITY) }
        show(); request(); confirm(); await("update_package_notice")
        compose.onNodeWithTag("update_package_notice").assertTextContains("Контрольная сумма", substring = true)
        absent("update_package_verified"); assertEquals(1, requests.size)
    }
    @Test fun sshProfileChangedAfterReviewBlocksBeforeDownload() {
        show(); request(); profile.set(profile.get().copy(host = "changed.invalid"))
        confirm(); await("update_preparation_unavailable"); assertTrue(requests.isEmpty())
    }
    @Test fun profileChangedDuringDownloadDiscardsTheLateReceipt() {
        val pending = delayedDownload(); show(); request(); confirm(); started()
        compose.runOnIdle {
            profile.set(profile.get().copy(username = "changed")); pending.complete(verified(requests.single()))
        }
        await("update_preparation_unavailable"); absent("update_package_verified"); assertEquals(1, discarded.size)
    }
    @Test fun installationChangedDuringDownloadCannotReceiveTheOldPackageReceipt() {
        val pending = delayedDownload(); show(); request(); confirm(); started()
        compose.runOnIdle {
            local.set((local.get() as LocalManagementReview.Ready).copy(panelPort = 2054))
            pending.complete(verified(requests.single()))
        }
        await("update_preparation_unavailable"); absent("update_package_verified"); assertEquals(1, discarded.size)
    }
    @Test fun lostExactJournalFactsCannotBeReplacedWithAPackageSuccess() {
        val pending = delayedDownload(); show(); request(); confirm(); started()
        compose.runOnIdle { val result = verified(requests.single()); report.set(null); pending.complete(result) }
        await("update_preparation_unavailable"); absent("update_package_verified"); assertEquals(1, discarded.size)
    }
    @Test fun anotherTargetsReceiptIsRejectedEvenByAMisbehavingPort() {
        download = { request ->
            val correct = receipt(request)
            UpdatePackagePreparationResult.Verified(correct.copy(scope = correct.scope.copy(serverAccessId = ServerAccessId("foreign"))))
        }
        show(); request(); confirm(); await("update_package_notice")
        absent("update_package_verified"); assertEquals(1, discarded.size)
    }
    @Test fun lateReceiptAfterLeavingForegroundIsNotProjectedOrReplayed() {
        val pending = delayedDownload(); val model = show(); request(); confirm(); started()
        compose.runOnIdle { model.leaveForeground(); pending.complete(verified(requests.single())) }
        compose.waitForIdle(); absent("update_package_verified")
        compose.runOnIdle { model.enterForeground() }
        await("update_package_section"); absent("update_package_verified"); assertEquals(1, requests.size)
    }
    @Test fun freshViewModelRestoresOnlyThePreflightPointer() {
        val saved = saved(); val model = show(saved); request(); confirm(); await("update_package_verified")
        lateinit var restored: ManagementUpdatePreparationViewModel
        compose.runOnIdle {
            model.leaveForeground()
            restored = ManagementUpdatePreparationViewModel(saved, "server", "install", "ssh", localPort, statuses, readiness, packages) { clock.get() }
            restored.enterForeground()
        }
        compose.waitUntil(10_000) { restored.state.value.result != null }
        assertNull(restored.state.value.packageReceipt); assertEquals(1, requests.size)
        compose.runOnIdle { restored.leaveForeground() }
    }
    @Test fun cancellingDownloadNeverResumesWithoutAnotherConfirmation() {
        val pending = delayedDownload(); val model = show(); request(); confirm(); started()
        compose.runOnIdle { model.cancelPackage(); pending.complete(verified(requests.single())) }
        await("update_package_notice"); absent("update_package_verified"); assertEquals(1, requests.size)
        download = { verified(it) }
        request(); confirm(); await("update_package_verified"); assertEquals(2, requests.size)
    }
    @Test fun reportExpiringDuringDownloadCannotKeepAVerifiedReceipt() {
        val pending = delayedDownload(); show(); request(); confirm(); started()
        compose.runOnIdle { clock.set(time.plusSeconds(700)); pending.complete(verified(requests.single())) }
        await("update_package_notice"); absent("update_package_verified"); assertEquals(1, discarded.size)
    }
    @Test fun arm64ServerSelectsOnlyTheReviewedArm64Package() {
        report.set(requireNotNull(report.get()).copy(architecture = UpdateServerArchitecture.ARM64))
        show(); request(); confirm(); await("update_package_verified")
        assertEquals(ReviewedXuiUpdatePackage.V3_10_2_ARM64, requests.single().release)
        compose.onNodeWithTag("update_package_architecture").assertTextContains("aarch64 / arm64", substring = true)
    }

    private fun show(handle: SavedStateHandle = saved()): ManagementUpdatePreparationViewModel {
        val model = ManagementUpdatePreparationViewModel(handle, "server", "install", "ssh", localPort, statuses, readiness, packages) { clock.get() }
        compose.setContent { VelumTegraTheme { ManagementUpdatePreparationScreen(model, actions, {}) } }
        await("update_package_section")
        return model
    }
    private fun saved() = SavedStateHandle(mapOf("update_preflight_server" to "server", "update_preflight_installation" to "install",
        "update_preflight_access" to "ssh", "update_preflight_operation" to "prepared"))
    private fun request() { compose.onNodeWithTag("update_package_request").performScrollTo().performClick(); await("update_package_confirm") }
    private fun confirm() = compose.onNodeWithTag("update_package_confirm").performClick()
    private fun started() { compose.waitUntil(10_000) { requests.size == 1 } }
    private fun await(tag: String) { compose.waitUntil(10_000) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() } }
    private fun absent(tag: String) = assertEquals(0, compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun receipt(request: UpdatePackageRequest) = UpdatePackageReceipt(request.report.scope, request.report.observedAt,
        request.release, request.release.sha256, 100, clock.get(), "a".repeat(32))
    private fun verified(request: UpdatePackageRequest) = UpdatePackagePreparationResult.Verified(receipt(request))
    private fun delayedDownload(): CompletableDeferred<UpdatePackagePreparationResult> {
        val pending = CompletableDeferred<UpdatePackagePreparationResult>()
        download = { withContext(NonCancellable) { pending.await() } }
        return pending
    }
}
