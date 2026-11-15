package com.velumtegra.xuimobile.management

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.Assert.*
import org.junit.Test

/** Drive actual ViewModels: successful nullable action results must not become missing-record errors. */
@OptIn(ExperimentalCoroutinesApi::class)
class RecoveryViewModelSubmissionTest {
    private enum class Kind { COMPARISON, RESTORE, START, TRIAL }
    private data class State(val operation: String?, val notice: String?, val dialog: String?)
    private class Calls { var starts = 0; var checks = 0; var reply: String? = null; var block = false }
    private data class Harness(val enter: () -> Unit, val leave: () -> Unit, val request: () -> Unit,
        val requestCheck: () -> Unit, val confirm: () -> Unit, val state: () -> State)

    private fun harness(kind: Kind, calls: Calls): Harness {
        val f = RecoveryRegressionFixture
        return when (kind) {
            Kind.TRIAL -> {
                val sourceReview = RestoreCheckSourceReview("backup", f.checkBinding.source, f.at)
                val statuses = object : RestoreCheckStatusPort {
                    override suspend fun source(server: String, installation: String, access: String, source: String) = sourceReview
                    override suspend fun read(server: String, installation: String, access: String, operation: String) =
                        RestoreCheckObservation(operation, "backup", "fixture", false, mayRestore = true, sourceProof = f.checkBinding)
                    override suspend fun unfinished(server: String, installation: String, access: String, source: String) = emptyList<String>()
                }
                val actions = object : RestoreCheckActionPort {
                    override suspend fun inspectConfirmed(review: ManagementRestartReview, source: String): RestoreCheckStart {
                        calls.starts++
                        return if (calls.block) RestoreCheckStart.Blocked("fixture blocked") else RestoreCheckStart.Recorded("created")
                    }
                    override suspend fun restoreConfirmed(review: ManagementRestartReview, operation: String,
                        reviewedSource: com.velumtegra.xuimobile.core.model.RestoreCheckBinding): String? {
                        calls.checks++; assertEquals("created", operation); assertEquals(f.checkBinding, reviewedSource)
                        return calls.reply
                    }
                    override suspend fun inspectCurrentConfirmed(review: ManagementRestartReview, operation: String): String? = error("inspect current")
                    override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? = error("check")
                    override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? = error("cancel")
                }
                val vm = ManagementRestoreCheckViewModel(SavedStateHandle(), "server", "install", "ssh", "backup", f.local, statuses)
                Harness(vm::enterForeground, vm::leaveForeground, vm::requestInspect, vm::requestRestore, { vm.confirm(actions) },
                    { State(vm.state.value.operationId, vm.state.value.notice, vm.state.value.dialog) })
            }
            Kind.COMPARISON -> {
                val sourceReview = RestoreCompatibilitySourceReview("check", 1, f.checkBinding, f.at)
                val statuses = object : RestoreCompatibilityStatusPort {
                    override suspend fun source(server: String, installation: String, access: String, source: String) = sourceReview
                    override suspend fun read(server: String, installation: String, access: String, operation: String) =
                        RestoreCompatibilityObservation(operation, "check", "fixture", false, mayRetry = true)
                    override suspend fun unfinished(server: String, installation: String, access: String, source: String) = emptyList<String>()
                }
                val actions = object : RestoreCompatibilityActionPort {
                    override suspend fun startConfirmed(review: ManagementRestartReview, source: RestoreCompatibilitySourceReview): RestoreCompatibilityStart {
                        calls.starts++
                        return if (calls.block) RestoreCompatibilityStart.Blocked("fixture blocked") else RestoreCompatibilityStart.Recorded("created")
                    }
                    override suspend fun retryConfirmed(review: ManagementRestartReview, source: RestoreCompatibilitySourceReview, operation: String): String? {
                        calls.checks++; assertEquals("created", operation); return calls.reply
                    }
                    override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? = error("cancel")
                }
                val vm = ManagementRestoreCompatibilityViewModel(SavedStateHandle(), "server", "install", "ssh", sourceReview.operationId, f.local, statuses)
                Harness(vm::enterForeground, vm::leaveForeground, vm::requestRead, vm::requestRetry, { vm.confirm(actions) },
                    { State(vm.state.value.operationId, vm.state.value.notice, vm.state.value.dialog) })
            }
            Kind.RESTORE -> {
                val sourceReview = WorkingDatabaseRestoreSourceReview("comparison", 1, f.comparisonBinding, f.report, true)
                val statuses = object : WorkingDatabaseRestoreStatusPort {
                    override suspend fun source(server: String, installation: String, access: String, source: String) = sourceReview
                    override suspend fun read(server: String, installation: String, access: String, operation: String) =
                        WorkingDatabaseRestoreObservation(operation, "comparison", "fixture", false, mayCheck = true)
                    override suspend fun unfinished(server: String, installation: String, access: String, source: String) = emptyList<String>()
                }
                val actions = object : WorkingDatabaseRestoreActionPort {
                    override suspend fun startConfirmed(review: ManagementRestartReview, source: WorkingDatabaseRestoreSourceReview): WorkingDatabaseRestoreStart {
                        calls.starts++
                        return if (calls.block) WorkingDatabaseRestoreStart.Blocked("fixture blocked") else WorkingDatabaseRestoreStart.Recorded("created")
                    }
                    override suspend fun checkConfirmed(review: ManagementRestartReview, source: WorkingDatabaseRestoreSourceReview, operation: String): String? {
                        calls.checks++; assertEquals("created", operation); return calls.reply
                    }
                    override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? = error("cancel")
                }
                val vm = ManagementWorkingDatabaseRestoreViewModel(SavedStateHandle(), "server", "install", "ssh", "comparison", f.local, statuses)
                Harness(vm::enterForeground, vm::leaveForeground, vm::requestRestore, vm::requestCheck, { vm.confirm(actions) },
                    { State(vm.state.value.operationId, vm.state.value.notice, vm.state.value.dialog) })
            }
            Kind.START -> {
                val sourceReview = RestoredPanelStartSourceReview("restore", 1, f.restoreBinding, true)
                val statuses = object : RestoredPanelStartStatusPort {
                    override suspend fun source(server: String, installation: String, access: String, source: String) = sourceReview
                    override suspend fun read(server: String, installation: String, access: String, operation: String) =
                        RestoredPanelStartObservation(operation, "restore", "fixture", false, mayCheck = true)
                    override suspend fun unfinished(server: String, installation: String, access: String, source: String) = emptyList<String>()
                }
                val actions = object : RestoredPanelStartActionPort {
                    override suspend fun startConfirmed(review: ManagementRestartReview, source: RestoredPanelStartSourceReview): RestoredPanelStartRequest {
                        calls.starts++
                        return if (calls.block) RestoredPanelStartRequest.Blocked("fixture blocked") else RestoredPanelStartRequest.Recorded("created")
                    }
                    override suspend fun checkConfirmed(review: ManagementRestartReview, source: RestoredPanelStartSourceReview, operation: String): String? {
                        calls.checks++; assertEquals("created", operation); return calls.reply
                    }
                    override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? = error("cancel")
                }
                val vm = ManagementRestoredPanelStartViewModel(SavedStateHandle(), "server", "install", "ssh", "restore", f.local, statuses)
                Harness(vm::enterForeground, vm::leaveForeground, vm::requestStart, vm::requestCheck, { vm.confirm(actions) },
                    { State(vm.state.value.operationId, vm.state.value.notice, vm.state.value.dialog) })
            }
        }
    }

    @Test fun recordedSubmissionAndSuccessfulCheckRetainTheExactIdWithoutFalseError() = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        try {
            for (kind in Kind.values()) {
                val calls = Calls(); val h = harness(kind, calls)
                h.enter(); runCurrent(); h.request(); assertNotNull(kind.name, h.state().dialog)
                h.confirm(); runCurrent()
                assertEquals(kind.name, "created", h.state().operation)
                assertNull(kind.name, h.state().notice)
                h.requestCheck(); assertNotNull(kind.name, h.state().dialog)
                h.confirm(); runCurrent()
                assertNull(kind.name, h.state().notice)
                assertEquals(1, calls.starts); assertEquals(1, calls.checks)
                assertEquals("created", h.state().operation)
                h.leave()
            }
        } finally { Dispatchers.resetMain() }
    }

    @Test fun actualActionRefusalRemainsVisible() = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        try {
            for (kind in Kind.values()) {
                val calls = Calls().also { it.block = true }; val h = harness(kind, calls)
                h.enter(); runCurrent(); h.request(); h.confirm(); runCurrent()
                assertEquals(kind.name, "fixture blocked", h.state().notice)
                assertNull(h.state().operation); assertEquals(1, calls.starts)
                h.leave()
            }
        } finally { Dispatchers.resetMain() }
    }

    @Test fun leavingForegroundRevokesAnUnsubmittedConfirmation() = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        try {
            for (kind in Kind.values()) {
                val calls = Calls(); val h = harness(kind, calls)
                h.enter(); runCurrent(); h.request(); h.leave(); h.confirm(); runCurrent()
                assertEquals(kind.name, 0, calls.starts)
                assertNull(h.state().operation)
            }
        } finally { Dispatchers.resetMain() }
    }
}
