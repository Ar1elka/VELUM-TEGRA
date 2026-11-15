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

@OptIn(ExperimentalCoroutinesApi::class)
class RestoreCheckReadRecoveryTest {
    @Test fun successfulExactRefreshClearsOnlyTheObsoleteReadError() = runTest {
        Dispatchers.setMain(StandardTestDispatcher(testScheduler))
        try {
            for (exact in listOf(true, false)) {
                val f = RecoveryRegressionFixture
                var available = false
                val original = RestoreCheckSourceReview("backup", f.checkBinding.source, f.at)
                val status = object : RestoreCheckStatusPort {
                    override suspend fun source(server: String, installation: String, access: String, source: String) = original
                    override suspend fun read(server: String, installation: String, access: String, operation: String) =
                        if (!available) null else RestoreCheckObservation(operation, if (exact) "backup" else "foreign", "verified", true,
                            sourceProof = f.checkBinding)
                    override suspend fun unfinished(server: String, installation: String, access: String, source: String) = emptyList<String>()
                }
                val saved = SavedStateHandle(mapOf("rc_operation" to "created", "rc_server" to "server", "rc_installation" to "install",
                    "rc_access" to "ssh", "rc_source" to "backup"))
                val vm = ManagementRestoreCheckViewModel(saved, "server", "install", "ssh", "backup", f.local, status)
                vm.enterForeground(); runCurrent()
                assertEquals("Точная запись или исходная копия недоступна.", vm.state.value.notice)
                available = true
                vm.refresh(); runCurrent()
                if (exact) {
                    assertNull(vm.state.value.notice)
                    assertEquals("created", vm.state.value.observation?.operationId)
                } else {
                    assertNull(vm.state.value.observation)
                    assertEquals("Точная запись или исходная копия недоступна.", vm.state.value.notice)
                }
                vm.leaveForeground()
            }
        } finally { Dispatchers.resetMain() }
    }
}
