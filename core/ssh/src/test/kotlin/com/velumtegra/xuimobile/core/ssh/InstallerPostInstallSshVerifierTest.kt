package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerPostInstallSshVerifierTest {
    private val now = Instant.parse("2026-09-12T07:00:00Z")
    private val scope = InstallerWorkerScope(
        operationId = OperationId("install-post-verify"),
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
        managedInstallId = ManagedInstallId("v1-0123456789abcdef0123456789abcdef"),
    )

    @Test
    fun fixedReadOnlyCompilerContainsNoInstallerReplaySurface() {
        val worker = requireNotNull(InstallerPostInstallReadOnlyCompiler.workerEvidence(scope)).rawForTransport()
        val marker = InstallerPostInstallReadOnlyCompiler.managedMarker().rawForTransport()
        val facts = requireNotNull(InstallerPostInstallReadOnlyCompiler.installationFacts(scope)).rawForTransport()

        assertTrue(worker.contains("/var/lib/velum-tegra/installer/v1/${scope.managedInstallId.value}"))
        assertTrue(marker.contains(ManagedInstallMarkerProtocol.MARKER_PATH))
        assertFalse(facts.contains(ManagedInstallMarkerProtocol.MARKER_PATH))
        assertTrue(facts.contains(InstallerPostInstallPolicy.BINARY_PATH))
        assertTrue(facts.contains("setting -show true"))
        assertTrue(facts.contains("systemctl is-active"))
        assertTrue(facts.contains("ss -H -ltn"))
        assertFalse(worker.contains("install.sh"))
        assertFalse(marker.contains("install.sh"))
        assertFalse(facts.contains("curl"))
        assertFalse(facts.contains("nohup"))
    }

    @Test
    fun terminalSuccessAndExactFactsBecomeVerifiedNormalizedEvidence() = runBlocking {
        val marker = ManagedInstallMarkerProtocol.encode(scope.managedInstallId).trim()
        val handle = exactHandle(
            listOf(
                success("PROCESS=DEAD\nHEARTBEAT=${now.minusSeconds(3).epochSecond}\nTERMINAL=SUCCESS\n"),
                success("$marker\n"),
                success(
                    "SERVICE_PRESENT=1\n" +
                        "BINARY_PRESENT=1\n" +
                        "ROOT_PRESENT=1\n" +
                        "DATABASE_PRESENT=1\n" +
                        "SERVICE_STATE=active\n" +
                        "PORT=23456\n" +
                        "WEB_BASE_PATH=/panel/\n" +
                        "LISTEN_ADDRESS=\n" +
                        "LISTENER_PRESENT=1\n",
                ),
            ),
        )

        val result = InstallerPostInstallSshVerifier(now = { now }).verify(scope, handle)
        val verified = result as InstallerPostInstallRemoteVerificationResult.Verified
        assertEquals(3, handle.executions)
        assertEquals(ManagedInstallMarkerReadbackState.MATCH, verified.facts.markerReadback)
        assertEquals(ManagementServiceState.ACTIVE, verified.facts.serviceState)
        assertEquals(23456, verified.facts.panelPort)
        assertEquals("/panel/", verified.facts.webBasePath)
        assertTrue(verified.facts.listenerPresent)
    }

    @Test
    fun multilineManagedMarkerIsMalformedAndCannotBeHiddenByFirstLineReadback() = runBlocking {
        val exact = ManagedInstallMarkerProtocol.encode(scope.managedInstallId).trim()
        val handle = exactHandle(
            listOf(
                success("PROCESS=DEAD\nHEARTBEAT=${now.minusSeconds(3).epochSecond}\nTERMINAL=SUCCESS\n"),
                success("$exact\nUNEXPECTED=second-line\n"),
                success(
                    "SERVICE_PRESENT=1\nBINARY_PRESENT=1\nROOT_PRESENT=1\nDATABASE_PRESENT=1\n" +
                        "SERVICE_STATE=active\nPORT=23456\nWEB_BASE_PATH=/panel/\n" +
                        "LISTEN_ADDRESS=\nLISTENER_PRESENT=1\n",
                ),
            ),
        )

        val result = InstallerPostInstallSshVerifier(now = { now }).verify(scope, handle)
        val verified = result as InstallerPostInstallRemoteVerificationResult.Verified
        assertEquals(3, handle.executions)
        assertEquals(ManagedInstallMarkerReadbackState.MALFORMED, verified.facts.markerReadback)
    }

    @Test
    fun exactSessionMismatchExecutesZeroReadbackCommands() = runBlocking {
        val handle = FakeHandle(
            SessionBinding(
                SessionId("wrong"),
                ServerAccessId("other-access"),
                SessionOwner.Operation(scope.operationId),
            ),
            emptyList(),
        )
        val result = InstallerPostInstallSshVerifier(now = { now }).verify(scope, handle)
        assertEquals(
            InstallerPostInstallRemoteFailure.ExactSessionBindingMismatch,
            (result as InstallerPostInstallRemoteVerificationResult.Rejected).failure,
        )
        assertEquals(0, handle.executions)
    }

    @Test
    fun markerMismatchRemainsNormalizedMismatchForDomainFailClosedDecision() = runBlocking {
        val other = "VELUM_TEGRA_MANAGED_INSTALL_V1=v1-ffffffffffffffffffffffffffffffff"
        val handle = exactHandle(
            listOf(
                success("PROCESS=DEAD\nHEARTBEAT=${now.minusSeconds(3).epochSecond}\nTERMINAL=SUCCESS\n"),
                success("$other\n"),
                success(
                    "SERVICE_PRESENT=1\nBINARY_PRESENT=1\nROOT_PRESENT=1\nDATABASE_PRESENT=1\n" +
                        "SERVICE_STATE=active\nPORT=23456\nWEB_BASE_PATH=/panel/\n" +
                        "LISTEN_ADDRESS=\nLISTENER_PRESENT=1\n",
                ),
            ),
        )
        val result = InstallerPostInstallSshVerifier(now = { now }).verify(scope, handle)
        val verified = result as InstallerPostInstallRemoteVerificationResult.Verified
        assertEquals(ManagedInstallMarkerReadbackState.MISMATCH, verified.facts.markerReadback)
    }

    private fun exactHandle(results: List<SshCommandResult>): FakeHandle = FakeHandle(
        SessionBinding(SessionId("session"), scope.serverAccessId, SessionOwner.Operation(scope.operationId)),
        results,
    )

    private fun success(stdout: String): SshCommandResult = SshCommandResult(
        dispatchState = CommandDispatchState.DISPATCHED,
        completion = CommandCompletion.ConfirmedSuccess,
        stdout = CapturedOutput.of(stdout.toByteArray(), truncated = false),
        stderr = CapturedOutput.EMPTY,
    )

    private class FakeHandle(
        override val binding: SessionBinding,
        private val results: List<SshCommandResult>,
    ) : SshSessionHandle {
        private var closed = false
        var executions: Int = 0
            private set

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            val result = results.getOrNull(executions) ?: error("Unexpected SSH execution #${executions + 1}")
            executions += 1
            return result
        }

        override fun close() {
            closed = true
        }
    }
}
