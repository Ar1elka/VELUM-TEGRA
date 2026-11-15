package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeSpec
import com.velumtegra.xuimobile.core.domain.DiscoveryProver
import com.velumtegra.xuimobile.core.domain.DiscoveryProofAttempt
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryObservation
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.DiscoveryPresence
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoverySshProbeExecutorTest {
    private val now = Instant.parse("2026-09-06T08:00:00Z")
    private val scope = DiscoveryScope(
        operationId = OperationId("discovery-op"),
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
    )

    @Test
    fun `compiler accepts only approved finite read-only probe vocabulary`() {
        DiscoveryProbePlan.initialProbes.forEach { probe ->
            val command = requireNotNull(DiscoveryReadOnlyCommandCompiler.compile(probe)).command.rawForTransport()
            assertTrue(command.isNotBlank())
            val lower = command.lowercase()
            listOf(
                "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable",
                "systemctl disable", "apt ", "apt-get", "curl ", "wget ", "sed -i", " tee ",
                "rm ", "mv ", "cp ", "chmod ", "chown ", "sqlite3", "install.sh",
            ).forEach { forbidden -> assertFalse("forbidden token $forbidden in $command", forbidden in lower) }
        }

        assertEquals(
            null,
            DiscoveryReadOnlyCommandCompiler.compile(
                DiscoveryProbeSpec.ServiceUnitPresence("other.service"),
            ),
        )
        assertEquals(
            null,
            DiscoveryReadOnlyCommandCompiler.compile(
                DiscoveryProbeSpec.InstallationPathPresence(DiscoveryPathKind.BINARY, "/tmp/x-ui"),
            ),
        )
        assertEquals(
            null,
            DiscoveryReadOnlyCommandCompiler.compile(
                DiscoveryProbeSpec.PlatformRelease(timeout = Duration.ofMinutes(1)),
            ),
        )
    }

    @Test
    fun `wrong exact session binding fails before any command executes`() = runBlocking {
        val handle = FakeHandle(
            binding = SessionBinding(
                sessionId = SessionId("session-a"),
                serverAccessId = ServerAccessId("wrong-access"),
                owner = SessionOwner.Operation(scope.operationId),
            ),
        ) { _, _ -> error("must not execute") }

        val result = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        assertTrue(result is DiscoverySshProbeRunResult.Failed)
        assertTrue((result as DiscoverySshProbeRunResult.Failed).failure is DiscoverySshProbeExecutionFailure.ExactSessionBindingMismatch)
        assertEquals(0, handle.executions)
    }

    @Test
    fun `approved plan normalizes canonical Ubuntu layout and reaches discovery proof`() = runBlocking {
        val handle = exactHandle { raw, _ -> canonicalLayoutResult(raw) }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        assertTrue(run is DiscoverySshProbeRunResult.Completed)
        val evidence = (run as DiscoverySshProbeRunResult.Completed).evidence
        assertEquals(DiscoveryProbePlan.initialProbes.size, handle.executions)

        val classification = DiscoveryClassifier.classify(evidence)
        assertTrue(classification is DiscoveryClassification.SupportedCandidate)
        val attempt = DiscoveryProver.prove(evidence, classification, DiscoveryProofId("proof-a"))
        assertTrue(attempt is DiscoveryProofAttempt.Proven)
        val proof = (attempt as DiscoveryProofAttempt.Proven).proof
        assertEquals("x-ui.service", proof.observedIdentity.serviceUnit)
        assertEquals("/usr/local/x-ui/x-ui", proof.observedIdentity.binaryPath)
        assertEquals("/usr/local/x-ui", proof.observedIdentity.rootPath)
        assertEquals("/etc/x-ui/x-ui.db", proof.observedIdentity.databasePath)
    }

    @Test
    fun `complete explicit absence remains typed and foreign absent markers add no fake family`() = runBlocking {
        val handle = exactHandle { raw, _ ->
            when {
                raw == "cat -- /etc/os-release" -> success("ID=ubuntu\nVERSION_ID=24.04\n")
                else -> absent()
            }
        }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        val evidence = (run as DiscoverySshProbeRunResult.Completed).evidence
        assertTrue(DiscoveryClassifier.classify(evidence) is DiscoveryClassification.NoSupportedInstallation)
        assertFalse(evidence.observations.any { it is DiscoveryObservation.PanelFamily })
    }

    @Test
    fun `foreign marker is report only normalized family evidence`() = runBlocking {
        val handle = exactHandle { raw, _ ->
            when {
                raw == "cat -- /etc/os-release" -> success("ID=ubuntu\n")
                raw.contains("/www/server/panel") -> success()
                else -> absent()
            }
        }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        val evidence = (run as DiscoverySshProbeRunResult.Completed).evidence
        assertTrue(DiscoveryClassifier.classify(evidence) is DiscoveryClassification.ForeignPanel)
    }

    @Test
    fun `malformed platform bytes fail closed without raw output in failure`() = runBlocking {
        val handle = exactHandle { raw, _ ->
            if (raw == "cat -- /etc/os-release") {
                commandResult(
                    completion = CommandCompletion.ConfirmedSuccess,
                    stdout = CapturedOutput.of(byteArrayOf(0xC3.toByte(), 0x28), truncated = false),
                )
            } else absent()
        }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        assertTrue(run is DiscoverySshProbeRunResult.Failed)
        val failed = run as DiscoverySshProbeRunResult.Failed
        assertTrue(failed.failure is DiscoverySshProbeExecutionFailure.MalformedProbeEvidence)
        assertFalse(failed.toString().contains("ID="))
    }

    @Test
    fun `truncated platform output fails closed`() = runBlocking {
        val handle = exactHandle { raw, _ ->
            if (raw == "cat -- /etc/os-release") {
                commandResult(
                    completion = CommandCompletion.ConfirmedSuccess,
                    stdout = CapturedOutput.of("ID=ubuntu\n".toByteArray(), truncated = true),
                )
            } else absent()
        }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        assertTrue((run as DiscoverySshProbeRunResult.Failed).failure is DiscoverySshProbeExecutionFailure.OutputTruncated)
    }

    @Test
    fun `transport uncertainty preserves dispatch boundary and stops the plan`() = runBlocking {
        val handle = exactHandle { _, _ ->
            SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = CommandCompletion.Unknown("safe fake uncertainty"),
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )
        }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        val failure = (run as DiscoverySshProbeRunResult.Failed).failure
        assertEquals(
            DiscoverySshProbeExecutionFailure.CommandUncertain(CommandDispatchState.DISPATCHED),
            failure,
        )
        assertEquals(1, handle.executions)
    }

    @Test
    fun `executor applies bounded per-probe transport configuration`() = runBlocking {
        val configs = mutableListOf<SshTransportConfig>()
        val handle = exactHandle { raw, config ->
            configs += config
            if (raw == "cat -- /etc/os-release") success("ID=ubuntu\n") else absent()
        }
        val run = DiscoverySshProbeExecutor { now }.executeInitialPlan(scope, handle)
        assertTrue(run is DiscoverySshProbeRunResult.Completed)
        assertEquals(DiscoveryProbePlan.initialProbes.size, configs.size)
        assertTrue(configs.all { it.channelOpenTimeout <= Duration.ofSeconds(5) })
        assertTrue(configs.all { it.commandExecutionTimeout == DiscoveryProbePlan.DEFAULT_PROBE_TIMEOUT })
        assertTrue(configs.all { it.stdoutCaptureLimitBytes == 8 * 1024 })
        assertTrue(configs.all { it.stderrCaptureLimitBytes == 4 * 1024 })
    }

    private fun exactHandle(
        responder: (String, SshTransportConfig) -> SshCommandResult,
    ): FakeHandle = FakeHandle(
        binding = SessionBinding(
            sessionId = SessionId("session-a"),
            serverAccessId = scope.serverAccessId,
            owner = SessionOwner.Operation(scope.operationId),
        ),
        responder = responder,
    )

    private fun canonicalLayoutResult(raw: String): SshCommandResult = when {
        raw == "cat -- /etc/os-release" -> success("ID=ubuntu\nVERSION_ID=24.04\n")
        raw.contains("x-ui.service") -> success()
        raw.contains("'/usr/local/x-ui/x-ui'") -> success()
        raw.contains("'/usr/local/x-ui'") && raw.startsWith("[ -d") -> success()
        raw.contains("'/etc/x-ui/x-ui.db'") -> success()
        else -> absent()
    }

    private fun success(stdout: String = ""): SshCommandResult = commandResult(
        completion = CommandCompletion.ConfirmedSuccess,
        stdout = CapturedOutput.of(stdout.toByteArray(), truncated = false),
    )

    private fun absent(): SshCommandResult = commandResult(
        completion = CommandCompletion.ConfirmedFailure("predicate false", exitCode = 1),
    )

    private fun commandResult(
        completion: CommandCompletion,
        stdout: CapturedOutput = CapturedOutput.EMPTY,
    ): SshCommandResult = SshCommandResult(
        dispatchState = CommandDispatchState.DISPATCHED,
        completion = completion,
        stdout = stdout,
        stderr = CapturedOutput.EMPTY,
    )

    private class FakeHandle(
        override val binding: SessionBinding,
        private val responder: (String, SshTransportConfig) -> SshCommandResult,
    ) : SshSessionHandle {
        var executions: Int = 0
            private set
        private var closed = false

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executions += 1
            return responder(command.rawForTransport(), config)
        }

        override fun close() {
            closed = true
        }
    }
}
