package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbePlan
import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbeSpec
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseIntegrityStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFilePresence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticObservation
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeepDiagnosticSshProbeExecutorTest {
    private val now = Instant.parse("2026-09-06T13:00:00Z")
    private val identity = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = null,
    )
    private val installation = XuiInstallation(
        id = XuiInstallationId("install-deep-a"),
        serverId = ServerId("server-deep-a"),
        ownership = InstallationOwnership.ADOPTED,
        identity = identity,
        baseline = InstallationBaseline(
            serviceUnit = identity.serviceUnit,
            binaryPath = identity.binaryPath,
            rootPath = identity.rootPath,
            databasePath = identity.databasePath,
            panelPort = 2053,
            webBasePath = "/panel/",
            listenAddress = null,
            capturedAt = now.minusSeconds(60),
        ),
    )
    private val scope = DeepDiagnosticScope(
        operationId = OperationId("deep-a"),
        serverId = installation.serverId,
        serverAccessId = ServerAccessId("access-deep-a"),
        installationId = installation.id,
    )

    @Test
    fun `compiler emits only reviewed finite read only deep commands`() {
        val primary = DeepDiagnosticProbePlan.forInstallation(installation).primaryProbes
        val derived = DeepDiagnosticProbePlan.derivedCertificateProbes(
            com.velumtegra.xuimobile.core.model.DeepDiagnosticCertificateReferences(
                certificatePath = "/etc/ssl/x-ui/fullchain.pem",
                privateKeyPath = "/etc/ssl/x-ui/privkey.pem",
            ),
        )
        val commands = (primary + derived).map { requireNotNull(DeepDiagnosticReadOnlyCommandCompiler.compile(it)).rawForTransport() }
        assertEquals(7, commands.size)
        commands.forEach { command ->
            val lower = command.lowercase()
            listOf(
                "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable",
                "systemctl disable", "apt ", "apt-get", "curl ", "wget ", "find /", "sed -i",
                " tee ", "rm ", "mv ", "cp ", "chmod ", "chown ", "insert ", "update ",
                "delete ", "drop ", "alter ", "install.sh", "journalctl",
            ).forEach { forbidden -> assertFalse("forbidden token $forbidden in $command", forbidden in lower) }
        }
        val keyCommand = commands.single { "deep-private-key" !in it && "privkey.pem" in it }
        assertFalse("cat " in keyCommand.lowercase())
        assertFalse("openssl pkey" in keyCommand.lowercase())
    }

    @Test
    fun `compiler rejects unsafe service target`() {
        val unsafe = DeepDiagnosticProbeSpec.ServiceDefinitionReadback(
            serviceUnit = "x-ui.service;rm",
            expectedBinaryPath = identity.binaryPath,
        )
        assertEquals(null, DeepDiagnosticReadOnlyCommandCompiler.compile(unsafe))
    }

    @Test
    fun `wrong exact session binding fails before any command`() = runBlocking {
        val handle = FakeHandle(
            SessionBinding(SessionId("session-wrong"), ServerAccessId("wrong-access"), SessionOwner.Operation(scope.operationId)),
        ) { _, _ -> error("must not execute") }
        val result = DeepDiagnosticSshProbeExecutor { now }.execute(scope, installation, handle)
        assertTrue(result is DeepDiagnosticSshProbeRunResult.Failed)
        assertTrue((result as DeepDiagnosticSshProbeRunResult.Failed).failure is DeepDiagnosticSshProbeExecutionFailure.ExactSessionBindingMismatch)
        assertEquals(0, handle.executions)
    }

    @Test
    fun `primary and derived probes normalize into bounded evidence`() = runBlocking {
        val handle = exactHandle { raw, _ -> canonicalResult(raw) }
        val result = DeepDiagnosticSshProbeExecutor { now }.execute(scope, installation, handle)
        assertTrue(result is DeepDiagnosticSshProbeRunResult.Completed)
        val evidence = (result as DeepDiagnosticSshProbeRunResult.Completed).evidence
        assertEquals(7, handle.executions)
        assertEquals(7, evidence.observations.size)
        assertTrue(evidence.observations.filterIsInstance<DeepDiagnosticObservation.DatabaseIntegrity>().single().status == DeepDiagnosticDatabaseIntegrityStatus.OK)
        val cert = evidence.observations.filterIsInstance<DeepDiagnosticObservation.CertificateFile>().single()
        assertEquals(DeepDiagnosticFilePresence.PRESENT, cert.presence)
        assertEquals(Instant.parse("2026-09-01T12:00:00Z"), cert.notBefore)
        assertEquals(Instant.parse("2026-12-01T12:00:00Z"), cert.notAfter)
        val key = evidence.observations.filterIsInstance<DeepDiagnosticObservation.PrivateKeyFile>().single()
        assertEquals(DeepDiagnosticFilePresence.PRESENT, key.presence)
    }

    @Test
    fun `database quick check corruption becomes typed failed integrity not transport success`() = runBlocking {
        val handle = exactHandle { raw, _ ->
            if ("PRAGMA quick_check" in raw) success("database disk image is malformed\n") else canonicalResult(raw)
        }
        val result = DeepDiagnosticSshProbeExecutor { now }.execute(scope, installation, handle)
        val evidence = (result as DeepDiagnosticSshProbeRunResult.Completed).evidence
        assertEquals(
            DeepDiagnosticDatabaseIntegrityStatus.FAILED,
            evidence.observations.filterIsInstance<DeepDiagnosticObservation.DatabaseIntegrity>().single().status,
        )
    }

    @Test
    fun `unsafe certificate reference fails closed before derived file command and raw path is not retained`() = runBlocking {
        val rawUnsafe = "CERT=../../secret.pem\nKEY=\n"
        val handle = exactHandle { raw, _ ->
            if ("webCertFile" in raw) success(rawUnsafe) else canonicalResult(raw)
        }
        val result = DeepDiagnosticSshProbeExecutor { now }.execute(scope, installation, handle)
        assertTrue(result is DeepDiagnosticSshProbeRunResult.Failed)
        assertTrue((result as DeepDiagnosticSshProbeRunResult.Failed).failure is DeepDiagnosticSshProbeExecutionFailure.MalformedProbeEvidence)
        assertEquals(5, handle.executions)
        assertFalse(result.toString().contains("../../secret.pem"))
    }

    @Test
    fun `transport uncertainty stops immediately with bounded config`() = runBlocking {
        val configs = mutableListOf<SshTransportConfig>()
        val handle = exactHandle { _, config ->
            configs += config
            SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = CommandCompletion.Unknown("fake uncertainty"),
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )
        }
        val result = DeepDiagnosticSshProbeExecutor { now }.execute(scope, installation, handle)
        val failure = (result as DeepDiagnosticSshProbeRunResult.Failed).failure
        assertEquals(
            DeepDiagnosticSshProbeExecutionFailure.CommandUncertain(CommandDispatchState.DISPATCHED),
            failure,
        )
        assertEquals(1, handle.executions)
        assertEquals(1, configs.size)
        assertTrue(configs.single().channelOpenTimeout <= Duration.ofSeconds(5))
        assertEquals(DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT, configs.single().commandExecutionTimeout)
        assertEquals(8 * 1024, configs.single().stdoutCaptureLimitBytes)
        assertEquals(2 * 1024, configs.single().stderrCaptureLimitBytes)
    }

    @Test
    fun `truncated evidence fails closed and does not expose bytes in result`() = runBlocking {
        val secretRaw = "v3.7.0-secret"
        val handle = exactHandle { raw, _ ->
            if (raw.endsWith(" -v")) {
                commandResult(
                    CommandCompletion.ConfirmedSuccess,
                    CapturedOutput.of(secretRaw.toByteArray(), truncated = true),
                )
            } else canonicalResult(raw)
        }
        val result = DeepDiagnosticSshProbeExecutor { now }.execute(scope, installation, handle)
        assertTrue((result as DeepDiagnosticSshProbeRunResult.Failed).failure is DeepDiagnosticSshProbeExecutionFailure.OutputTruncated)
        assertFalse(result.toString().contains(secretRaw))
    }

    private fun exactHandle(responder: (String, SshTransportConfig) -> SshCommandResult): FakeHandle = FakeHandle(
        binding = SessionBinding(SessionId("session-deep-a"), scope.serverAccessId, SessionOwner.Operation(scope.operationId)),
        responder = responder,
    )

    private fun canonicalResult(raw: String): SshCommandResult = when {
        "LoadState" in raw -> success("LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; ignore_errors=no ; }\n")
        raw.endsWith(" -v") -> success("v3.7.0\n")
        "PRAGMA quick_check" in raw -> success("ok\n")
        "pragma_table_info" in raw -> success("SUPPORTED\n")
        "webCertFile" in raw -> success("CERT=/etc/ssl/x-ui/fullchain.pem\nKEY=/etc/ssl/x-ui/privkey.pem\n")
        "openssl x509" in raw -> success("PRESENCE=PRESENT\nnotBefore=Sep  1 12:00:00 2026 GMT\nnotAfter=Dec  1 12:00:00 2026 GMT\n")
        "privkey.pem" in raw -> success("PRESENT\n")
        else -> error("unexpected reviewed command: $raw")
    }

    private fun success(stdout: String = ""): SshCommandResult = commandResult(
        completion = CommandCompletion.ConfirmedSuccess,
        stdout = CapturedOutput.of(stdout.toByteArray(), truncated = false),
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
        override val isOpen: Boolean get() = !closed
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executions += 1
            return responder(command.rawForTransport(), config)
        }
        override fun close() { closed = true }
    }
}
