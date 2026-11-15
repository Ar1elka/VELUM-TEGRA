package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ManagementProbePlan
import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.domain.ManagementReadbackPolicy
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagementBaselineReadbackResult
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.model.ManagementIdentityDrift
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagementSshProbeExecutorTest {
    private val now = Instant.parse("2026-09-06T11:00:00Z")
    private val identity = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = null,
    )
    private val baseline = InstallationBaseline(
        serviceUnit = identity.serviceUnit,
        binaryPath = identity.binaryPath,
        rootPath = identity.rootPath,
        databasePath = identity.databasePath,
        panelPort = 54321,
        webBasePath = "/panel/",
        listenAddress = "127.0.0.1",
        capturedAt = now.minusSeconds(60),
    )
    private val installation = XuiInstallation(
        id = XuiInstallationId("install-a"),
        serverId = ServerId("server-a"),
        ownership = InstallationOwnership.ADOPTED,
        identity = identity,
        baseline = baseline,
    )
    private val scope = ManagementScope(
        operationId = OperationId("quick-a"),
        serverId = installation.serverId,
        serverAccessId = ServerAccessId("access-a"),
        installationId = installation.id,
    )

    @Test
    fun `compiler emits only reviewed bounded read-only quick inspect commands`() {
        val commands = ManagementProbePlan.quickInspect(installation).map { probe ->
            val compiled = requireNotNull(ManagementReadOnlyCommandCompiler.compile(probe))
            (compiled as CompiledManagementProbe.Command).command.rawForTransport()
        }

        assertEquals(7, commands.size)
        commands.forEach { command ->
            val lower = command.lowercase()
            listOf(
                "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable",
                "systemctl disable", "apt ", "apt-get", "curl ", "wget ", "find ", "sed -i",
                " tee ", "rm ", "mv ", "cp ", "chmod ", "chown ", "insert ", "update ",
                "delete ", "drop ", "alter ", "install.sh",
            ).forEach { forbidden -> assertFalse("forbidden token $forbidden in $command", forbidden in lower) }
        }
        val settings = commands.single { "sqlite3" in it }
        assertTrue("sqlite3 -readonly" in settings)
        assertTrue("webPort" in settings && "webBasePath" in settings && "webListen" in settings)
    }

    @Test
    fun `compiler rejects unsafe dynamic targets and does not invent managed marker source`() {
        assertNull(
            ManagementReadOnlyCommandCompiler.compile(
                ManagementProbeSpec.ServiceUnitPresence("x-ui.service\nrestart"),
            ),
        )
        assertNull(
            ManagementReadOnlyCommandCompiler.compile(
                ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, "/etc/x-ui/x-ui.db;touch-pwn"),
            ),
        )
        assertNull(
            ManagementReadOnlyCommandCompiler.compile(
                ManagementProbeSpec.ExactListenerPresence(54321, "127.0.0.1;touch"),
            ),
        )
        assertNull(
            ManagementReadOnlyCommandCompiler.compile(
                ManagementProbeSpec.ServiceLiveState("x-ui.service", timeout = Duration.ofMinutes(1)),
            ),
        )
        val marker = ManagementReadOnlyCommandCompiler.compile(
            ManagementProbeSpec.ManagedInstallMarkerReadback(ManagedInstallId("v1-0123456789abcdef0123456789abcdef")),
        ) as CompiledManagementProbe.Command
        assertEquals(
            "if [ -f '/var/lib/velum-tegra/managed-install/v1/identity' ]; then " +
                "cat -- '/var/lib/velum-tegra/managed-install/v1/identity'; else exit 44; fi",
            marker.command.rawForTransport(),
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

        val result = ManagementSshProbeExecutor { now }.executeQuickInspect(scope, installation, handle)
        assertTrue(result is ManagementSshProbeRunResult.Failed)
        assertTrue(
            (result as ManagementSshProbeRunResult.Failed).failure is
                ManagementSshProbeExecutionFailure.ExactSessionBindingMismatch,
        )
        assertEquals(0, handle.executions)
    }

    @Test
    fun `quick inspect normalizes exact readback and produces fresh proof`() = runBlocking {
        val handle = exactHandle { raw, _ -> canonicalResult(raw) }
        val run = ManagementSshProbeExecutor { now }.executeQuickInspect(scope, installation, handle)
        assertTrue(run is ManagementSshProbeRunResult.Completed)
        assertEquals(7, handle.executions)

        val snapshot = ManagementReadbackPolicy.quickInspect(
            installation = installation,
            evidence = (run as ManagementSshProbeRunResult.Completed).evidence,
            proofId = TargetProofId("proof-a"),
            now = now,
        )
        assertEquals(ManagementIdentityStatus.Matched, snapshot.identityStatus)
        assertNotNull(snapshot.freshProof)
        assertEquals(scope.serverAccessId, snapshot.freshProof?.serverAccessId)
    }

    @Test
    fun `enrollment baseline uses exact identity and targeted read only settings`() = runBlocking {
        val handle = exactHandle { raw, _ -> canonicalResult(raw) }
        val run = ManagementSshProbeExecutor { now }.executeEnrollmentBaseline(scope, identity, handle)
        assertTrue(run is ManagementSshProbeRunResult.Completed)
        assertEquals(5, handle.executions)

        val baselineResult = ManagementReadbackPolicy.buildEnrollmentBaseline(
            identity,
            (run as ManagementSshProbeRunResult.Completed).evidence,
        )
        val complete = baselineResult as ManagementBaselineReadbackResult.Complete
        assertEquals(54321, complete.baseline.panelPort)
        assertEquals("/panel/", complete.baseline.webBasePath)
        assertEquals("127.0.0.1", complete.baseline.listenAddress)
    }

    @Test
    fun `managed marker is read back and only an exact match yields fresh proof`() = runBlocking {
        val managedId = ManagedInstallId("v1-0123456789abcdef0123456789abcdef")
        val otherId = ManagedInstallId("v1-fedcba9876543210fedcba9876543210")
        val managedInstallation = installation.copy(
            ownership = InstallationOwnership.MANAGED,
            identity = identity.copy(managedInstallId = managedId),
        )
        suspend fun inspect(marker: SshCommandResult): Pair<ManagementSshProbeRunResult, Int> {
            val handle = exactHandle { raw, _ -> if ("managed-install" in raw) marker else canonicalResult(raw) }
            return ManagementSshProbeExecutor { now }.executeQuickInspect(scope, managedInstallation, handle) to handle.executions
        }
        fun snapshot(run: ManagementSshProbeRunResult) = ManagementReadbackPolicy.quickInspect(
            managedInstallation,
            (run as ManagementSshProbeRunResult.Completed).evidence,
            TargetProofId("proof-managed"),
            now,
        )

        val (matched, executions) = inspect(success(ManagedInstallMarkerProtocol.encode(managedId)))
        assertEquals(8, executions)
        assertEquals(ManagementIdentityStatus.Matched, snapshot(matched).identityStatus)
        assertNotNull(snapshot(matched).freshProof)

        val mismatch = snapshot(inspect(success(ManagedInstallMarkerProtocol.encode(otherId))).first)
        assertEquals(
            ManagementIdentityStatus.Drift(setOf(ManagementIdentityDrift.MANAGED_MARKER_MISMATCH)),
            mismatch.identityStatus,
        )
        assertNull(mismatch.freshProof)

        val absent = snapshot(
            inspect(commandResult(CommandCompletion.ConfirmedFailure(reason = "absent", exitCode = 44))).first,
        )
        assertEquals(
            ManagementIdentityStatus.Drift(setOf(ManagementIdentityDrift.MANAGED_MARKER_ABSENT)),
            absent.identityStatus,
        )
        assertNull(absent.freshProof)

        val malformed = inspect(success("not-a-managed-marker\n")).first as ManagementSshProbeRunResult.Failed
        assertEquals(ManagementSshProbeExecutionFailure.MalformedProbeEvidence, malformed.failure)
        assertTrue(malformed.failedProbe is ManagementProbeSpec.ManagedInstallMarkerReadback)
        assertFalse(malformed.toString().contains("not-a-managed-marker"))

        val unreadable = inspect(commandResult(CommandCompletion.ConfirmedFailure(reason = "denied", exitCode = 1))).first
        assertEquals(
            ManagementSshProbeExecutionFailure.CommandFailed(1),
            (unreadable as ManagementSshProbeRunResult.Failed).failure,
        )
    }

    @Test
    fun `malformed or truncated settings fail closed without retaining raw output`() = runBlocking {
        val malformedHandle = exactHandle { raw, _ ->
            if ("sqlite3" in raw) success("PORT=oops\nWEB_BASE_PATH=/panel/\n") else canonicalResult(raw)
        }
        val malformed = ManagementSshProbeExecutor { now }.executeQuickInspect(scope, installation, malformedHandle)
        assertTrue(
            (malformed as ManagementSshProbeRunResult.Failed).failure is
                ManagementSshProbeExecutionFailure.MalformedProbeEvidence,
        )
        assertFalse(malformed.toString().contains("PORT=oops"))

        val truncatedHandle = exactHandle { raw, _ ->
            if ("sqlite3" in raw) {
                commandResult(
                    completion = CommandCompletion.ConfirmedSuccess,
                    stdout = CapturedOutput.of("PORT=54321\n".toByteArray(), truncated = true),
                )
            } else canonicalResult(raw)
        }
        val truncated = ManagementSshProbeExecutor { now }.executeQuickInspect(scope, installation, truncatedHandle)
        assertTrue(
            (truncated as ManagementSshProbeRunResult.Failed).failure is
                ManagementSshProbeExecutionFailure.OutputTruncated,
        )
    }

    @Test
    fun `transport uncertainty stops the plan and bounded config is used`() = runBlocking {
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

        val run = ManagementSshProbeExecutor { now }.executeQuickInspect(scope, installation, handle)
        val failure = (run as ManagementSshProbeRunResult.Failed).failure
        assertEquals(
            ManagementSshProbeExecutionFailure.CommandUncertain(CommandDispatchState.DISPATCHED),
            failure,
        )
        assertEquals(1, handle.executions)
        assertEquals(1, configs.size)
        assertTrue(configs.single().channelOpenTimeout <= Duration.ofSeconds(5))
        assertEquals(ManagementProbePlan.DEFAULT_PROBE_TIMEOUT, configs.single().commandExecutionTimeout)
        assertEquals(4 * 1024, configs.single().stdoutCaptureLimitBytes)
        assertEquals(2 * 1024, configs.single().stderrCaptureLimitBytes)
    }

    @Test
    fun `settings reader failures stop before further probes and retain no database output`() = runBlocking {
        for (code in listOf(ManagementPanelSettingsExit.SQLITE_UNAVAILABLE,
            ManagementPanelSettingsExit.DATABASE_UNREADABLE, ManagementPanelSettingsExit.QUERY_FAILED)) {
            val handle = exactHandle { raw, _ ->
                if ("sqlite3" in raw) commandResult(
                    CommandCompletion.ConfirmedFailure(reason = "fixture settings failure", exitCode = code),
                    CapturedOutput.of("private-settings-must-not-escape".toByteArray(), truncated = false),
                ) else canonicalResult(raw)
            }
            val result = ManagementSshProbeExecutor { now }.executeQuickInspect(scope, installation, handle)
                as ManagementSshProbeRunResult.Failed
            assertEquals(ManagementSshProbeExecutionFailure.CommandFailed(code), result.failure)
            assertTrue(result.failedProbe is ManagementProbeSpec.PanelSettingsReadback)
            assertEquals(6, handle.executions) // listener query is never reached
            assertFalse(result.toString().contains("private-settings-must-not-escape"))
            assertTrue(result.observations.none { it is com.velumtegra.xuimobile.core.model.ManagementObservation.PanelSettings })
        }
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

    private fun canonicalResult(raw: String): SshCommandResult = when {
        "systemctl is-active" in raw -> success("active\n")
        "sqlite3" in raw -> success("PORT=54321\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n")
        else -> success()
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
