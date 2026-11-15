package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.ReviewedInstallPlanPolicy
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.InstallerPlanStep
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ReviewedInstallPlan
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.UpdateServerArchitecture
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FreshInstallReadinessSshAdapterTest {
    private val now = Instant.parse("2026-11-06T10:00:00Z")
    private val scope = FreshInstallScope(OperationId("op-1"), ServerId("server-1"), ServerAccessId("access-1"))
    private val compiler = FreshInstallReadinessCommandCompiler
    private val paths = compiler.observedPaths

    // ---- compiler -------------------------------------------------------------------------

    @Test
    fun `compiled commands are fixed and contain no mutating or network tokens`() {
        val forbidden = listOf(
            "sudo", "curl", "wget", "apt", "systemctl start", "systemctl stop", "systemctl restart",
            "systemctl enable", "systemctl disable", "systemctl daemon", " rm ", " mv ", " cp ", "chmod ",
            "chown ", "install ", "mkdir", "touch", "tee ", ">>", "sed -i", "sqlite3", "install.sh", "kill",
        )
        compiler.all.forEach { cmd ->
            // Quoted literals (paths, tool names, printf formats) are data, not commands.
            val raw = cmd.command.rawForTransport().replace(Regex("'[^']*'"), "''")
            forbidden.forEach { token -> assertFalse("$token in ${cmd.step}", token in raw) }
            // Only discarding redirects to /dev/null are allowed; never a file write.
            assertFalse(Regex(">\\s*[^&\\s/]").containsMatchIn(raw.replace(">/dev/null", "").replace("2>&1", "")))
            assertTrue(cmd.config.commandExecutionTimeout.seconds <= 10)
            assertTrue(cmd.config.stdoutCaptureLimitBytes <= 8 * 1024)
            assertTrue(cmd.command.toString().contains("[REDACTED]"))
        }
    }

    @Test
    fun `required tools cover every utility used by the reviewed installer compiler`() {
        val compiled = requireNotNull(InstallerReviewedCommandCompiler.compile(canonicalPlan())).steps +
            requireNotNull(InstallerReviewedCommandCompiler.compileDetached(canonicalPlan())).steps
        val text = compiled.joinToString("\n") { it.command.rawForTransport() }
        compiler.requiredToolNames.forEach { tool ->
            assertTrue("$tool unused by compiler", Regex("(^|[^A-Za-z0-9_-])$tool([^A-Za-z0-9_-]|$)").containsMatchIn(text))
        }
        // The external, non-builtin utilities the compiler actually invokes must all be required.
        listOf("curl", "sha1sum", "awk", "setsid", "nohup", "install", "mv", "rm", "chmod", "date", "sleep", "dirname", "wc", "tr", "cat")
            .forEach { assertTrue("$it must be required", it in compiler.requiredToolNames) }
    }

    @Test
    fun `observed paths include every discovery path launcher marker and foreign marker`() {
        val observed = paths.map { it.path }
        (DiscoveryProbePlan.supportedBinaryProbePaths + DiscoveryProbePlan.supportedRootProbePaths +
            DiscoveryProbePlan.supportedDatabaseProbePaths + DiscoveryProbePlan.foreignPanelPathMarkers)
            .forEach { assertTrue(it in observed) }
        assertTrue(ManagedInstallMarkerProtocol.MARKER_PATH in observed)
        assertTrue(paths.any { it.role == FreshInstallPathRole.LAUNCHER && it.path == "/usr/bin/x-ui" })
        assertEquals(observed.size, observed.toSet().size)
    }

    // ---- exact session ------------------------------------------------------------------

    @Test
    fun `wrong owner or access or closed session is rejected before any command`() = runBlocking {
        val adapter = FreshInstallReadinessSshAdapter { now }
        val wrongOwner = handle(owner = SessionOwner.Operation(OperationId("other")))
        val wrongAccess = handle(access = ServerAccessId("other"))
        listOf(wrongOwner, wrongAccess).forEach {
            assertEquals(
                FreshInstallReadinessObservationResult.Rejected(FreshInstallReadinessRejection.ExactSessionBindingMismatch),
                adapter.observe(scope, it),
            )
            assertEquals(0, it.executions)
        }
        val closed = handle().also { it.close() }
        assertEquals(
            FreshInstallReadinessObservationResult.Rejected(FreshInstallReadinessRejection.SessionClosed),
            adapter.observe(scope, closed),
        )
        assertEquals(0, closed.executions)
    }

    @Test
    fun `session closing or changing mid-run is indeterminate`() = runBlocking {
        val closing = handle { raw, h -> if (raw == compiler.platformRelease.command.rawForTransport()) h.close(); clean(raw) }
        val result = FreshInstallReadinessSshAdapter { now }.observe(scope, closing)
        val indeterminate = result as FreshInstallReadinessObservationResult.Indeterminate
        assertTrue(FreshInstallUncertainty.SessionChanged in indeterminate.uncertainties)
        assertEquals(3, closing.executions)
    }

    // ---- positive ---------------------------------------------------------------------

    @Test
    fun `ready only with complete valid clean data and runs each fixed command once`() = runBlocking {
        val h = handle { raw, _ -> clean(raw) }
        val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h)
        val ready = result as FreshInstallReadinessObservationResult.Ready
        assertEquals(DiscoveryPlatform("ubuntu", "24.04"), ready.facts.platform)
        assertEquals(UpdateServerArchitecture.AMD64, ready.facts.architecture)
        assertEquals(FreshInstallPrivilegeCapability.DIRECT_ROOT, ready.facts.privilegeCapability)
        assertEquals(FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1, ready.facts.installerCapability)
        assertEquals(now, ready.facts.observedAt)
        assertEquals(scope, ready.facts.scope)
        assertEquals(compiler.all.map { it.command.rawForTransport() }, h.commands)
        h.configs.forEach {
            assertTrue(it.channelOpenTimeout <= java.time.Duration.ofSeconds(5))
            assertTrue(it.stderrCaptureLimitBytes <= 512)
        }
    }

    @Test
    fun `arm64 is supported`() = runBlocking {
        val h = handle { raw, _ -> if (raw == compiler.kernelAndArchitecture.command.rawForTransport()) ok("Linux\naarch64\n") else clean(raw) }
        val ready = FreshInstallReadinessSshAdapter { now }.observe(scope, h) as FreshInstallReadinessObservationResult.Ready
        assertEquals(UpdateServerArchitecture.ARM64, ready.facts.architecture)
    }

    // ---- prerequisites ------------------------------------------------------------------

    @Test
    fun `non root stops after uid and never claims clean`() = runBlocking {
        val h = handle { raw, _ -> if (raw == "id -u") ok("1000\n") else clean(raw) }
        val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h)
        assertEquals(
            FreshInstallReadinessObservationResult.PrerequisitesUnmet(setOf(FreshInstallPrerequisiteGap.NotDirectRoot)),
            result,
        )
        assertEquals(1, h.executions)
        assertFalse(h.commands.any { "sudo" in it })
    }

    @Test
    fun `unsupported platform architecture kernel systemd and missing tools are prerequisites not conflicts`() = runBlocking {
        val h = handle { raw, _ ->
            when (raw) {
                compiler.kernelAndArchitecture.command.rawForTransport() -> ok("FreeBSD\narmv7l\n")
                compiler.platformRelease.command.rawForTransport() -> ok("ID=alpine\nVERSION_ID=3.20\n")
                compiler.systemd.command.rawForTransport() -> ok("SYSTEMD=ABSENT\n")
                compiler.requiredTools.command.rawForTransport() ->
                    ok(compiler.requiredToolNames.joinToString("") { t -> if (t == "curl" || t == "setsid") "$t A\n" else "$t P\n" })
                else -> clean(raw)
            }
        }
        val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h)
        val unmet = result as FreshInstallReadinessObservationResult.PrerequisitesUnmet
        assertEquals(
            setOf(
                FreshInstallPrerequisiteGap.NotLinux,
                FreshInstallPrerequisiteGap.UnsupportedArchitecture,
                FreshInstallPrerequisiteGap.UnsupportedPlatform(DiscoveryPlatform("alpine", "3.20")),
                FreshInstallPrerequisiteGap.SystemdUnavailable,
                FreshInstallPrerequisiteGap.RequiredToolMissing("curl"),
                FreshInstallPrerequisiteGap.RequiredToolMissing("setsid"),
            ),
            unmet.prerequisiteGaps,
        )
        // Service probe is not run without systemd.
        assertFalse(h.commands.contains(compiler.serviceLoadState.command.rawForTransport()))
    }

    // ---- conflicts ----------------------------------------------------------------------

    @Test
    fun `loaded x-ui service is a conflict`() = runBlocking {
        val h = handle { raw, _ -> if (raw == compiler.serviceLoadState.command.rawForTransport()) ok("loaded\n") else clean(raw) }
        val conflict = FreshInstallReadinessSshAdapter { now }.observe(scope, h) as FreshInstallReadinessObservationResult.Conflict
        assertEquals(
            setOf<FreshInstallConflict>(
                FreshInstallConflict.ExistingServiceUnit("x-ui.service", FreshInstallServiceLoadState.LOADED),
            ),
            conflict.conflicts,
        )
        assertTrue(conflict.uncertainties.isEmpty())
    }

    @Test
    fun `symlink wrong type directory marker and foreign panel are conflicts with exact kind`() = runBlocking {
        val root = indexOf(FreshInstallPathRole.ROOT, "/usr/local/x-ui")
        val binary = indexOf(FreshInstallPathRole.BINARY, "/opt/x-ui/x-ui")
        val launcher = indexOf(FreshInstallPathRole.LAUNCHER, "/usr/bin/x-ui")
        val db = indexOf(FreshInstallPathRole.DATABASE, "/etc/x-ui/x-ui.db")
        val marker = indexOf(FreshInstallPathRole.MANAGED_MARKER, ManagedInstallMarkerProtocol.MARKER_PATH)
        val foreign = indexOf(FreshInstallPathRole.FOREIGN_PANEL, "/www/server/panel")
        val h = handle { raw, _ ->
            if (raw == compiler.knownPaths.command.rawForTransport()) {
                pathStates(mapOf(root to "FILE", binary to "SYMLINK", launcher to "SYMLINK", db to "DIR", marker to "FILE", foreign to "OTHER"))
            } else clean(raw)
        }
        val conflict = FreshInstallReadinessSshAdapter { now }.observe(scope, h) as FreshInstallReadinessObservationResult.Conflict
        assertEquals(
            setOf<FreshInstallConflict>(
                FreshInstallConflict.ExistingPath(FreshInstallPathRole.ROOT, "/usr/local/x-ui", FreshInstallPathObject.REGULAR_FILE),
                FreshInstallConflict.ExistingPath(FreshInstallPathRole.BINARY, "/opt/x-ui/x-ui", FreshInstallPathObject.SYMLINK),
                FreshInstallConflict.ExistingPath(FreshInstallPathRole.LAUNCHER, "/usr/bin/x-ui", FreshInstallPathObject.SYMLINK),
                FreshInstallConflict.ExistingPath(FreshInstallPathRole.DATABASE, "/etc/x-ui/x-ui.db", FreshInstallPathObject.DIRECTORY),
                FreshInstallConflict.ExistingPath(
                    FreshInstallPathRole.MANAGED_MARKER, ManagedInstallMarkerProtocol.MARKER_PATH, FreshInstallPathObject.REGULAR_FILE,
                ),
                FreshInstallConflict.ExistingPath(FreshInstallPathRole.FOREIGN_PANEL, "/www/server/panel", FreshInstallPathObject.OTHER),
            ),
            conflict.conflicts,
        )
    }

    @Test
    fun `conflict plus later uncertainty stays a conflict and carries the uncertainty`() = runBlocking {
        val svc = compiler.serviceLoadState.command.rawForTransport()
        val h = handle { raw, _ ->
            when (raw) {
                svc -> ok("masked\n")
                compiler.knownPaths.command.rawForTransport() -> unknown()
                else -> clean(raw)
            }
        }
        val conflict = FreshInstallReadinessSshAdapter { now }.observe(scope, h) as FreshInstallReadinessObservationResult.Conflict
        assertEquals(1, conflict.conflicts.size)
        assertEquals(
            setOf<FreshInstallUncertainty>(
                FreshInstallUncertainty.CommandUncertain(FreshInstallReadinessStep.KNOWN_PATHS, CommandDispatchState.DISPATCHED),
            ),
            conflict.uncertainties,
        )
    }

    // ---- unknown / truncated / malformed: never Ready ----------------------------------

    @Test
    fun `permission error or non zero exit is never treated as absent`() = runBlocking {
        for (step in listOf(compiler.knownPaths, compiler.serviceLoadState, compiler.platformRelease, compiler.requiredTools)) {
            val h = handle { raw, _ ->
                if (raw == step.command.rawForTransport()) failed(exit = 1, stderr = "Permission denied") else clean(raw)
            }
            val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h)
            val indeterminate = result as FreshInstallReadinessObservationResult.Indeterminate
            assertEquals(
                setOf<FreshInstallUncertainty>(FreshInstallUncertainty.CommandFailed(step.step, 1)),
                indeterminate.uncertainties,
            )
        }
    }

    @Test
    fun `unreadable path state is uncertainty not clean`() = runBlocking {
        val idx = indexOf(FreshInstallPathRole.DATABASE, "/opt/x-ui/x-ui.db")
        val h = handle { raw, _ ->
            if (raw == compiler.knownPaths.command.rawForTransport()) pathStates(mapOf(idx to "UNREADABLE")) else clean(raw)
        }
        val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h) as FreshInstallReadinessObservationResult.Indeterminate
        assertEquals(setOf<FreshInstallUncertainty>(FreshInstallUncertainty.UnreadablePath("/opt/x-ui/x-ui.db")), result.uncertainties)
    }

    @Test
    fun `unknown completion and undispatched command abort the plan`() = runBlocking {
        val unknownHandle = handle { _, _ -> unknown() }
        val first = FreshInstallReadinessSshAdapter { now }.observe(scope, unknownHandle)
        assertEquals(
            FreshInstallReadinessObservationResult.Indeterminate(
                setOf(FreshInstallUncertainty.CommandUncertain(FreshInstallReadinessStep.EFFECTIVE_UID, CommandDispatchState.DISPATCHED)),
                emptySet(),
            ),
            first,
        )
        assertEquals(1, unknownHandle.executions)

        val notDispatched = handle { _, _ ->
            SshCommandResult(CommandDispatchState.NOT_DISPATCHED, CommandCompletion.Unknown("x"), CapturedOutput.EMPTY, CapturedOutput.EMPTY)
        }
        val second = FreshInstallReadinessSshAdapter { now }.observe(scope, notDispatched) as FreshInstallReadinessObservationResult.Indeterminate
        assertEquals(
            setOf<FreshInstallUncertainty>(
                FreshInstallUncertainty.CommandUncertain(FreshInstallReadinessStep.EFFECTIVE_UID, CommandDispatchState.NOT_DISPATCHED),
            ),
            second.uncertainties,
        )
    }

    @Test
    fun `truncated oversize non utf8 and stderr output fail closed on every step`() = runBlocking {
        val variants: List<(String) -> SshCommandResult> = listOf(
            { good -> SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess, CapturedOutput.of(good.toByteArray(), true), CapturedOutput.EMPTY) },
            { good -> SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess, CapturedOutput.of(good.toByteArray() + byteArrayOf(0xC3.toByte(), 0x28), false), CapturedOutput.EMPTY) },
            { good -> SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess, CapturedOutput.of(good.toByteArray(), false), CapturedOutput.of("warn".toByteArray(), false)) },
            { _ -> SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess, CapturedOutput.of(ByteArray(0), false), CapturedOutput.EMPTY) },
        )
        for (step in compiler.all) {
            for (variant in variants) {
                val h = handle { raw, _ ->
                    if (raw == step.command.rawForTransport()) variant(cleanText(raw)) else clean(raw)
                }
                val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h)
                assertTrue("${step.step} -> $result", result is FreshInstallReadinessObservationResult.Indeterminate)
                assertFalse(result is FreshInstallReadinessObservationResult.Ready)
            }
        }
    }

    @Test
    fun `missing extra reordered or unexpected lines are malformed never ready`() = runBlocking {
        fun observeWith(step: FreshInstallReadinessCommand, transform: (String) -> String): FreshInstallReadinessObservationResult {
            val h = handle { raw, _ -> if (raw == step.command.rawForTransport()) ok(transform(cleanText(raw))) else clean(raw) }
            return runBlocking { FreshInstallReadinessSshAdapter { now }.observe(scope, h) }
        }
        listOf(compiler.effectiveUid, compiler.kernelAndArchitecture, compiler.systemd, compiler.requiredTools, compiler.serviceLoadState, compiler.knownPaths)
            .forEach { step ->
                val transforms = listOf<(String) -> String>(
                    { it.lines().filter { l -> l.isNotEmpty() }.dropLast(1).joinToString("") { l -> l + "\n" } },
                    { it + "EXTRA\n" },
                    { it.removeSuffix("\n") },
                    { it.replace("\n", "\r\n") },
                )
                transforms.forEach { t ->
                    val result = observeWith(step, t)
                    assertTrue("${step.step}: $result", result is FreshInstallReadinessObservationResult.Indeterminate)
                }
            }
        // Garbage os-release (no ID) and garbage states.
        assertTrue(observeWith(compiler.platformRelease) { "NAME=x\n" } is FreshInstallReadinessObservationResult.Indeterminate)
        assertTrue(observeWith(compiler.serviceLoadState) { "active\n" } is FreshInstallReadinessObservationResult.Indeterminate)
        assertTrue(observeWith(compiler.systemd) { "SYSTEMD=MAYBE\n" } is FreshInstallReadinessObservationResult.Indeterminate)
        assertTrue(observeWith(compiler.effectiveUid) { "root\n" } is FreshInstallReadinessObservationResult.Indeterminate)
        assertTrue(observeWith(compiler.effectiveUid) { "00\n" } is FreshInstallReadinessObservationResult.Indeterminate)
        assertTrue(observeWith(compiler.knownPaths) { it.replace("ABSENT", "MISSING") } is FreshInstallReadinessObservationResult.Indeterminate)
        // A shifted index is malformed.
        assertTrue(observeWith(compiler.knownPaths) { it.replaceFirst("0 ABSENT", "7 ABSENT") } is FreshInstallReadinessObservationResult.Indeterminate)
    }

    @Test
    fun `result and reasons never contain raw output`() = runBlocking {
        val secret = "TOP-SECRET-RAW"
        val h = handle { raw, _ -> if (raw == compiler.platformRelease.command.rawForTransport()) ok("ID=ubuntu\nNAME=$secret x\n\u0000") else clean(raw) }
        val result = FreshInstallReadinessSshAdapter { now }.observe(scope, h)
        assertFalse(result.toString().contains(secret))
    }

    // ---- fixtures -----------------------------------------------------------------------

    private fun indexOf(role: FreshInstallPathRole, path: String): Int =
        paths.indexOfFirst { it.role == role && it.path == path }.also { assertTrue("$role $path", it >= 0) }

    private fun cleanText(raw: String): String = when (raw) {
        compiler.effectiveUid.command.rawForTransport() -> "0\n"
        compiler.kernelAndArchitecture.command.rawForTransport() -> "Linux\nx86_64\n"
        compiler.platformRelease.command.rawForTransport() -> "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"
        compiler.systemd.command.rawForTransport() -> "SYSTEMD=PRESENT\n"
        compiler.requiredTools.command.rawForTransport() -> compiler.requiredToolNames.joinToString("") { "$it P\n" }
        compiler.serviceLoadState.command.rawForTransport() -> "not-found\n"
        compiler.knownPaths.command.rawForTransport() -> paths.indices.joinToString("") { "$it ABSENT\n" }
        else -> error("unexpected command")
    }

    private fun clean(raw: String): SshCommandResult = ok(cleanText(raw))

    private fun pathStates(overrides: Map<Int, String>): SshCommandResult =
        ok(paths.indices.joinToString("") { "$it ${overrides[it] ?: "ABSENT"}\n" })

    private fun ok(stdout: String) = SshCommandResult(
        CommandDispatchState.DISPATCHED,
        CommandCompletion.ConfirmedSuccess,
        CapturedOutput.of(stdout.toByteArray(), truncated = false),
        CapturedOutput.EMPTY,
    )

    private fun failed(exit: Int, stderr: String) = SshCommandResult(
        CommandDispatchState.DISPATCHED,
        CommandCompletion.ConfirmedFailure("exit", exit),
        CapturedOutput.EMPTY,
        CapturedOutput.of(stderr.toByteArray(), truncated = false),
    )

    private fun unknown() = SshCommandResult(
        CommandDispatchState.DISPATCHED,
        CommandCompletion.Unknown("transport lost"),
        CapturedOutput.EMPTY,
        CapturedOutput.EMPTY,
    )

    private fun canonicalPlan(): ReviewedInstallPlan {
        val managedId = ManagedInstallId("v1-0123456789abcdef0123456789abcdef")
        val cap = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1
        return ReviewedInstallPlan(
            scope = InstallerWorkerScope(scope.operationId, scope.serverId, scope.serverAccessId, managedId),
            capability = cap,
            steps = listOf(
                InstallerPlanStep.PrepareWorker(ReviewedInstallPlanPolicy.PREPARE_WORKER_TIMEOUT),
                InstallerPlanStep.FetchReviewedInstaller(cap, ReviewedInstallPlanPolicy.FETCH_INSTALLER_TIMEOUT),
                InstallerPlanStep.ExecuteReviewedInstaller(cap, ReviewedInstallPlanPolicy.EXECUTE_INSTALLER_TIMEOUT),
                InstallerPlanStep.WriteManagedMarker(managedId, ReviewedInstallPlanPolicy.WRITE_MARKER_TIMEOUT),
            ),
        )
    }

    private fun handle(
        owner: SessionOwner = SessionOwner.Operation(scope.operationId),
        access: ServerAccessId = scope.serverAccessId,
        responder: (String, FakeHandle) -> SshCommandResult = { raw, _ -> clean(raw) },
    ) = FakeHandle(SessionBinding(SessionId("s-1"), access, owner), responder)

    private class FakeHandle(
        override val binding: SessionBinding,
        private val responder: (String, FakeHandle) -> SshCommandResult,
    ) : SshSessionHandle {
        val commands = mutableListOf<String>()
        val configs = mutableListOf<SshTransportConfig>()
        val executions: Int get() = commands.size
        private var closed = false
        override val isOpen: Boolean get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            commands += command.rawForTransport()
            configs += config
            return responder(command.rawForTransport(), this)
        }

        override fun close() {
            closed = true
        }
    }
}
