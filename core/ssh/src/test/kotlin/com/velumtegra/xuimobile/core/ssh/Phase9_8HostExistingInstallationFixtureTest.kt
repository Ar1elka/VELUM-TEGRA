package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyPairGenerator
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Host-only Phase 9.8 witness for the complete existing-installation action family.
 *
 * The fixture never launches a host shell/process. It accepts only byte-exact commands emitted by
 * the reviewed production compilers for the run-tag-derived exact scopes. Synthetic replies model
 * the remote state transitions; any fallback auth, unknown command or extra replay is recorded as a
 * hard acceptance failure.
 */
class Phase9_8HostExistingInstallationFixtureTest {
    @Test
    fun `host fixture witnesses exact phase9 recovery restart uninstall reinstall and no replay`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        val runTag = System.getenv(ENV_RUN_TAG)
        assumeTrue("Phase 9.8 fixture is opt-in", !fixtureDirValue.isNullOrBlank() && !runTag.isNullOrBlank())
        require(requireNotNull(runTag).matches(Regex("[a-f0-9]{12}"))) { "Phase 9.8 run tag is invalid" }

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val fixture = FixtureModel(runTag)
        val expected = expectedCommands(fixture)
        val expectedTotal = expected.values.sumOf { it.behaviors.size }
        check(expectedTotal == EXPECTED_COMMANDS) {
            "Phase 9.8 must witness exactly $EXPECTED_COMMANDS commands, built $expectedTotal"
        }

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 9.8 fixture host fingerprint is not canonical SHA-256" }

        val exactAuthAttempts = AtomicInteger(0)
        val unexpectedAuthAttempts = AtomicInteger(0)
        val observedCounts = ConcurrentHashMap<String, AtomicInteger>()
        val commandRequests = AtomicInteger(0)

        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                if (username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD) {
                    exactAuthAttempts.incrementAndGet()
                    true
                } else {
                    unexpectedAuthAttempts.incrementAndGet()
                    writeAtomic(fixtureDir.resolve(UNEXPECTED_AUTH_FILE), "username=${sanitize(username)}\n")
                    false
                }
            }
            commandFactory = CommandFactory { _, command ->
                FixtureCommand(
                    command = command,
                    fixtureDir = fixtureDir,
                    expected = expected,
                    observedCounts = observedCounts,
                    commandRequests = commandRequests,
                    expectedTotal = expectedTotal,
                )
            }
        }

        try {
            server.start()
            check(server.port in 1..65535) { "Phase 9.8 SSH fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\n" +
                    "fingerprint=$fingerprint\n" +
                    "expectedCommands=$expectedTotal\n" +
                    "expectedAuth=$EXPECTED_AUTH\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals("Phase 9.8 exact SSH authentication count changed", EXPECTED_AUTH, exactAuthAttempts.get())
            assertEquals("No fallback SSH credential may be attempted", 0, unexpectedAuthAttempts.get())
            assertEquals("Only the reviewed finite command set may be dispatched", expectedTotal, commandRequests.get())
            expected.forEach { (raw, spec) ->
                assertEquals(
                    "Reviewed command count mismatch for ${spec.label}",
                    spec.behaviors.size,
                    observedCounts[raw]?.get() ?: 0,
                )
            }
            assertFalse(
                "No unknown/over-dispatched command may reach the fixture",
                Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)),
            )
            writeAtomic(fixtureDir.resolve(COMPLETED_FILE), "commands=$expectedTotal\nauth=$EXPECTED_AUTH\n")
        } finally {
            runCatching { server.stop() }
        }
    }

    private class FixtureCommand(
        private val command: String,
        private val fixtureDir: Path,
        private val expected: Map<String, ExpectedCommand>,
        private val observedCounts: ConcurrentHashMap<String, AtomicInteger>,
        private val commandRequests: AtomicInteger,
        private val expectedTotal: Int,
    ) : Command {
        private var output: OutputStream? = null
        private var error: OutputStream? = null
        private var exitCallback: ExitCallback? = null
        private var worker: Thread? = null

        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) { this.output = output }
        override fun setErrorStream(error: OutputStream) { this.error = error }
        override fun setExitCallback(callback: ExitCallback) { exitCallback = callback }

        override fun start(channel: ChannelSession, env: Environment) {
            worker = thread(name = "phase9-8-existing-installation-fixture", isDaemon = true) {
                val requestNumber = commandRequests.incrementAndGet()
                val spec = expected[command]
                val count = observedCounts.computeIfAbsent(command) { AtomicInteger(0) }.incrementAndGet()
                val behavior = spec?.behaviors?.getOrNull(count - 1)
                if (spec == null || behavior == null) {
                    writeAtomic(
                        fixtureDir.resolve(UNEXPECTED_COMMAND_FILE),
                        "request=$requestNumber\ncount=$count\ncommand=${sanitize(command)}\n",
                    )
                    error?.write("rejected\n".toByteArray(StandardCharsets.UTF_8))
                    error?.flush()
                    exitCallback?.onExit(126)
                    return@thread
                }

                when (behavior) {
                    is FixtureBehavior.Reply -> {
                        if (behavior.stdout.isNotEmpty()) {
                            output?.write(behavior.stdout.toByteArray(StandardCharsets.UTF_8))
                            output?.flush()
                        }
                        exitCallback?.onExit(behavior.exitCode)
                    }
                    FixtureBehavior.CloseWithoutExit -> {
                        // Accepted exec without exit-status. Production must classify this as
                        // DISPATCHED + Unknown and may never replay the mutating command.
                        channel.close(true)
                    }
                }

                if (requestNumber == expectedTotal && expected.all { (raw, expectedSpec) ->
                        observedCounts[raw]?.get() == expectedSpec.behaviors.size
                    }
                ) {
                    writeAtomic(fixtureDir.resolve(OBSERVED_FILE), "commands=$requestNumber\n")
                }
            }
        }

        override fun destroy(channel: ChannelSession) {
            worker?.interrupt()
            worker = null
        }
    }

    private sealed interface FixtureBehavior {
        data class Reply(val exitCode: Int = 0, val stdout: String = "") : FixtureBehavior
        data object CloseWithoutExit : FixtureBehavior
    }

    private data class ExpectedCommand(
        var label: String,
        val behaviors: MutableList<FixtureBehavior>,
    )

    private data class FixtureModel(
        val runTag: String,
        val serverId: ServerId = ServerId("phase98-server-$runTag"),
        val accessId: ServerAccessId = ServerAccessId("phase98-access-$runTag"),
        val installationId: XuiInstallationId = XuiInstallationId("phase98-installation-$runTag"),
        val managedInstallId: ManagedInstallId = ManagedInstallId(MANAGED_INSTALL_ID),
    ) {
        val installation = XuiInstallation(
            id = installationId,
            serverId = serverId,
            ownership = InstallationOwnership.MANAGED,
            identity = InstallationIdentity(
                serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                managedInstallId = managedInstallId,
            ),
            baseline = InstallationBaseline(
                serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                panelPort = INITIAL_PANEL_PORT,
                webBasePath = INITIAL_WEB_BASE_PATH,
                listenAddress = LOOPBACK_HOST,
                capturedAt = FIXED_NOW.minusSeconds(600),
            ),
        )
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint(LOOPBACK_HOST, 22),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.Password(SecretId("phase98-host-only-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase98-host-only"),
        )

        fun operation(action: OperationType, label: String): VersionedOperationSnapshot = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = OperationId("phase98-$label-$runTag"),
                type = action,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, FIXED_NOW.minusSeconds(10)),
                startedAt = FIXED_NOW.minusSeconds(60),
                updatedAt = FIXED_NOW.minusSeconds(10),
            ),
            OperationRevision(0),
        )
    }

    private fun expectedCommands(fixture: FixtureModel): Map<String, ExpectedCommand> {
        val result = linkedMapOf<String, ExpectedCommand>()

        fun add(raw: String, label: String, behavior: FixtureBehavior = FixtureBehavior.Reply()) {
            val prior = result[raw]
            if (prior == null) {
                result[raw] = ExpectedCommand(label, mutableListOf(behavior))
            } else {
                prior.label = "${prior.label}+$label"
                prior.behaviors += behavior
            }
        }

        fun command(probe: ManagementProbeSpec): String =
            ((ManagementReadOnlyCommandCompiler.compile(probe) as? CompiledManagementProbe.Command)
                ?: error("Phase 9.8 management probe did not compile: $probe"))
                .command.rawForTransport()

        fun addPresence(installation: XuiInstallation, label: String, present: Boolean) {
            val behavior = if (present) FixtureBehavior.Reply() else FixtureBehavior.Reply(exitCode = 1)
            add(command(ManagementProbeSpec.ServiceUnitPresence(installation.identity.serviceUnit)), "$label-service", behavior)
            add(command(ManagementProbeSpec.ExactPathPresence(ManagementPathKind.BINARY, installation.identity.binaryPath)), "$label-binary", behavior)
            add(command(ManagementProbeSpec.ExactPathPresence(ManagementPathKind.ROOT, installation.identity.rootPath)), "$label-root", behavior)
            add(command(ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, installation.identity.databasePath)), "$label-database", behavior)
        }

        fun addHealthyPostVerify(label: String) {
            addPresence(fixture.installation, label, present = true)
            add(
                command(ManagementProbeSpec.ServiceLiveState(fixture.installation.identity.serviceUnit)),
                "$label-service-state",
                FixtureBehavior.Reply(stdout = "active\n"),
            )
            add(
                command(
                    ManagementProbeSpec.ExactListenerPresence(
                        expectedPort = fixture.installation.baseline.panelPort,
                        expectedListenAddress = fixture.installation.baseline.listenAddress,
                    ),
                ),
                "$label-listener",
            )
            add(restartMarkerCommand(), "$label-managed-marker", FixtureBehavior.Reply(stdout = ManagedInstallMarkerProtocol.encode(fixture.managedInstallId)))
        }

        // 1) RECOVERY: exact read-only diagnosis -> one reviewed start-service repair -> reconnect -> read-only verify.
        val recovery = fixture.operation(OperationType.RECOVERY, "recovery")
        val recoveryPreflight = verifiedPreflight(recovery, fixture.installation, fixture.access, FIXED_NOW)
        addPresence(fixture.installation, "recovery-diagnosis", present = true)
        add(
            command(ManagementProbeSpec.ServiceLiveState(fixture.installation.identity.serviceUnit)),
            "recovery-diagnosis-service-state",
            FixtureBehavior.Reply(stdout = "inactive\n"),
        )
        add(
            command(
                ManagementProbeSpec.ExactListenerPresence(
                    expectedPort = fixture.installation.baseline.panelPort,
                    expectedListenAddress = fixture.installation.baseline.listenAddress,
                ),
            ),
            "recovery-diagnosis-listener-absent",
            FixtureBehavior.Reply(exitCode = 1),
        )
        val recoveryEvidence = ExistingInstallationRecoveryEvidence(
            scope = recoveryPreflight.evidence.scope,
            diagnosis = ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT,
            serviceState = ManagementServiceState.INACTIVE,
            observedAt = FIXED_NOW,
            validUntil = FIXED_NOW.plusSeconds(30),
        )
        val recoveryRepair = (ExistingInstallationRecoveryRepairPolicy.authorize(recoveryPreflight, recoveryEvidence, FIXED_NOW)
            as ExistingInstallationRecoveryRepairPolicyResult.Verified).repair
        add(
            requireNotNull(ExistingInstallationRecoveryCommandCompiler.compile(recoveryRepair)).command.rawForTransport(),
            "recovery-start-exact-service",
        )
        addHealthyPostVerify("recovery-postverify")

        // 2) RESTART success: command exit is not success; a fresh reconnect/read-back is still required.
        val restart = fixture.operation(OperationType.RESTART, "restart-success")
        val restartPreflight = verifiedPreflight(restart, fixture.installation, fixture.access, FIXED_NOW)
        val restartPlan = ReviewedExistingInstallationActionPlanPolicy.build(restartPreflight)
        add(
            requireNotNull(ExistingInstallationRestartCommandCompiler.compile(restartPreflight, restartPlan)).command.rawForTransport(),
            "restart-success-dispatch",
        )
        addHealthyPostVerify("restart-success-postverify")

        // 3) RESTART uncertainty: the one accepted restart has no exit-status. The recovery path may
        // only reconnect and read back; the restart command itself must not be replayed.
        val uncertainRestart = fixture.operation(OperationType.RESTART, "restart-uncertain")
        val uncertainPreflight = verifiedPreflight(uncertainRestart, fixture.installation, fixture.access, FIXED_NOW)
        val uncertainPlan = ReviewedExistingInstallationActionPlanPolicy.build(uncertainPreflight)
        add(
            requireNotNull(ExistingInstallationRestartCommandCompiler.compile(uncertainPreflight, uncertainPlan)).command.rawForTransport(),
            "restart-uncertain-dispatch",
            FixtureBehavior.CloseWithoutExit,
        )
        addHealthyPostVerify("restart-uncertain-postverify")

        // Wrong-owner and durable-barrier scenarios intentionally contribute zero commands. Their
        // SSH authentications are still counted independently and the device must reject/block before exec.

        // 4) UNINSTALL: one exact destructive command, then complete bounded absence proof.
        val uninstall = fixture.operation(OperationType.UNINSTALL, "uninstall")
        val uninstallPreflight = verifiedPreflight(uninstall, fixture.installation, fixture.access, FIXED_NOW)
        val uninstallPlan = ReviewedExistingInstallationActionPlanPolicy.build(uninstallPreflight)
        add(
            requireNotNull(ExistingInstallationUninstallCommandCompiler.compile(uninstallPreflight, uninstallPlan)).command.rawForTransport(),
            "uninstall-dispatch",
        )
        addPresence(fixture.installation, "uninstall-absence", present = false)
        add(
            command(
                ManagementProbeSpec.ExactListenerPresence(
                    expectedPort = fixture.installation.baseline.panelPort,
                    expectedListenAddress = fixture.installation.baseline.listenAddress,
                ),
            ),
            "uninstall-listener-absence",
            FixtureBehavior.Reply(exitCode = 1),
        )
        add(
            "[ -x ${ExistingInstallationUninstallCommandCompiler.STANDARD_MENU_PATH} ]",
            "uninstall-menu-absence",
            FixtureBehavior.Reply(exitCode = 1),
        )

        // 5) MANAGED REINSTALL: exact five-step compound mutation then read-only worker/marker/facts.
        val reinstall = fixture.operation(OperationType.REINSTALL, "reinstall")
        val reinstallPreflight = verifiedPreflight(reinstall, fixture.installation, fixture.access, FIXED_NOW)
        val reinstallPlan = ReviewedExistingInstallationActionPlanPolicy.build(reinstallPreflight)
        val compiledReinstall = requireNotNull(ExistingInstallationReinstallCommandCompiler.compile(reinstallPreflight, reinstallPlan))
        check(compiledReinstall.steps.size == 5) { "Phase 9.8 reinstall must compile exactly five steps" }
        compiledReinstall.steps.forEach { step -> add(step.command.rawForTransport(), "reinstall-${step.kind}") }
        add(
            reinstallWorkerReadback(compiledReinstall.workerScope),
            "reinstall-worker-postverify",
            FixtureBehavior.Reply(stdout = "PROCESS=DEAD\nHEARTBEAT=NONE\nTERMINAL=SUCCESS\n"),
        )
        add(
            reinstallMarkerCommand(),
            "reinstall-marker-postverify",
            FixtureBehavior.Reply(stdout = ManagedInstallMarkerProtocol.encode(fixture.managedInstallId)),
        )
        add(
            requireNotNull(InstallerPostInstallReadOnlyCompiler.installationFacts(compiledReinstall.workerScope)).rawForTransport(),
            "reinstall-facts-postverify",
            FixtureBehavior.Reply(
                stdout = "SERVICE_PRESENT=1\n" +
                    "BINARY_PRESENT=1\n" +
                    "ROOT_PRESENT=1\n" +
                    "DATABASE_PRESENT=1\n" +
                    "SERVICE_STATE=active\n" +
                    "PORT=$REINSTALLED_PANEL_PORT\n" +
                    "WEB_BASE_PATH=$REINSTALLED_WEB_BASE_PATH\n" +
                    "LISTEN_ADDRESS=$LOOPBACK_HOST\n" +
                    "LISTENER_PRESENT=1\n",
            ),
        )

        return result
    }

    private fun restartMarkerCommand(): String {
        val path = shellQuote(ManagedInstallMarkerProtocol.MARKER_PATH)
        return "if [ -f $path ]; then cat -- $path; else exit 44; fi"
    }

    private fun reinstallMarkerCommand(): String {
        val path = ManagedInstallMarkerProtocol.MARKER_PATH
        return "if [ -f ${shellQuote(path)} ]; then cat -- ${shellQuote(path)}; else exit 44; fi"
    }

    private fun reinstallWorkerReadback(scope: InstallerWorkerScope): String {
        val work = requireNotNull(ExistingInstallationReinstallCommandCompiler.workerDirectory(scope))
        return """
            set -eu
            work=${shellQuote(work)}
            [ -d "${'$'}work" ] || exit 44
            terminal=NONE
            if [ -f "${'$'}work/terminal" ]; then
                terminal=${'$'}(cat -- "${'$'}work/terminal" 2>/dev/null || true)
                case "${'$'}terminal" in SUCCESS|FAILED:[0-9]*) ;; *) terminal=UNKNOWN ;; esac
            fi
            heartbeat=NONE
            if [ -f "${'$'}work/heartbeat" ]; then
                heartbeat=${'$'}(cat -- "${'$'}work/heartbeat" 2>/dev/null || true)
                case "${'$'}heartbeat" in ''|*[!0-9]*) heartbeat=INVALID ;; esac
            fi
            process=UNKNOWN
            if [ -f "${'$'}work/pid" ]; then
                pid=${'$'}(cat -- "${'$'}work/pid" 2>/dev/null || true)
                case "${'$'}pid" in ''|*[!0-9]*) process=UNKNOWN ;; *) if kill -0 "${'$'}pid" 2>/dev/null; then process=ALIVE; else process=DEAD; fi ;; esac
            fi
            printf 'PROCESS=%s\nHEARTBEAT=%s\nTERMINAL=%s\n' "${'$'}process" "${'$'}heartbeat" "${'$'}terminal"
        """.trimIndent()
    }

    private fun verifiedPreflight(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        access: ServerAccess,
        now: Instant,
    ): VerifiedExistingInstallationActionPreflight {
        val proof = InstallationProof(
            id = TargetProofId("phase98-proof-${current.snapshot.operationId.value}"),
            installationId = installation.id,
            serverId = installation.serverId,
            serverAccessId = access.id,
            observedIdentity = installation.identity,
            observedAt = now.minusSeconds(3),
            validUntil = now.plusSeconds(600),
        )
        val verifiedTarget = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now)
            as TargetVerificationResult.Verified).target
        val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, verifiedTarget, now)
            as ExistingInstallationActionAuthorizationResult.Verified).authorization
        val evidence = ExistingInstallationPreflightEvidence(
            scope = ExistingInstallationActionScope(
                operationId = current.snapshot.operationId,
                operationRevision = current.revision.value,
                serverId = installation.serverId,
                serverAccessId = access.id,
                installationId = installation.id,
                action = current.snapshot.type,
                ownership = installation.ownership,
                managedInstallId = installation.identity.managedInstallId,
            ),
            installationProof = proof,
            accessPathState = ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
            layoutCapability = ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
            privilegeCapability = ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
            mutationBarrierState = ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
            observedAt = now.minusSeconds(2),
            validUntil = now.plusSeconds(300),
        )
        return (ExistingInstallationActionPreflightPolicy.verify(authorization, current, installation, evidence, now)
            as ExistingInstallationActionPreflightResult.Verified).preflight
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(
            READY_FILE,
            OBSERVED_FILE,
            COMPLETED_FILE,
            UNEXPECTED_AUTH_FILE,
            UNEXPECTED_COMMAND_FILE,
            RELEASE_FILE,
        ).forEach { name -> runCatching { Files.deleteIfExists(fixtureDir.resolve(name)) } }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 9.8 runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE98_FIXTURE_DIR"
        const val ENV_RUN_TAG = "VELUM_PHASE98_RUN_TAG"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase98"
        const val FIXTURE_PASSWORD = "VELUM-phase98-test-only-password"
        const val MANAGED_INSTALL_ID = "v1-0123456789abcdef0123456789abcdef"
        const val INITIAL_PANEL_PORT = 2053
        const val INITIAL_WEB_BASE_PATH = "/panel/"
        const val REINSTALLED_PANEL_PORT = 24443
        const val REINSTALLED_WEB_BASE_PATH = "/phase98-reinstalled/"
        const val EXPECTED_COMMANDS = 45
        const val EXPECTED_AUTH = 12
        const val READY_FILE = "ready.properties"
        const val OBSERVED_FILE = "phase9.observed"
        const val COMPLETED_FILE = "phase9.completed"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 300_000L
        const val POLL_INTERVAL_MILLIS = 50L
        val FIXED_NOW: Instant = Instant.parse("2026-09-14T15:00:00Z")

        fun sanitize(value: String): String = value.replace("\r", "?").replace("\n", "?").take(320)

        fun writeAtomic(path: Path, text: String) {
            val temporary = path.resolveSibling(path.fileName.toString() + ".tmp")
            Files.write(temporary, text.toByteArray(StandardCharsets.UTF_8))
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: Exception) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}
