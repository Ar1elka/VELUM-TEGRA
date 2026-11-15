package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.InstallerWorkerLivenessPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.ReviewedInstallPlanPolicy
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallerPlanStep
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ReviewedInstallPlan
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
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
 * Host-only Phase 8.6 Installer witness.
 *
 * No host shell or child process is launched. The SSH server accepts only byte-exact commands
 * produced by the reviewed production compilers for the run-tag-derived scopes below. Unknown or
 * over-dispatched commands, fallback credentials and any extra replay are recorded as failures.
 */
class Phase8_6HostInstallerFixtureTest {
    @Test
    fun `host fixture witnesses finite installer flow uncertainty liveness and exact ownership`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        val runTag = System.getenv(ENV_RUN_TAG)
        assumeTrue("Phase 8.6 fixture is opt-in", !fixtureDirValue.isNullOrBlank() && !runTag.isNullOrBlank())
        require(requireNotNull(runTag).matches(Regex("[a-f0-9]{12}"))) { "Phase 8.6 run tag is invalid" }

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val scopes = scopes(runTag)
        val expected = expectedCommands(scopes)
        val expectedTotal = expected.values.sumOf { it.expectedCount }
        check(expectedTotal == EXPECTED_COMMANDS) { "Phase 8.6 must witness exactly $EXPECTED_COMMANDS commands" }

        // Independent witness: post-verify readback has no phase/progress field and can treat a fresh
        // heartbeat as liveness even when the process state is UNKNOWN.
        val heartbeatCommand = requireNotNull(InstallerPostInstallReadOnlyCompiler.workerEvidence(scopes.heartbeatOnly))
            .rawForTransport()
        check("heartbeat" in heartbeatCommand && "terminal" in heartbeatCommand && "pid" in heartbeatCommand)
        check("phase" !in heartbeatCommand.lowercase() && "progress" !in heartbeatCommand.lowercase())
        val heartbeatEvidence = InstallerPostInstallParsers.parseWorkerEvidence(
            scopes.heartbeatOnly,
            "PROCESS=UNKNOWN\nHEARTBEAT=${FIXED_NOW.minusSeconds(5).epochSecond}\nTERMINAL=NONE\n",
            FIXED_NOW,
        ) ?: error("Heartbeat-only evidence parser rejected canonical fixture evidence")
        check(
            InstallerWorkerLivenessPolicy.classify(scopes.heartbeatOnly, heartbeatEvidence, FIXED_NOW) ==
                com.velumtegra.xuimobile.core.model.InstallerWorkerLiveness.KnownAlive,
        ) { "Fresh independent heartbeat must classify as KnownAlive" }

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 8.6 fixture host fingerprint is not canonical SHA-256" }

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
            check(server.port in 1..65535) { "Phase 8.6 SSH fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\n" +
                    "fingerprint=$fingerprint\n" +
                    "expectedCommands=$expectedTotal\n" +
                    "expectedAuth=$EXPECTED_AUTH\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals("Five exact operation-owned SSH sessions are expected", EXPECTED_AUTH, exactAuthAttempts.get())
            assertEquals("No fallback SSH credential may be attempted", 0, unexpectedAuthAttempts.get())
            assertEquals("Only the reviewed finite command set may be dispatched", expectedTotal, commandRequests.get())
            expected.forEach { (raw, spec) ->
                assertEquals(
                    "Reviewed command count mismatch for ${spec.label}",
                    spec.expectedCount,
                    observedCounts[raw]?.get() ?: 0,
                )
            }
            assertFalse("No unknown/over-dispatched command may reach the fixture", Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)))
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
            worker = thread(name = "phase8-6-installer-fixture", isDaemon = true) {
                val requestNumber = commandRequests.incrementAndGet()
                val spec = expected[command]
                val count = observedCounts.computeIfAbsent(command) { AtomicInteger(0) }.incrementAndGet()
                if (spec == null || count > spec.expectedCount) {
                    writeAtomic(
                        fixtureDir.resolve(UNEXPECTED_COMMAND_FILE),
                        "request=$requestNumber\ncount=$count\ncommand=${sanitize(command)}\n",
                    )
                    error?.write("rejected\n".toByteArray(StandardCharsets.UTF_8))
                    error?.flush()
                    exitCallback?.onExit(126)
                    return@thread
                }

                when (val behavior = spec.behavior) {
                    is FixtureBehavior.Reply -> {
                        if (behavior.stdout.isNotEmpty()) {
                            output?.write(behavior.stdout.toByteArray(StandardCharsets.UTF_8))
                            output?.flush()
                        }
                        exitCallback?.onExit(behavior.exitCode)
                    }
                    FixtureBehavior.CloseWithoutExit -> {
                        // The exec request was accepted, but no exit-status is sent. Production must
                        // classify this as DISPATCHED + Unknown and must never replay the mutation.
                        channel.close(true)
                    }
                }

                if (requestNumber == expectedTotal && expected.all { (raw, expectedSpec) ->
                        observedCounts[raw]?.get() == expectedSpec.expectedCount
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
        val label: String,
        val expectedCount: Int,
        val behavior: FixtureBehavior,
    )

    private data class FixtureScopes(
        val success: InstallerWorkerScope,
        val uncertain: InstallerWorkerScope,
        val staleUnknown: InstallerWorkerScope,
        val heartbeatOnly: InstallerWorkerScope,
        val wrongOwnerPlan: InstallerWorkerScope,
    )

    private fun scopes(runTag: String): FixtureScopes {
        val serverId = ServerId("phase86-server-$runTag")
        val accessId = ServerAccessId("phase86-access-$runTag")
        fun scope(label: String): InstallerWorkerScope {
            val operationId = OperationId("phase86-$label-$runTag")
            return InstallerWorkerScope(
                operationId = operationId,
                serverId = serverId,
                serverAccessId = accessId,
                managedInstallId = ManagedInstallIdentityPolicy.forOperation(operationId),
            )
        }
        return FixtureScopes(
            success = scope("success"),
            uncertain = scope("uncertain"),
            staleUnknown = scope("unknown"),
            heartbeatOnly = scope("heartbeat"),
            wrongOwnerPlan = scope("wrong-owner-plan"),
        )
    }

    private fun expectedCommands(scopes: FixtureScopes): Map<String, ExpectedCommand> {
        val result = linkedMapOf<String, ExpectedCommand>()

        fun add(raw: String, label: String, behavior: FixtureBehavior = FixtureBehavior.Reply()) {
            val prior = result[raw]
            if (prior == null) {
                result[raw] = ExpectedCommand(label, 1, behavior)
            } else {
                check(prior.behavior == behavior) { "Same reviewed command cannot have conflicting fixture behavior" }
                result[raw] = prior.copy(expectedCount = prior.expectedCount + 1, label = "${prior.label}+$label")
            }
        }

        val successPlan = canonicalPlan(scopes.success)
        val successCompiled = requireNotNull(InstallerReviewedCommandCompiler.compile(successPlan))
        successCompiled.steps.forEach { step -> add(step.command.rawForTransport(), "success-${step.kind}") }
        val marker = ManagedInstallMarkerProtocol.encode(scopes.success.managedInstallId)
        add(
            requireNotNull(InstallerReviewedCommandCompiler.compileMarkerReadback(successPlan)).command.rawForTransport(),
            "success-marker-after-mutation",
            FixtureBehavior.Reply(stdout = marker),
        )
        add(
            requireNotNull(InstallerPostInstallReadOnlyCompiler.workerEvidence(scopes.success)).rawForTransport(),
            "success-worker-terminal",
            FixtureBehavior.Reply(stdout = "PROCESS=DEAD\nHEARTBEAT=NONE\nTERMINAL=SUCCESS\n"),
        )
        add(
            InstallerPostInstallReadOnlyCompiler.managedMarker().rawForTransport(),
            "success-marker-post-verify",
            FixtureBehavior.Reply(stdout = marker),
        )
        add(
            requireNotNull(InstallerPostInstallReadOnlyCompiler.installationFacts(scopes.success)).rawForTransport(),
            "success-installation-facts",
            FixtureBehavior.Reply(
                stdout = "SERVICE_PRESENT=1\n" +
                    "BINARY_PRESENT=1\n" +
                    "ROOT_PRESENT=1\n" +
                    "DATABASE_PRESENT=1\n" +
                    "SERVICE_STATE=active\n" +
                    "PORT=$PANEL_PORT\n" +
                    "WEB_BASE_PATH=$WEB_BASE_PATH\n" +
                    "LISTEN_ADDRESS=\n" +
                    "LISTENER_PRESENT=1\n",
            ),
        )

        val uncertainPlan = canonicalPlan(scopes.uncertain)
        val uncertainCompiled = requireNotNull(InstallerReviewedCommandCompiler.compile(uncertainPlan))
        check(uncertainCompiled.steps.size == 4)
        add(uncertainCompiled.steps[0].command.rawForTransport(), "uncertain-prepare")
        add(
            uncertainCompiled.steps[1].command.rawForTransport(),
            "uncertain-fetch-no-exit",
            FixtureBehavior.CloseWithoutExit,
        )

        add(
            requireNotNull(InstallerPostInstallReadOnlyCompiler.workerEvidence(scopes.staleUnknown)).rawForTransport(),
            "stale-heartbeat-unknown",
            FixtureBehavior.Reply(
                stdout = "PROCESS=UNKNOWN\nHEARTBEAT=${FIXED_NOW.minusSeconds(30).epochSecond}\nTERMINAL=NONE\n",
            ),
        )
        add(
            requireNotNull(InstallerPostInstallReadOnlyCompiler.workerEvidence(scopes.heartbeatOnly)).rawForTransport(),
            "fresh-heartbeat-known-alive",
            FixtureBehavior.Reply(
                stdout = "PROCESS=UNKNOWN\nHEARTBEAT=${FIXED_NOW.minusSeconds(5).epochSecond}\nTERMINAL=NONE\n",
            ),
        )

        // wrongOwnerPlan intentionally contributes zero commands: the device must reject its exact
        // session binding before any remote dispatch.
        canonicalPlan(scopes.wrongOwnerPlan).also { check(ReviewedInstallPlanPolicy.isCanonical(it)) }
        return result
    }

    private fun canonicalPlan(scope: InstallerWorkerScope): ReviewedInstallPlan {
        val capability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1
        return ReviewedInstallPlan(
            scope = scope,
            capability = capability,
            steps = listOf(
                InstallerPlanStep.PrepareWorker(ReviewedInstallPlanPolicy.PREPARE_WORKER_TIMEOUT),
                InstallerPlanStep.FetchReviewedInstaller(capability, ReviewedInstallPlanPolicy.FETCH_INSTALLER_TIMEOUT),
                InstallerPlanStep.ExecuteReviewedInstaller(capability, ReviewedInstallPlanPolicy.EXECUTE_INSTALLER_TIMEOUT),
                InstallerPlanStep.WriteManagedMarker(scope.managedInstallId, ReviewedInstallPlanPolicy.WRITE_MARKER_TIMEOUT),
            ),
        ).also { check(ReviewedInstallPlanPolicy.isCanonical(it)) }
    }

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
        throw AssertionError("Timed out waiting for Phase 8.6 runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE86_FIXTURE_DIR"
        const val ENV_RUN_TAG = "VELUM_PHASE86_RUN_TAG"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase86"
        const val FIXTURE_PASSWORD = "VELUM-phase86-test-only-password"
        const val PANEL_PORT = 23456
        const val WEB_BASE_PATH = "/phase86/"
        const val EXPECTED_COMMANDS = 12
        const val EXPECTED_AUTH = 5
        const val READY_FILE = "ready.properties"
        const val OBSERVED_FILE = "installer.observed"
        const val COMPLETED_FILE = "installer.completed"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 300_000L
        const val POLL_INTERVAL_MILLIS = 50L
        val FIXED_NOW: Instant = Instant.parse("2026-09-12T08:00:00Z")

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
