package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeSpec
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyPairGenerator
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
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
 * Host-only deterministic SSH fixture for the opt-in Phase 5.7 Android acceptance gate.
 *
 * The server never invokes a host shell or process. It accepts only the exact production Discovery
 * command strings compiled from [DiscoveryProbePlan], returns synthetic read-only observations and
 * fails if any unknown/duplicate command or fallback credential is attempted.
 */
class Phase5_7HostSshDiscoveryFixtureTest {
    @Test
    fun `host fixture observes one exact allowlisted read only discovery plan`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 5.7 host fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val responses = expectedResponses()
        check(responses.size == DiscoveryProbePlan.initialProbes.size) {
            "Phase 5.7 fixture command map must be one-to-one with DiscoveryProbePlan"
        }

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 5.7 fixture host fingerprint is not canonical SHA-256" }

        val exactAuthAttempts = AtomicInteger(0)
        val unexpectedAuthAttempts = AtomicInteger(0)
        val seenCommands = ConcurrentHashMap.newKeySet<String>()
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
                    writeAtomic(
                        fixtureDir.resolve(UNEXPECTED_AUTH_FILE),
                        "username=${sanitize(username)}\n",
                    )
                    false
                }
            }
            commandFactory = CommandFactory { _, command ->
                Phase5_7FixtureCommand(
                    command = command,
                    fixtureDir = fixtureDir,
                    responses = responses,
                    seenCommands = seenCommands,
                    commandRequests = commandRequests,
                )
            }
        }

        try {
            server.start()
            check(server.port in 1..65535) { "Phase 5.7 host fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\nexpectedCommands=${responses.size}\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals(
                "Phase 5.7 must authenticate exactly one exact production SSH session",
                1,
                exactAuthAttempts.get(),
            )
            assertEquals(
                "Phase 5.7 must not attempt any fallback/poison credential",
                0,
                unexpectedAuthAttempts.get(),
            )
            assertEquals(
                "Phase 5.7 must execute exactly the finite reviewed Discovery probe count",
                responses.size,
                commandRequests.get(),
            )
            assertEquals(
                "Every reviewed Discovery command must be observed exactly once",
                responses.keys,
                seenCommands,
            )
            assertFalse(
                "No unexpected command may reach the host fixture",
                Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)),
            )
        } finally {
            runCatching { server.stop() }
        }
    }

    private class Phase5_7FixtureCommand(
        private val command: String,
        private val fixtureDir: Path,
        private val responses: Map<String, FixtureResponse>,
        private val seenCommands: MutableSet<String>,
        private val commandRequests: AtomicInteger,
    ) : Command {
        private var output: OutputStream? = null
        private var error: OutputStream? = null
        private var exitCallback: ExitCallback? = null

        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) {
            this.output = output
        }
        override fun setErrorStream(error: OutputStream) {
            this.error = error
        }
        override fun setExitCallback(callback: ExitCallback) {
            exitCallback = callback
        }

        override fun start(channel: ChannelSession, env: Environment) {
            val requestNumber = commandRequests.incrementAndGet()
            val response = responses[command]
            if (response == null || !seenCommands.add(command)) {
                writeAtomic(
                    fixtureDir.resolve(UNEXPECTED_COMMAND_FILE),
                    "request=$requestNumber\ncommand=${sanitize(command)}\n",
                )
                error?.write("rejected\n".toByteArray(StandardCharsets.UTF_8))
                error?.flush()
                exitCallback?.onExit(126)
                return
            }

            if (response.stdout.isNotEmpty()) {
                output?.write(response.stdout.toByteArray(StandardCharsets.UTF_8))
                output?.flush()
            }
            exitCallback?.onExit(response.exitCode)

            if (seenCommands.size == responses.size) {
                writeAtomic(
                    fixtureDir.resolve(COMPLETED_FILE),
                    "commands=${seenCommands.size}\n",
                )
            }
        }

        override fun destroy(channel: ChannelSession) = Unit
    }

    private data class FixtureResponse(
        val exitCode: Int,
        val stdout: String = "",
    )

    private fun expectedResponses(): Map<String, FixtureResponse> {
        val result = linkedMapOf<String, FixtureResponse>()
        DiscoveryProbePlan.initialProbes.forEach { probe ->
            val compiled = requireNotNull(DiscoveryReadOnlyCommandCompiler.compile(probe)) {
                "Canonical Discovery probe unexpectedly failed compilation"
            }
            val raw = compiled.command.rawForTransport()
            check(raw == independentlyExpectedRaw(probe)) {
                "Production Discovery compiler changed outside the independently reviewed read-only fixture contract"
            }
            val response = when (probe) {
                is DiscoveryProbeSpec.PlatformRelease -> FixtureResponse(
                    exitCode = 0,
                    stdout = "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
                )
                is DiscoveryProbeSpec.ServiceUnitPresence -> FixtureResponse(
                    exitCode = if (probe.serviceUnit == "x-ui.service") 0 else 1,
                )
                is DiscoveryProbeSpec.InstallationPathPresence -> FixtureResponse(
                    exitCode = if (isCanonicalSupportedIdentityPath(probe.pathKind, probe.path)) 0 else 1,
                )
                is DiscoveryProbeSpec.ForeignPanelPathMarker -> FixtureResponse(exitCode = 1)
            }
            check(result.put(raw, response) == null) { "Discovery probe compiler emitted a duplicate raw command" }
        }
        return result
    }


    private fun independentlyExpectedRaw(probe: DiscoveryProbeSpec): String = when (probe) {
        is DiscoveryProbeSpec.PlatformRelease -> "cat -- /etc/os-release"
        is DiscoveryProbeSpec.ServiceUnitPresence ->
            "state=\$(systemctl show --property=LoadState --value -- '${probe.serviceUnit}' 2>/dev/null) || exit 2; [ \"\$state\" != \"not-found\" ]"
        is DiscoveryProbeSpec.InstallationPathPresence -> {
            val predicate = when (probe.pathKind) {
                DiscoveryPathKind.BINARY -> "-x"
                DiscoveryPathKind.ROOT -> "-d"
                DiscoveryPathKind.DATABASE -> "-f"
            }
            "[ $predicate '${probe.path}' ]"
        }
        is DiscoveryProbeSpec.ForeignPanelPathMarker -> "[ -e '${probe.path}' ]"
    }

    private fun isCanonicalSupportedIdentityPath(kind: DiscoveryPathKind, path: String): Boolean = when (kind) {
        DiscoveryPathKind.BINARY -> path == "/usr/local/x-ui/x-ui"
        DiscoveryPathKind.ROOT -> path == "/usr/local/x-ui"
        DiscoveryPathKind.DATABASE -> path == "/etc/x-ui/x-ui.db"
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(
            READY_FILE,
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
        throw AssertionError("Timed out waiting for Phase 5.7 runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE57_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase57"
        const val FIXTURE_PASSWORD = "VELUM-phase57-test-only-password"

        const val READY_FILE = "ready.properties"
        const val COMPLETED_FILE = "discovery.completed"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"

        const val RELEASE_TIMEOUT_MILLIS = 180_000L
        const val POLL_INTERVAL_MILLIS = 50L

        fun sanitize(value: String): String = value
            .replace("\r", "?")
            .replace("\n", "?")
            .take(160)

        fun writeAtomic(path: Path, text: String) {
            val temporary = path.resolveSibling(path.fileName.toString() + ".tmp")
            Files.write(temporary, text.toByteArray(StandardCharsets.UTF_8))
            try {
                Files.move(
                    temporary,
                    path,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: Exception) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}
