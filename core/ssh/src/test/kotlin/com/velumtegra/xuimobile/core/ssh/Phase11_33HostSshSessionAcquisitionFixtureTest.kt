package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyPairGenerator
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
 * Host-only Phase 11.33 witness: exactly one synthetic fixture authentication, zero remote commands.
 * It never launches a host shell/process and is reachable from Android only through USB adb reverse.
 */
class Phase11_33HostSshSessionAcquisitionFixtureTest {
    @Test
    fun `fixture accepts one exact authentication and no command dispatch`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 11.33 fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )
        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is
                HostKeyFingerprintParseResult.Valid,
        ) { "Phase 11.33 fixture host fingerprint is not canonical SHA-256" }

        val exactAuthAttempts = AtomicInteger(0)
        val unexpectedAuthAttempts = AtomicInteger(0)
        val commandRequests = AtomicInteger(0)

        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator =
                org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
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
                RejectingCommand(
                    fixtureDir = fixtureDir,
                    command = command,
                    commandRequests = commandRequests,
                )
            }
        }

        try {
            server.start()
            check(server.port in 1..65535) { "Phase 11.33 fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\nexpectedAuth=1\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals("Phase 11.33 must authenticate exactly once", 1, exactAuthAttempts.get())
            assertEquals("Phase 11.33 must never try another credential", 0, unexpectedAuthAttempts.get())
            assertEquals("Phase 11.33 must dispatch zero remote commands", 0, commandRequests.get())
            assertFalse(
                "No unexpected command may reach the fixture",
                Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)),
            )
        } finally {
            runCatching { server.stop() }
        }
    }

    private class RejectingCommand(
        private val fixtureDir: Path,
        private val command: String,
        private val commandRequests: AtomicInteger,
    ) : Command {
        private var error: OutputStream? = null
        private var exitCallback: ExitCallback? = null

        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) = Unit
        override fun setErrorStream(error: OutputStream) { this.error = error }
        override fun setExitCallback(callback: ExitCallback) { exitCallback = callback }

        override fun start(channel: ChannelSession, env: Environment) {
            val request = commandRequests.incrementAndGet()
            writeAtomic(
                fixtureDir.resolve(UNEXPECTED_COMMAND_FILE),
                "request=$request\ncommand=${sanitize(command)}\n",
            )
            error?.write("Phase 11.33 rejects all remote commands\n".toByteArray(StandardCharsets.UTF_8))
            error?.flush()
            exitCallback?.onExit(126)
        }

        override fun destroy(channel: ChannelSession) = Unit
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(READY_FILE, UNEXPECTED_AUTH_FILE, UNEXPECTED_COMMAND_FILE, RELEASE_FILE)
            .forEach { name -> runCatching { Files.deleteIfExists(fixtureDir.resolve(name)) } }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 11.33 runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE1133_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase1133"
        const val FIXTURE_PASSWORD = "VELUM-phase1133-test-only-password"

        const val READY_FILE = "ready.properties"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 240_000L
        const val POLL_INTERVAL_MILLIS = 50L

        fun sanitize(value: String): String =
            value.replace("\r", "?").replace("\n", "?").take(240)

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
