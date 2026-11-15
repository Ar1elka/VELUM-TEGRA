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
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Host-side test-only SSH witness for Phase 4.6G.
 *
 * It binds JVM loopback only and exists solely while the opt-in PowerShell runner is alive. The
 * server accepts one fixed test credential, but the Android acceptance intentionally must never
 * authenticate successfully: one case has an exact wrong host pin and one has an exact wrong
 * password. A missing-secret case must not reach TCP at all. Any successful authentication or exec
 * request therefore witnesses forbidden fallback/continuation and fails the fixture.
 */
class Phase4_6GHostSshRecoveryBlockFixtureTest {
    @Test
    fun `host fixture witnesses trust and auth blockers without fallback or command`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 4.6G host fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 4.6G fixture host fingerprint is not canonical SHA-256" }

        val rejectedAuthAttempts = AtomicInteger(0)
        val successfulAuthentications = AtomicInteger(0)
        val execRequests = AtomicInteger(0)

        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                val accepted = username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD
                if (accepted) successfulAuthentications.incrementAndGet() else rejectedAuthAttempts.incrementAndGet()
                accepted
            }
            commandFactory = CommandFactory { _, _ ->
                execRequests.incrementAndGet()
                NoOpCommand()
            }
        }

        try {
            server.start()
            check(server.port in 1..65535) { "Phase 4.6G host fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)
            Thread.sleep(POST_RELEASE_SETTLE_MILLIS)

            assertTrue(
                "Phase 4.6G auth-rejection case must reach the real SSH password authenticator",
                rejectedAuthAttempts.get() >= 1,
            )
            assertEquals(
                "No Phase 4.6G path may authenticate successfully; success would imply forbidden fallback",
                0,
                successfulAuthentications.get(),
            )
            assertEquals(
                "Recovery blockers are transport-only and must never execute a remote command",
                0,
                execRequests.get(),
            )
        } finally {
            runCatching { server.stop() }
        }
    }

    private class NoOpCommand : Command {
        private var exitCallback: ExitCallback? = null
        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) = Unit
        override fun setErrorStream(error: OutputStream) = Unit
        override fun setExitCallback(callback: ExitCallback) { exitCallback = callback }
        override fun start(channel: ChannelSession, env: Environment) { exitCallback?.onExit(1) }
        override fun destroy(channel: ChannelSession) = Unit
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(READY_FILE, RELEASE_FILE).forEach { name ->
            runCatching { Files.deleteIfExists(fixtureDir.resolve(name)) }
        }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 4.6G runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE46G_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase46g"
        const val FIXTURE_PASSWORD = "VELUM-phase46g-test-only-password"
        const val READY_FILE = "ready.properties"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 180_000L
        const val POST_RELEASE_SETTLE_MILLIS = 500L
        const val POLL_INTERVAL_MILLIS = 50L

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
