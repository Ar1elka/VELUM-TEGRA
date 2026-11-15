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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
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
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Host-side test-only SSH fixture used only by the opt-in Phase 4.6E real-device runner.
 *
 * Normal `:core:ssh:test` runs skip this test because the runner-only environment variable is
 * absent. When enabled, a real Apache MINA SSHD server binds only JVM loopback, authenticates one
 * fixed test-only credential, accepts one deterministic token, records that the exec request was
 * actually received, and then deliberately never reports command completion.
 *
 * No shell or host process is executed. The fixture exists only to make the conservative JSch
 * dispatch boundary externally observable before the Android runner removes the real default
 * network. The runner later writes a release marker; this fixture then proves exactly one exec
 * request was observed and shuts down.
 */
class Phase4_6EHostSshDispatchFixtureTest {
    @Test
    fun `host fixture confirms exactly one deterministic exec request`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 4.6E host fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 4.6E fixture host fingerprint is not canonical SHA-256" }

        val execRequests = AtomicInteger(0)
        val workers = CopyOnWriteArrayList<Thread>()
        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD
            }
            commandFactory = CommandFactory { _, command ->
                Phase4_6EFixtureCommand(
                    command = command,
                    fixtureDir = fixtureDir,
                    execRequests = execRequests,
                    workers = workers,
                )
            }
        }

        try {
            server.start()
            check(server.port in 1..65535) { "Phase 4.6E host fixture did not bind a TCP port" }

            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)
            Thread.sleep(POST_RELEASE_SETTLE_MILLIS)

            assertEquals(
                "Phase 4.6E must observe exactly one server-side exec request; any second request is replay",
                1,
                execRequests.get(),
            )
        } finally {
            workers.forEach { worker ->
                worker.interrupt()
                runCatching { worker.join(1_000) }
            }
            runCatching { server.stop() }
        }
    }

    private class Phase4_6EFixtureCommand(
        private val command: String,
        private val fixtureDir: Path,
        private val execRequests: AtomicInteger,
        private val workers: CopyOnWriteArrayList<Thread>,
    ) : Command {
        private var input: InputStream? = null
        private var output: OutputStream? = null
        private var error: OutputStream? = null
        private var exitCallback: ExitCallback? = null
        private val worker = AtomicReference<Thread?>(null)

        override fun setInputStream(input: InputStream) {
            this.input = input
        }

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
            val requestNumber = execRequests.incrementAndGet()
            if (requestNumber == 1 && command == FIXTURE_COMMAND) {
                writeAtomic(
                    fixtureDir.resolve(DISPATCH_FILE),
                    "received=$requestNumber\ncommand=$FIXTURE_COMMAND\n",
                )
            } else {
                writeAtomic(
                    fixtureDir.resolve(UNEXPECTED_FILE),
                    "received=$requestNumber\ncommand=${sanitize(command)}\n",
                )
            }

            val thread = Thread(
                {
                    try {
                        while (!Thread.currentThread().isInterrupted) {
                            Thread.sleep(1_000)
                        }
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                },
                "velum-phase46e-host-command",
            ).apply { isDaemon = true }

            check(worker.compareAndSet(null, thread)) { "Phase 4.6E fixture command started more than once" }
            workers += thread
            thread.start()
        }

        override fun destroy(channel: ChannelSession) {
            worker.getAndSet(null)?.let { thread ->
                thread.interrupt()
                workers.remove(thread)
            }
        }

        private fun sanitize(value: String): String = value
            .replace("\r", "?")
            .replace("\n", "?")
            .take(128)
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(READY_FILE, DISPATCH_FILE, UNEXPECTED_FILE, RELEASE_FILE).forEach { name ->
            runCatching { Files.deleteIfExists(fixtureDir.resolve(name)) }
        }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) {
                return
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 4.6E runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE46E_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase46e"
        const val FIXTURE_PASSWORD = "VELUM-phase46e-test-only-password"
        const val FIXTURE_COMMAND = "phase46e-read-only-hang"

        const val READY_FILE = "ready.properties"
        const val DISPATCH_FILE = "dispatch.received"
        const val UNEXPECTED_FILE = "unexpected.request"
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
