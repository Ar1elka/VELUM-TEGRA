package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.InstallerWorkerLivenessPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallerWorkerLiveness
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyPairGenerator
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
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
 * Host-only Phase 8.8 network-flap witness.
 *
 * External connection #1 is deliberately held before SSH identification so Android can traverse a
 * real ONLINE -> OFFLINE -> ONLINE generation change while one reconnect remains unresolved.
 * After the runner releases that stale socket, connection #2 is proxied to an internal Apache MINA
 * SSH server that accepts exactly one production-compiled read-only Installer worker-evidence
 * command. No mutation-shaped command is accepted or executed.
 */
class Phase8_8HostInstallerLifecycleFixtureTest {
    @Test
    fun `network flap fixture permits only post verify worker evidence after stale reconnect`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue("Phase 8.8 fixture is opt-in", !fixtureDirValue.isNullOrBlank())

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupMarkers(fixtureDir)

        val operationId = OperationId("phase8-8-network-operation")
        val scope = InstallerWorkerScope(
            operationId = operationId,
            serverId = ServerId("phase8-8-network-server"),
            serverAccessId = ServerAccessId("phase8-8-network-access"),
            managedInstallId = ManagedInstallIdentityPolicy.forOperation(operationId),
        )
        val expectedCommand = requireNotNull(InstallerPostInstallReadOnlyCompiler.workerEvidence(scope)).rawForTransport()
        check("heartbeat" in expectedCommand && "terminal" in expectedCommand && "pid" in expectedCommand)
        check("phase" !in expectedCommand.lowercase() && "progress" !in expectedCommand.lowercase())

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 8.8 fixture host fingerprint is not canonical SHA-256" }

        val authAttempts = AtomicInteger(0)
        val unexpectedAuth = AtomicInteger(0)
        val commandCount = AtomicInteger(0)
        val unexpectedCommand = AtomicInteger(0)
        val externalConnections = AtomicInteger(0)
        val activeExternal = AtomicInteger(0)
        val maxConcurrent = AtomicInteger(0)
        val proxyFailure = AtomicReference<Throwable?>(null)

        val sshServer = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                if (username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD) {
                    authAttempts.incrementAndGet()
                    true
                } else {
                    unexpectedAuth.incrementAndGet()
                    writeAtomic(fixtureDir.resolve(UNEXPECTED_AUTH_FILE), "username=${sanitize(username)}\n")
                    false
                }
            }
            commandFactory = CommandFactory { _, command ->
                WorkerEvidenceCommand(
                    command = command,
                    expectedCommand = expectedCommand,
                    fixtureDir = fixtureDir,
                    commandCount = commandCount,
                    unexpectedCommand = unexpectedCommand,
                    scope = scope,
                )
            }
        }

        var externalServer: ServerSocket? = null
        var proxyThread: Thread? = null
        try {
            sshServer.start()
            check(sshServer.port in 1..65535)
            externalServer = ServerSocket(0, 4, InetAddress.getByName(LOOPBACK_HOST)).apply {
                reuseAddress = true
                soTimeout = 300_000
            }

            val publishedPort = externalServer.localPort
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=$publishedPort\n" +
                    "fingerprint=$fingerprint\n" +
                    "expectedConnections=2\n" +
                    "expectedAuth=1\n" +
                    "expectedCommands=1\n",
            )

            val external = requireNotNull(externalServer)
            proxyThread = thread(name = "phase8-8-network-proxy", isDaemon = true) {
                try {
                    external.accept().use { first ->
                        recordExternalAccepted(externalConnections, activeExternal, maxConcurrent)
                        try {
                            writeAtomic(fixtureDir.resolve(FIRST_ACCEPTED_FILE), "connections=1\n")
                            waitForMarker(fixtureDir.resolve(RELEASE_FIRST_FILE), RELEASE_TIMEOUT_MILLIS)
                        } finally {
                            activeExternal.decrementAndGet()
                        }
                    }

                    external.accept().use { second ->
                        recordExternalAccepted(externalConnections, activeExternal, maxConcurrent)
                        Socket(LOOPBACK_HOST, sshServer.port).use { upstream ->
                            val clientToServer = thread(name = "phase8-8-proxy-c2s", isDaemon = true) {
                                pipe(second.getInputStream(), upstream.getOutputStream())
                                runCatching { upstream.shutdownOutput() }
                            }
                            val serverToClient = thread(name = "phase8-8-proxy-s2c", isDaemon = true) {
                                pipe(upstream.getInputStream(), second.getOutputStream())
                                runCatching { second.shutdownOutput() }
                            }
                            clientToServer.join(PROXY_JOIN_TIMEOUT_MILLIS)
                            serverToClient.join(PROXY_JOIN_TIMEOUT_MILLIS)
                            check(!clientToServer.isAlive && !serverToClient.isAlive) {
                                "Phase 8.8 SSH proxy streams did not terminate within the bounded join"
                            }
                        }
                        activeExternal.decrementAndGet()
                    }
                    writeAtomic(
                        fixtureDir.resolve(PROXY_COMPLETED_FILE),
                        "connections=${externalConnections.get()}\nmaxConcurrent=${maxConcurrent.get()}\n",
                    )
                } catch (t: Throwable) {
                    proxyFailure.set(t)
                    writeAtomic(fixtureDir.resolve(PROXY_FAILURE_FILE), sanitize(t.toString()))
                }
            }

            waitForMarker(fixtureDir.resolve(RELEASE_FIXTURE_FILE), RELEASE_TIMEOUT_MILLIS)
            val proxy = requireNotNull(proxyThread)
            proxy.join(PROXY_JOIN_TIMEOUT_MILLIS)
            proxyFailure.get()?.let { throw AssertionError("Phase 8.8 network proxy failed", it) }
            check(!proxy.isAlive) { "Phase 8.8 network proxy did not terminate" }

            assertEquals("Exactly two external TCP reconnect attempts are expected", 2, externalConnections.get())
            assertEquals("Reconnect attempts must never overlap", 1, maxConcurrent.get())
            assertEquals("Only the second exact SSH path may authenticate", 1, authAttempts.get())
            assertEquals("No fallback credential may be attempted", 0, unexpectedAuth.get())
            assertEquals("Exactly one read-only worker-evidence command is expected", 1, commandCount.get())
            assertEquals("No unknown or mutation-shaped command may be accepted", 0, unexpectedCommand.get())
            assertFalse(Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)))
            writeAtomic(
                fixtureDir.resolve(COMPLETED_FILE),
                "connections=2\nmaxConcurrent=1\nauth=1\ncommands=1\n",
            )
        } finally {
            runCatching { externalServer?.close() }
            runCatching { sshServer.stop() }
        }
    }

    private class WorkerEvidenceCommand(
        private val command: String,
        private val expectedCommand: String,
        private val fixtureDir: Path,
        private val commandCount: AtomicInteger,
        private val unexpectedCommand: AtomicInteger,
        private val scope: InstallerWorkerScope,
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
            worker = thread(name = "phase8-8-worker-evidence", isDaemon = true) {
                if (command != expectedCommand || commandCount.incrementAndGet() != 1) {
                    unexpectedCommand.incrementAndGet()
                    writeAtomic(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE), "command=${sanitize(command)}\n")
                    error?.write("rejected\n".toByteArray(StandardCharsets.UTF_8))
                    error?.flush()
                    exitCallback?.onExit(126)
                    return@thread
                }
                val now = Instant.now()
                val stdout = "PROCESS=UNKNOWN\nHEARTBEAT=${now.minusSeconds(2).epochSecond}\nTERMINAL=NONE\n"
                val parsed = InstallerPostInstallParsers.parseWorkerEvidence(
                    scope = scope,
                    raw = stdout,
                    observedAt = now,
                )
                check(parsed != null)
                check(InstallerWorkerLivenessPolicy.classify(scope, parsed, now) == InstallerWorkerLiveness.KnownAlive)
                output?.write(stdout.toByteArray(StandardCharsets.UTF_8))
                output?.flush()
                writeAtomic(fixtureDir.resolve(COMMAND_OBSERVED_FILE), "commands=1\n")
                exitCallback?.onExit(0)
            }
        }

        override fun destroy(channel: ChannelSession) {
            worker?.interrupt()
            worker = null
        }

    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE88_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase88"
        const val FIXTURE_PASSWORD = "VELUM-phase88-test-only-password"

        const val READY_FILE = "ready.properties"
        const val FIRST_ACCEPTED_FILE = "first.accepted"
        const val RELEASE_FIRST_FILE = "release.first"
        const val RELEASE_FIXTURE_FILE = "release.fixture"
        const val COMMAND_OBSERVED_FILE = "command.observed"
        const val PROXY_COMPLETED_FILE = "proxy.completed"
        const val PROXY_FAILURE_FILE = "proxy.failure"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val COMPLETED_FILE = "fixture.completed"
        const val RELEASE_TIMEOUT_MILLIS = 300_000L
        const val PROXY_JOIN_TIMEOUT_MILLIS = 60_000L

        fun recordExternalAccepted(
            total: AtomicInteger,
            active: AtomicInteger,
            maxConcurrent: AtomicInteger,
        ) {
            total.incrementAndGet()
            val nowActive = active.incrementAndGet()
            while (true) {
                val old = maxConcurrent.get()
                if (nowActive <= old || maxConcurrent.compareAndSet(old, nowActive)) break
            }
        }

        fun pipe(input: InputStream, output: OutputStream) {
            val buffer = ByteArray(8192)
            try {
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) return
                    output.write(buffer, 0, read)
                    output.flush()
                }
            } catch (_: Exception) {
                // Socket teardown is expected when the exact Android session closes.
            }
        }

        fun cleanupMarkers(fixtureDir: Path) {
            listOf(
                READY_FILE,
                FIRST_ACCEPTED_FILE,
                RELEASE_FIRST_FILE,
                RELEASE_FIXTURE_FILE,
                COMMAND_OBSERVED_FILE,
                PROXY_COMPLETED_FILE,
                PROXY_FAILURE_FILE,
                UNEXPECTED_AUTH_FILE,
                UNEXPECTED_COMMAND_FILE,
                COMPLETED_FILE,
            ).forEach { runCatching { Files.deleteIfExists(fixtureDir.resolve(it)) } }
        }

        fun waitForMarker(path: Path, timeoutMillis: Long) {
            val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
            while (System.nanoTime() < deadline) {
                if (Files.isRegularFile(path)) return
                Thread.sleep(50L)
            }
            throw AssertionError("Timed out waiting for Phase 8.8 fixture marker ${path.fileName}")
        }

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
