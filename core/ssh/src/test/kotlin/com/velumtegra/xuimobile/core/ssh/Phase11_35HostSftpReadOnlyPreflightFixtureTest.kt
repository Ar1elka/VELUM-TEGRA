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
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.server.session.ServerSession
import org.apache.sshd.sftp.server.SftpEventListener
import org.apache.sshd.sftp.server.SftpSubsystemFactory
import org.apache.sshd.sftp.server.UnsupportedAttributePolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Host-only witness for one bounded read-only SFTP root preflight and zero mutation/exec. */
class Phase11_35HostSftpReadOnlyPreflightFixtureTest {
    @Test
    fun `fixture preserves exact tree through one read-only sftp preflight`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue("Phase 11.35 fixture is runner-only", !fixtureDirValue.isNullOrBlank())
        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        val fsRoot = fixtureDir.resolve("sftp-root")
        Files.createDirectories(fsRoot)
        val targetRoot = fsRoot.resolve("phase11-35-target")
        Files.createDirectories(targetRoot)
        val indexBytes = "<html>phase11.35</html>\n".toByteArray(StandardCharsets.UTF_8)
        val manifestBytes = "fixture-read-only-preflight\n".toByteArray(StandardCharsets.UTF_8)
        Files.write(targetRoot.resolve("index.html"), indexBytes)
        Files.write(targetRoot.resolve("manifest.txt"), manifestBytes)
        cleanupRunnerMarkers(fixtureDir)

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid)

        val exactAuthAttempts = AtomicInteger(0)
        val unexpectedAuthAttempts = AtomicInteger(0)
        val commandRequests = AtomicInteger(0)
        val sftpInitialized = AtomicInteger(0)
        val sftpDestroyed = AtomicInteger(0)

        val sftpFactory = SftpSubsystemFactory.Builder()
            .withUnsupportedAttributePolicy(UnsupportedAttributePolicy.Ignore)
            .build().apply {
                addSftpEventListener(object : SftpEventListener {
                    override fun initialized(session: ServerSession, version: Int) {
                        sftpInitialized.incrementAndGet()
                    }
                    override fun destroying(session: ServerSession) {
                        sftpDestroyed.incrementAndGet()
                    }
                })
            }

        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            fileSystemFactory = VirtualFileSystemFactory(fsRoot)
            subsystemFactories = listOf(sftpFactory)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                if (username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD) {
                    exactAuthAttempts.incrementAndGet(); true
                } else {
                    unexpectedAuthAttempts.incrementAndGet()
                    writeAtomic(fixtureDir.resolve(UNEXPECTED_AUTH_FILE), "username=${sanitize(username)}\n")
                    false
                }
            }
            commandFactory = CommandFactory { _, command ->
                RejectingCommand(fixtureDir, command, commandRequests)
            }
        }

        try {
            server.start()
            check(server.port in 1..65535)
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\nexpectedAuth=1\nexpectedSftpInitialized=1\ntargetRoot=/phase11-35-target\nstagingRoot=/phase11-35-staging\nbackupRoot=/phase11-35-backup\n",
            )
            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)
            waitForCount(sftpDestroyed, 1, 5_000L)

            assertEquals("Phase 11.35 must authenticate exactly once", 1, exactAuthAttempts.get())
            assertEquals("No fallback authentication is allowed", 0, unexpectedAuthAttempts.get())
            assertEquals("No remote exec command is allowed", 0, commandRequests.get())
            assertEquals("Exactly one SFTP subsystem must initialize", 1, sftpInitialized.get())
            assertEquals("Exactly one SFTP subsystem must be destroyed", 1, sftpDestroyed.get())
            assertFalse(Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)))
            assertTrue(Files.isDirectory(targetRoot))
            assertTrue(Files.readAllBytes(targetRoot.resolve("index.html")).contentEquals(indexBytes))
            assertTrue(Files.readAllBytes(targetRoot.resolve("manifest.txt")).contentEquals(manifestBytes))
            assertFalse(Files.exists(fsRoot.resolve("phase11-35-staging")))
            assertFalse(Files.exists(fsRoot.resolve("phase11-35-backup")))
            val rootNames = Files.list(fsRoot).use { stream -> stream.map { it.fileName.toString() }.sorted().toList() }
            assertEquals(listOf("phase11-35-target"), rootNames)
            val targetNames = Files.list(targetRoot).use { stream -> stream.map { it.fileName.toString() }.sorted().toList() }
            assertEquals(listOf("index.html", "manifest.txt"), targetNames)
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
            error?.write("Phase 11.35 rejects all remote commands\n".toByteArray(StandardCharsets.UTF_8))
            error?.flush()
            exitCallback?.onExit(126)
        }
        override fun destroy(channel: ChannelSession) = Unit
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(READY_FILE, UNEXPECTED_AUTH_FILE, UNEXPECTED_COMMAND_FILE, RELEASE_FILE)
            .forEach { Files.deleteIfExists(fixtureDir.resolve(it)) }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 11.35 runner release marker")
    }

    private fun waitForCount(counter: AtomicInteger, expected: Int, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (counter.get() >= expected) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 11.35 SFTP subsystem close")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE1135_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase1135"
        const val FIXTURE_PASSWORD = "VELUM-phase1135-test-only-password"
        const val READY_FILE = "ready.properties"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 240_000L
        const val POLL_INTERVAL_MILLIS = 50L
        fun sanitize(value: String): String = value.replace("\r", "?").replace("\n", "?").take(240)
        fun writeAtomic(path: Path, text: String) {
            val tmp = path.resolveSibling(path.fileName.toString() + ".tmp")
            Files.write(tmp, text.toByteArray(StandardCharsets.UTF_8))
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: Exception) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}
