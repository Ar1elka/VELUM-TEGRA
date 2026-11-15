package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.CopyOption
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.security.KeyPairGenerator
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
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
import org.apache.sshd.sftp.server.DirectoryHandle
import org.apache.sshd.sftp.server.SftpEventListener
import org.apache.sshd.sftp.server.SftpSubsystemFactory
import org.apache.sshd.sftp.server.UnsupportedAttributePolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Host-only SFTP fixture. No host shell/process is launched. */
class Phase11_11AHostBoundedSftpFixtureTest {
    @Test
    fun `real device bounded SFTP stays inside reviewed fixture roots`() {
        val rawDir = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue("Phase 11.11A host fixture is runner-only", !rawDir.isNullOrBlank())
        val fixtureDir = Paths.get(requireNotNull(rawDir)).toAbsolutePath().normalize()
        val fsRoot = fixtureDir.resolve("sftp-root")
        Files.createDirectories(fsRoot.resolve("var/www"))
        // Windows host acceptance must not depend on Developer Mode/admin symlink privileges.
        // The test accessor reports this ordinary fixture directory as a symlink over SFTP lstat.
        Files.createDirectories(fsRoot.resolve("symlink-root"))
        cleanupMarkers(fixtureDir)
        val rollbackTarget = fsRoot.resolve("var/www/phase1111a-rollback")
        Files.createDirectories(rollbackTarget)
        Files.writeString(rollbackTarget.resolve("original.txt"), "original", StandardCharsets.UTF_8)

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        val canonical = CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) as? HostKeyFingerprintParseResult.Valid
            ?: error("fixture host fingerprint is not canonical SHA-256")
        val hostKeyHex = canonical.fingerprint.asHexSha256()
        val authCount = AtomicInteger(0)
        val unexpectedAuth = AtomicInteger(0)
        val commandCount = AtomicInteger(0)
        val observedCommands = CopyOnWriteArrayList<String>()
        val injectedExtra = AtomicBoolean(false)
        val forcedRollback = AtomicBoolean(false)
        val fixtureAccessor = Phase11_11AFixtureSftpAccessor()

        val sftpFactory = SftpSubsystemFactory.Builder()
            .withFileSystemAccessor(fixtureAccessor)
            .withUnsupportedAttributePolicy(UnsupportedAttributePolicy.Ignore)
            .build().apply {
            addSftpEventListener(object : SftpEventListener {
                override fun modifyingAttributes(
                    session: org.apache.sshd.server.session.ServerSession,
                    path: Path,
                    attrs: Map<String, *>,
                ) {
                    fixtureAccessor.capture(path, attrs)
                }

                override fun readingEntries(session: org.apache.sshd.server.session.ServerSession, remoteHandle: String, localHandle: DirectoryHandle) {
                    val text = localHandle.file.toString().replace('\\', '/')
                    if (text.contains(".phase1111a-extra.velum-stage-") && injectedExtra.compareAndSet(false, true)) {
                        Files.write(localHandle.file.resolve("unexpected.txt"), "unexpected".toByteArray(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW)
                    }
                }

                override fun moving(
                    session: org.apache.sshd.server.session.ServerSession,
                    srcPath: Path,
                    dstPath: Path,
                    opts: MutableCollection<CopyOption>,
                ) {
                    val src = srcPath.toString().replace('\\', '/')
                    val dst = dstPath.toString().replace('\\', '/')
                    if (src.contains(".phase1111a-rollback.velum-stage-") && dst.endsWith("/var/www/phase1111a-rollback") && forcedRollback.compareAndSet(false, true)) {
                        throw IOException("Phase 11.11A synthetic publish-rename rejection")
                    }
                }
            })
        }

        val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            fileSystemFactory = VirtualFileSystemFactory(fsRoot)
            subsystemFactories = listOf(sftpFactory)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                if (username == USER && password == PASSWORD) { authCount.incrementAndGet(); true }
                else { unexpectedAuth.incrementAndGet(); false }
            }
            commandFactory = CommandFactory { _, command -> IdentityCommand(command, commandCount, observedCommands, fixtureDir) }
        }

        try {
            server.start()
            writeAtomic(fixtureDir.resolve(READY), "port=${server.port}\nfingerprint=$fingerprint\nhostKeyHex=$hostKeyHex\nexpectedAuth=4\nexpectedCommands=8\n")
            waitFor(fixtureDir.resolve(RELEASE), 180_000)

            assertEquals(4, authCount.get())
            assertEquals(0, unexpectedAuth.get())
            assertEquals(8, commandCount.get())
            assertEquals(List(4) { listOf("getent passwd 'root'", "getent group 'root'") }.flatten(), observedCommands.toList())
            assertTrue(injectedExtra.get())
            assertTrue(forcedRollback.get())
            assertTrue(Files.isDirectory(fsRoot.resolve("var/www/phase1111a-commit")))
            assertFalse(Files.exists(fsRoot.resolve("var/www/phase1111a-extra")))
            assertFalse(Files.list(fsRoot.resolve("var/www")).use { stream -> stream.anyMatch { it.fileName.toString().contains("phase1111a-extra.velum-stage") } })
            assertTrue(Files.isDirectory(rollbackTarget))
            assertEquals("original", Files.readString(rollbackTarget.resolve("original.txt"), StandardCharsets.UTF_8))
            assertFalse(Files.list(fsRoot.resolve("var/www")).use { stream -> stream.anyMatch { it.fileName.toString().contains("phase1111a-rollback.velum-") } })
            assertFalse(Files.exists(fsRoot.resolve("escape.txt")))
            assertFalse(Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND)))
            writeAtomic(fixtureDir.resolve(COMPLETED), "auth=${authCount.get()}\ncommands=${commandCount.get()}\nextraInjected=true\nrollbackRestored=true\n")
        } finally {
            runCatching { server.stop() }
        }
    }

    private inner class IdentityCommand(
        private val command: String,
        private val count: AtomicInteger,
        private val observed: CopyOnWriteArrayList<String>,
        private val fixtureDir: Path,
    ) : Command {
        private var out: OutputStream? = null
        private var err: OutputStream? = null
        private var exit: ExitCallback? = null
        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) { out = output }
        override fun setErrorStream(error: OutputStream) { err = error }
        override fun setExitCallback(callback: ExitCallback) { exit = callback }
        override fun start(channel: ChannelSession, env: Environment) {
            val index = count.incrementAndGet()
            val expected = if (index % 2 == 1) "getent passwd 'root'" else "getent group 'root'"
            if (index > 8 || command != expected) {
                writeAtomic(fixtureDir.resolve(UNEXPECTED_COMMAND), "index=$index\nactual=${sanitize(command)}\n")
                err?.write("rejected\n".toByteArray(StandardCharsets.UTF_8)); err?.flush(); exit?.onExit(126); return
            }
            observed += command
            val text = if (index % 2 == 1) "root:x:0:0:root:/root:/bin/sh\n" else "root:x:0:\n"
            out?.write(text.toByteArray(StandardCharsets.UTF_8)); out?.flush(); exit?.onExit(0)
        }
        override fun destroy(channel: ChannelSession) = Unit
    }

    private fun cleanupMarkers(dir: Path) = listOf(READY, RELEASE, COMPLETED, UNEXPECTED_COMMAND).forEach { Files.deleteIfExists(dir.resolve(it)) }
    private fun waitFor(path: Path, timeoutMs: Long) {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (System.nanoTime() < deadline) { if (Files.exists(path)) return; Thread.sleep(50) }
        error("timed out waiting for $path")
    }
    private fun writeAtomic(path: Path, text: String) {
        Files.createDirectories(path.parent)
        val tmp = path.resolveSibling(path.fileName.toString() + ".tmp-${System.nanoTime()}")
        Files.writeString(tmp, text, StandardCharsets.UTF_8)
        try {
            Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        } catch (_: Exception) {
            Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
    }
    private fun sanitize(value: String) = value.replace("\n", " ").replace("\r", " ").take(300)

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE1111A_FIXTURE_DIR"
        const val LOOPBACK = "127.0.0.1"
        const val USER = "velum-phase1111a"
        const val PASSWORD = "VELUM-phase1111a-test-only-password"
        const val READY = "ready.properties"
        const val RELEASE = "release.marker"
        const val COMPLETED = "completed.properties"
        const val UNEXPECTED_COMMAND = "unexpected.command"
    }
}
