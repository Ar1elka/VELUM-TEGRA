package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteBuildRequest
import com.velumtegra.xuimobile.core.site.SiteBuilder
import com.velumtegra.xuimobile.core.site.SiteDesignGenerator
import com.velumtegra.xuimobile.core.site.SiteDesignRequest
import com.velumtegra.xuimobile.core.site.SiteDesignSeeds
import com.velumtegra.xuimobile.core.site.SiteExportFormat
import com.velumtegra.xuimobile.core.site.SiteLocalExportReceipt
import com.velumtegra.xuimobile.core.site.SitePreviewExportBoundary
import com.velumtegra.xuimobile.core.site.SitePreviewExportRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPlan
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.CopyOption
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
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
import org.apache.sshd.sftp.server.SftpEventListener
import org.apache.sshd.sftp.server.SftpSubsystemFactory
import org.apache.sshd.sftp.server.UnsupportedAttributePolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Host-only end-to-end coordinator fixture. No host shell/process is launched. */
class Phase11_12AHostDeploymentCoordinatorFixtureTest {
    @Test
    fun `real device coordinator stays inside exact reviewed deployment plans`() {
        val rawDir = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue("Phase 11.12A host fixture is runner-only", !rawDir.isNullOrBlank())
        val fixtureDir = Paths.get(requireNotNull(rawDir)).toAbsolutePath().normalize()
        val fsRoot = fixtureDir.resolve("sftp-root")
        Files.createDirectories(fsRoot.resolve("var/www"))
        cleanupMarkers(fixtureDir)

        val commit = plan(111120L, "commit", "/var/www/phase1112a-commit", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val blocked = plan(111121L, "blocked", "/var/www/phase1112a-blocked", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val cancel = plan(111122L, "cancel", "/var/www/phase1112a-cancel", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val rollback = plan(111123L, "rollback", "/var/www/phase1112a-rollback", SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE)

        val blockedTarget = fsRoot.resolve("var/www/phase1112a-blocked")
        Files.createDirectories(blockedTarget)
        Files.writeString(blockedTarget.resolve("sentinel.txt"), "blocked-original", StandardCharsets.UTF_8)
        val rollbackTarget = fsRoot.resolve("var/www/phase1112a-rollback")
        Files.createDirectories(rollbackTarget)
        Files.writeString(rollbackTarget.resolve("original.txt"), "original", StandardCharsets.UTF_8)

        val expectations = buildList {
            addAll(expectations(commit, targetType = "ABSENT", includeSftpIdentity = true))
            addAll(expectations(blocked, targetType = "DIRECTORY", includeSftpIdentity = false))
            addAll(expectations(cancel, targetType = "ABSENT", includeSftpIdentity = false))
            addAll(expectations(rollback, targetType = "DIRECTORY", includeSftpIdentity = true))
        }
        assertEquals(EXPECTED_COMMANDS, expectations.size)

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        val canonical = CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) as? HostKeyFingerprintParseResult.Valid
            ?: error("fixture host fingerprint is not canonical SHA-256")
        val hostKeyHex = canonical.fingerprint.asHexSha256()
        val authCount = AtomicInteger(0)
        val unexpectedAuth = AtomicInteger(0)
        val commandCount = AtomicInteger(0)
        val observedCommands = CopyOnWriteArrayList<String>()
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

                    override fun moving(
                        session: org.apache.sshd.server.session.ServerSession,
                        srcPath: Path,
                        dstPath: Path,
                        opts: MutableCollection<CopyOption>,
                    ) {
                        val src = slash(srcPath)
                        val dst = slash(dstPath)
                        if (
                            src.endsWith(rollback.publish.stagingRoot) &&
                            dst.endsWith(rollback.publish.targetRoot) &&
                            forcedRollback.compareAndSet(false, true)
                        ) {
                            throw IOException("Phase 11.12A synthetic publish-rename rejection")
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
            commandFactory = CommandFactory { _, command ->
                ReviewedCommand(command, commandCount, expectations, observedCommands, fixtureDir)
            }
        }

        try {
            server.start()
            writeAtomic(
                fixtureDir.resolve(READY),
                "port=${server.port}\nfingerprint=$fingerprint\nhostKeyHex=$hostKeyHex\nexpectedAuth=$EXPECTED_AUTH\nexpectedCommands=$EXPECTED_COMMANDS\n",
            )
            waitFor(fixtureDir.resolve(RELEASE), 180_000)

            assertEquals(EXPECTED_AUTH, authCount.get())
            assertEquals(0, unexpectedAuth.get())
            assertEquals(EXPECTED_COMMANDS, commandCount.get())
            assertEquals(expectations.map(Expectation::raw), observedCommands.toList())
            assertTrue(forcedRollback.get())

            assertTrue(Files.isDirectory(fsRoot.resolve("var/www/phase1112a-commit")))
            assertTrue(Files.isDirectory(blockedTarget))
            assertEquals("blocked-original", Files.readString(blockedTarget.resolve("sentinel.txt"), StandardCharsets.UTF_8))
            assertFalse(Files.exists(fsRoot.resolve("var/www/phase1112a-cancel")))
            assertTrue(Files.isDirectory(rollbackTarget))
            assertEquals("original", Files.readString(rollbackTarget.resolve("original.txt"), StandardCharsets.UTF_8))

            listOf(commit, blocked, cancel, rollback).forEach { reviewed ->
                assertFalse(Files.exists(resolveRemote(fsRoot, reviewed.publish.stagingRoot)))
                reviewed.publish.backupRoot?.let { assertFalse(Files.exists(resolveRemote(fsRoot, it))) }
            }
            assertFalse(Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND)))
            writeAtomic(
                fixtureDir.resolve(COMPLETED),
                "auth=${authCount.get()}\ncommands=${commandCount.get()}\ncommit=true\nblockedUntouched=true\ncancelNoMutation=true\nrollbackRestored=true\n",
            )
        } finally {
            runCatching { server.stop() }
        }
    }

    private data class Expectation(val raw: String, val stdout: String = "", val exitCode: Int = 0)

    private inner class ReviewedCommand(
        private val command: String,
        private val count: AtomicInteger,
        private val expectations: List<Expectation>,
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
            val index = count.getAndIncrement()
            val expected = expectations.getOrNull(index)
            if (expected == null || command != expected.raw) {
                writeAtomic(
                    fixtureDir.resolve(UNEXPECTED_COMMAND),
                    "index=${index + 1}\nactual=${sanitize(command)}\nexpected=${sanitize(expected?.raw ?: "<none>")}\n",
                )
                err?.write("rejected\n".toByteArray(StandardCharsets.UTF_8))
                err?.flush()
                exit?.onExit(126)
                return
            }
            observed += command
            out?.write(expected.stdout.toByteArray(StandardCharsets.UTF_8))
            out?.flush()
            exit?.onExit(expected.exitCode)
        }
        override fun destroy(channel: ChannelSession) = Unit
    }

    private fun expectations(
        plan: SiteRemoteDeployPlan,
        targetType: String,
        includeSftpIdentity: Boolean,
    ): List<Expectation> = buildList {
        add(Expectation(pathObservation(plan.publish.targetRoot), "$targetType\t0\n"))
        add(Expectation(pathObservation(plan.publish.stagingRoot), "ABSENT\t0\n"))
        plan.publish.backupRoot?.let { add(Expectation(pathObservation(it), "ABSENT\t0\n")) }
        val parent = plan.publish.targetRoot.substringBeforeLast('/').ifBlank { "/" }
        add(Expectation("df -Pk -- ${quote(parent)} | awk 'NR==2 {print \$4}'", "65536\n"))
        add(Expectation("getent passwd ${quote(plan.publish.owner)} >/dev/null 2>&1"))
        add(Expectation("getent group ${quote(plan.publish.group)} >/dev/null 2>&1"))
        add(Expectation("id -u; id -un; id -Gn", "0\nroot\nroot\n"))
        if (includeSftpIdentity) {
            add(Expectation("getent passwd ${quote(plan.publish.owner)}", "root:x:0:0:root:/root:/bin/sh\n"))
            add(Expectation("getent group ${quote(plan.publish.group)}", "root:x:0:\n"))
        }
    }

    private fun plan(seed: Long, label: String, targetRoot: String, policy: SiteRemoteExistingTargetPolicy): SiteRemoteDeployPlan {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(
                SiteDesignGenerator.generate(
                    SiteDesignRequest(
                        seeds = SiteDesignSeeds.fromRoot(DesignSeed(seed)),
                        siteName = "Phase 11.12A $label",
                    ),
                ),
            ),
        )
        val export = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(
                format = SiteExportFormat.DIRECTORY,
                requestedBaseName = "phase1112a-$label",
            ),
        ).export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = export.manifest.outputName,
            outputPath = Paths.get("/tmp/${export.manifest.outputName}"),
            fileCount = export.manifest.fileCount,
            totalBytes = export.manifest.totalBytes,
            sourceTreeSha256 = export.manifest.sourceTreeSha256,
            planSha256 = export.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        return SiteRemoteDeployBoundary.prepare(
            export,
            receipt,
            SiteRemoteDeployRequest(
                remoteHostIdentity = LOOPBACK,
                targetRoot = targetRoot,
                owner = "root",
                group = "root",
                existingTargetPolicy = policy,
            ),
        )
    }

    private fun pathObservation(path: String): String =
        "if [ -L ${quote(path)} ]; then printf 'SYMLINK\\t0\\n'; " +
            "elif [ -d ${quote(path)} ]; then printf 'DIRECTORY\\t0\\n'; " +
            "elif [ -f ${quote(path)} ]; then printf 'FILE\\t'; wc -c < ${quote(path)}; " +
            "elif [ -e ${quote(path)} ]; then printf 'OTHER\\t0\\n'; " +
            "else printf 'ABSENT\\t0\\n'; fi"

    private fun quote(value: String): String = "'$value'"
    private fun resolveRemote(root: Path, remote: String): Path = root.resolve(remote.removePrefix("/"))
    private fun slash(path: Path): String = path.toString().replace('\\', '/')
    private fun sanitize(value: String) = value.replace("\n", " ").replace("\r", " ").take(500)
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

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE1112A_FIXTURE_DIR"
        const val LOOPBACK = "127.0.0.1"
        const val USER = "velum-phase1112a"
        const val PASSWORD = "VELUM-phase1112a-test-only-password"
        const val READY = "ready.properties"
        const val RELEASE = "release.marker"
        const val COMPLETED = "completed.properties"
        const val UNEXPECTED_COMMAND = "unexpected.command"
        const val EXPECTED_AUTH = 4
        const val EXPECTED_COMMANDS = 29
    }
}
