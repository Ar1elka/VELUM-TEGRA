package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteBuildRequest
import com.velumtegra.xuimobile.core.site.SiteBuilder
import com.velumtegra.xuimobile.core.site.SiteDesignGenerator
import com.velumtegra.xuimobile.core.site.SiteDesignRequest
import com.velumtegra.xuimobile.core.site.SiteDesignSeeds
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
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

/** Host-only witness for Phase 11.10A. It never launches a host shell or process. */
class Phase11_10AHostSiteObservationFixtureTest {
    @Test
    fun `real device may dispatch only the exact finite Site observation vocabulary`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 11.10A host fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )
        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val expected = expectedSequence()
        check(expected.size == EXPECTED_COMMANDS) { "Phase 11.10A witness plan must contain exactly $EXPECTED_COMMANDS commands" }
        expected.forEach { check(isReviewedReadOnly(it.raw)) { "Fixture plan contains non-read-only command: ${it.label}" } }

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        val canonical = CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint))
            as? HostKeyFingerprintParseResult.Valid ?: error("Fixture host fingerprint is not canonical SHA-256")
        val hostKeyHex = canonical.fingerprint.asHexSha256()

        val exactAuthAttempts = AtomicInteger(0)
        val unexpectedAuthAttempts = AtomicInteger(0)
        val commandRequests = AtomicInteger(0)
        val observed = CopyOnWriteArrayList<String>()

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
                FixtureCommand(command, fixtureDir, expected, commandRequests, observed)
            }
        }

        try {
            server.start()
            check(server.port in 1..65535) { "Phase 11.10A host fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\nhostKeyHex=$hostKeyHex\nexpectedCommands=$EXPECTED_COMMANDS\nexpectedAuth=$EXPECTED_AUTH\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals("Acceptance must use exactly two exact SSH authentications", EXPECTED_AUTH, exactAuthAttempts.get())
            assertEquals("No fallback credential may be attempted", 0, unexpectedAuthAttempts.get())
            assertEquals("Only the exact finite Site observation plan may be dispatched", EXPECTED_COMMANDS, commandRequests.get())
            assertEquals(expected.map { it.raw }, observed.toList())
            assertFalse("No unexpected command may reach the fixture", Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)))
            writeAtomic(
                fixtureDir.resolve(COMPLETED_FILE),
                "commands=${commandRequests.get()}\nauth=${exactAuthAttempts.get()}\n",
            )
        } finally {
            runCatching { server.stop() }
        }
    }

    private inner class FixtureCommand(
        private val command: String,
        private val fixtureDir: Path,
        private val expected: List<ExpectedCommand>,
        private val commandRequests: AtomicInteger,
        private val observed: CopyOnWriteArrayList<String>,
    ) : Command {
        private var output: OutputStream? = null
        private var error: OutputStream? = null
        private var exitCallback: ExitCallback? = null

        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) { this.output = output }
        override fun setErrorStream(error: OutputStream) { this.error = error }
        override fun setExitCallback(callback: ExitCallback) { exitCallback = callback }

        override fun start(channel: ChannelSession, env: Environment) {
            val request = commandRequests.incrementAndGet()
            val spec = expected.getOrNull(request - 1)
            if (spec == null || command != spec.raw || !isReviewedReadOnly(command)) {
                writeAtomic(
                    fixtureDir.resolve(UNEXPECTED_COMMAND_FILE),
                    "request=$request\nexpected=${sanitize(spec?.raw ?: "<none>")}\nactual=${sanitize(command)}\n",
                )
                error?.write("rejected\n".toByteArray(StandardCharsets.UTF_8))
                error?.flush()
                exitCallback?.onExit(126)
                return
            }
            observed += command
            if (spec.stdout.isNotEmpty()) {
                output?.write(spec.stdout)
                output?.flush()
            }
            exitCallback?.onExit(spec.exitCode)
            if (request == expected.size) {
                writeAtomic(fixtureDir.resolve(OBSERVED_FILE), "commands=$request\n")
            }
        }

        override fun destroy(channel: ChannelSession) = Unit
    }

    private data class ExpectedCommand(
        val label: String,
        val raw: String,
        val exitCode: Int = 0,
        val stdout: ByteArray = ByteArray(0),
    )

    private fun expectedSequence(): List<ExpectedCommand> {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(
                SiteDesignGenerator.generate(
                    SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(SITE_SEED))),
                ),
            ),
        )
        val target = SiteRemoteDeployPolicy.prepareTargetRoot(TARGET_ROOT)
        val staging = siblingStage(target, bundle.manifest.treeSha256)
        val parent = target.substringBeforeLast('/').ifBlank { "/" }
        val first = bundle.documents.first()

        fun bytes(text: String) = text.toByteArray(StandardCharsets.UTF_8)
        fun pathObservation(path: String, response: String, label: String) = ExpectedCommand(
            label = label,
            raw = "if [ -L ${quote(path)} ]; then printf 'SYMLINK\\t0\\n'; " +
                "elif [ -d ${quote(path)} ]; then printf 'DIRECTORY\\t0\\n'; " +
                "elif [ -f ${quote(path)} ]; then printf 'FILE\\t'; wc -c < ${quote(path)}; " +
                "elif [ -e ${quote(path)} ]; then printf 'OTHER\\t0\\n'; " +
                "else printf 'ABSENT\\t0\\n'; fi",
            stdout = bytes(response),
        )
        fun commonPreflight(targetResponse: String, prefix: String) = listOf(
            pathObservation(target, targetResponse, "$prefix-target"),
            pathObservation(staging, "ABSENT\t0\n", "$prefix-staging"),
            ExpectedCommand("$prefix-capacity", "df -Pk -- ${quote(parent)} | awk 'NR==2 {print \$4}'", stdout = bytes("1048576\n")),
            ExpectedCommand("$prefix-owner", "getent passwd ${quote("root")} >/dev/null 2>&1"),
            ExpectedCommand("$prefix-group", "getent group ${quote("root")} >/dev/null 2>&1"),
            ExpectedCommand("$prefix-identity", "id -u; id -un; id -Gn", stdout = bytes("0\nroot\nroot wheel www-data\n")),
        )

        return buildList {
            addAll(commonPreflight("ABSENT\t0\n", "ready"))
            add(ExpectedCommand(
                "file-sha256",
                "sha256sum -- ${quote("$target/${first.path}")}",
                stdout = bytes("${first.sha256}  ${first.path}\n"),
            ))
            bundle.documents.forEach { document ->
                add(ExpectedCommand(
                    label = "tree-${document.path}",
                    raw = "cat -- ${quote("$target/${document.path}")}",
                    stdout = document.content.toByteArray(StandardCharsets.UTF_8),
                ))
            }
            addAll(commonPreflight("DIRECTORY\t0\n", "blocked"))
        }
    }

    private fun siblingStage(targetRoot: String, treeSha256: String): String {
        val lastSlash = targetRoot.lastIndexOf('/')
        val parent = if (lastSlash == 0) "" else targetRoot.substring(0, lastSlash)
        val name = targetRoot.substring(lastSlash + 1)
        return "$parent/.$name.velum-stage-${treeSha256.take(12)}"
    }

    /** Independent witness: expected commands are exact, and this rejects common mutation primitives too. */
    private fun isReviewedReadOnly(raw: String): Boolean {
        if (raw.isBlank() || '\n' in raw || '\r' in raw || '\u0000' in raw) return false
        val lowered = " ${raw.lowercase()} "
        val forbidden = listOf(
            " rm ", " mv ", " cp ", " mkdir ", " chmod ", " chown ", " touch ", " truncate ",
            " tee ", " sed -i", " perl -pi", " scp ", " sftp ", " curl ", " wget ",
            " systemctl start", " systemctl stop", " systemctl restart", " > ", ">>",
        )
        return forbidden.none(lowered::contains)
    }

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(READY_FILE, OBSERVED_FILE, COMPLETED_FILE, UNEXPECTED_AUTH_FILE, UNEXPECTED_COMMAND_FILE, RELEASE_FILE)
            .forEach { runCatching { Files.deleteIfExists(fixtureDir.resolve(it)) } }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 11.10A runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE1110A_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase1110a"
        const val FIXTURE_PASSWORD = "VELUM-phase1110a-test-only-password"
        const val TARGET_ROOT = "/var/www/velum-phase1110a"
        const val SITE_SEED = 111010L
        const val EXPECTED_COMMANDS = 21
        const val EXPECTED_AUTH = 2
        const val READY_FILE = "ready.properties"
        const val OBSERVED_FILE = "site-observation.observed"
        const val COMPLETED_FILE = "site-observation.completed"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 240_000L
        const val POLL_INTERVAL_MILLIS = 50L

        fun sanitize(value: String): String = value.replace("\r", "?").replace("\n", "?").take(360)

        fun writeAtomic(path: Path, text: String) {
            val temp = path.resolveSibling("${path.fileName}.tmp-${System.nanoTime()}")
            Files.writeString(temp, text, StandardCharsets.UTF_8)
            try {
                Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: Exception) {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}
