package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbePlan
import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbeSpec
import com.velumtegra.xuimobile.core.domain.ManagementProbePlan
import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.model.DeepDiagnosticCertificateReferences
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
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
 * Host-only deterministic SSH witness for Phase 6.7 real-device Management acceptance.
 *
 * The fixture never launches a host shell/process. It accepts only the exact finite production
 * QUICK_INSPECT + DEEP_DIAGNOSTIC read-only commands and synthetic test credentials. Any unknown
 * command, over-dispatch of a reviewed command, or fallback credential creates a failure marker.
 */
class Phase6_7HostSshManagementFixtureTest {
    @Test
    fun `host fixture witnesses exact quick inspect and deep diagnostic plans`() {
        val fixtureDirValue = System.getenv(ENV_FIXTURE_DIR)
        assumeTrue(
            "Phase 6.7 host fixture is opt-in and must be launched only by its PowerShell runner",
            !fixtureDirValue.isNullOrBlank(),
        )

        val fixtureDir = Paths.get(requireNotNull(fixtureDirValue)).toAbsolutePath().normalize()
        Files.createDirectories(fixtureDir)
        cleanupRunnerMarkers(fixtureDir)

        val installation = canonicalInstallation()
        val expected = expectedCommands(installation)
        val expectedTotal = expected.values.sumOf { it.expectedCount }
        check(expectedTotal == 21) { "Phase 6.7 must witness exactly 21 reviewed command dispatches" }

        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val fingerprint = KeyUtils.getFingerPrint(hostKey.public)
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint)) is HostKeyFingerprintParseResult.Valid,
        ) { "Phase 6.7 fixture host fingerprint is not canonical SHA-256" }

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
            check(server.port in 1..65535) { "Phase 6.7 host fixture did not bind a TCP port" }
            writeAtomic(
                fixtureDir.resolve(READY_FILE),
                "port=${server.port}\nfingerprint=$fingerprint\nexpectedCommands=$expectedTotal\nexpectedAuth=2\n",
            )

            waitForMarker(fixtureDir.resolve(RELEASE_FILE), RELEASE_TIMEOUT_MILLIS)

            assertEquals("QUICK + DEEP must create exactly two exact SSH authentications", 2, exactAuthAttempts.get())
            assertEquals("Phase 6.7 must never try the poison credential", 0, unexpectedAuthAttempts.get())
            assertEquals("Phase 6.7 must dispatch exactly the reviewed finite total", expectedTotal, commandRequests.get())
            expected.forEach { (raw, spec) ->
                assertEquals(
                    "Reviewed command count mismatch for ${spec.label}",
                    spec.expectedCount,
                    observedCounts[raw]?.get() ?: 0,
                )
            }
            assertFalse("No unexpected command may reach the fixture", Files.exists(fixtureDir.resolve(UNEXPECTED_COMMAND_FILE)))
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

        override fun setInputStream(input: InputStream) = Unit
        override fun setOutputStream(output: OutputStream) { this.output = output }
        override fun setErrorStream(error: OutputStream) { this.error = error }
        override fun setExitCallback(callback: ExitCallback) { exitCallback = callback }

        override fun start(channel: ChannelSession, env: Environment) {
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
                return
            }

            if (spec.response.stdout.isNotEmpty()) {
                output?.write(spec.response.stdout.toByteArray(StandardCharsets.UTF_8))
                output?.flush()
            }
            exitCallback?.onExit(spec.response.exitCode)

            if (requestNumber == expectedTotal && expected.all { (raw, expectedSpec) ->
                    observedCounts[raw]?.get() == expectedSpec.expectedCount
                }
            ) {
                writeAtomic(fixtureDir.resolve(COMPLETED_FILE), "commands=$requestNumber\n")
            }
        }

        override fun destroy(channel: ChannelSession) = Unit
    }

    private data class FixtureResponse(val exitCode: Int, val stdout: String = "")
    private data class ExpectedCommand(
        val label: String,
        val expectedCount: Int,
        val response: FixtureResponse,
    )

    private fun expectedCommands(installation: XuiInstallation): Map<String, ExpectedCommand> {
        val result = linkedMapOf<String, ExpectedCommand>()

        fun addManagement(probe: ManagementProbeSpec, count: Int) {
            val compiled = ManagementReadOnlyCommandCompiler.compile(probe)
            check(compiled is CompiledManagementProbe.Command) { "Phase 6.7 ADOPTED Management probe must compile to a command" }
            val raw = compiled.command.rawForTransport()
            check(isReviewedReadOnly(raw)) { "Management compiler emitted command outside Phase 6.7 read-only witness policy" }
            val response = when (probe) {
                is ManagementProbeSpec.ServiceUnitPresence -> FixtureResponse(0)
                is ManagementProbeSpec.ExactPathPresence -> FixtureResponse(0)
                is ManagementProbeSpec.ServiceLiveState -> FixtureResponse(0, "active\n")
                is ManagementProbeSpec.PanelSettingsReadback -> FixtureResponse(
                    0,
                    "PORT=54321\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n",
                )
                is ManagementProbeSpec.ExactListenerPresence -> FixtureResponse(0)
                is ManagementProbeSpec.ManagedInstallMarkerReadback -> error("ADOPTED fixture must not request marker")
            }
            val prior = result[raw]
            check(prior == null || prior.response == response) { "Same reviewed Management command cannot have conflicting responses" }
            result[raw] = ExpectedCommand(label = "management-${probe::class.simpleName}", expectedCount = (prior?.expectedCount ?: 0) + count, response = response)
        }

        ManagementProbePlan.quickInspect(installation).forEach { addManagement(it, count = 2) }

        val plan = DeepDiagnosticProbePlan.forInstallation(installation)
        plan.primaryProbes.forEach { probe ->
            val command = requireNotNull(DeepDiagnosticReadOnlyCommandCompiler.compile(probe)) {
                "Canonical Deep Diagnostic primary probe failed compilation"
            }
            val raw = command.rawForTransport()
            check(isReviewedReadOnly(raw)) { "Deep compiler emitted command outside Phase 6.7 read-only witness policy" }
            val response = when (probe) {
                is DeepDiagnosticProbeSpec.ServiceDefinitionReadback -> FixtureResponse(
                    0,
                    "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; }\n",
                )
                is DeepDiagnosticProbeSpec.BinaryVersionReadback -> FixtureResponse(0, "v2.8.4\n")
                is DeepDiagnosticProbeSpec.DatabaseQuickCheck -> FixtureResponse(0, "ok\n")
                is DeepDiagnosticProbeSpec.DatabaseSchemaReadback -> FixtureResponse(0, "SUPPORTED\n")
                is DeepDiagnosticProbeSpec.CertificateReferencesReadback -> FixtureResponse(
                    0,
                    "CERT=$CERT_PATH\nKEY=$KEY_PATH\n",
                )
                is DeepDiagnosticProbeSpec.ExactCertificateFileReadback,
                is DeepDiagnosticProbeSpec.ExactPrivateKeyPresence,
                -> error("Derived probe cannot appear in primary list")
            }
            check(result.put(raw, ExpectedCommand("deep-${probe::class.simpleName}", 1, response)) == null) {
                "Deep primary command unexpectedly duplicates another reviewed command"
            }
        }

        DeepDiagnosticProbePlan.derivedCertificateProbes(
            DeepDiagnosticCertificateReferences(CERT_PATH, KEY_PATH),
        ).forEach { probe ->
            val command = requireNotNull(DeepDiagnosticReadOnlyCommandCompiler.compile(probe)) {
                "Canonical Deep Diagnostic derived probe failed compilation"
            }
            val raw = command.rawForTransport()
            check(isReviewedReadOnly(raw)) { "Derived compiler emitted command outside Phase 6.7 read-only witness policy" }
            val response = when (probe) {
                is DeepDiagnosticProbeSpec.ExactCertificateFileReadback -> FixtureResponse(
                    0,
                    "PRESENCE=PRESENT\nnotBefore=Jan 1 00:00:00 2020 GMT\nnotAfter=Jan 1 00:00:00 2099 GMT\n",
                )
                is DeepDiagnosticProbeSpec.ExactPrivateKeyPresence -> FixtureResponse(0, "PRESENT\n")
                else -> error("Unexpected derived probe")
            }
            check(result.put(raw, ExpectedCommand("derived-${probe::class.simpleName}", 1, response)) == null) {
                "Derived command unexpectedly duplicates another reviewed command"
            }
        }

        return result
    }

    private fun canonicalInstallation(): XuiInstallation = XuiInstallation(
        id = XuiInstallationId("phase67-fixture-installation"),
        serverId = ServerId("phase67-fixture-server"),
        ownership = InstallationOwnership.ADOPTED,
        identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = null,
        ),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = 54321,
            webBasePath = "/panel/",
            listenAddress = "127.0.0.1",
            capturedAt = Instant.parse("2026-09-06T12:00:00Z"),
        ),
    )

    /** Independent safety witness. This does not define production compilation, only rejects mutation-like output. */
    private fun isReviewedReadOnly(raw: String): Boolean {
        if (raw.isBlank() || '\n' in raw || '\r' in raw || '\u0000' in raw) return false
        val forbidden = listOf(
            " rm ", "mv ", "cp ", "chmod ", "chown ", "touch ", "mkdir ", "truncate ",
            "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable", "systemctl disable",
            "apt ", "apt-get ", "yum ", "dnf ", "pacman ", "apk add", "curl ", "wget ",
            "sqlite3 " + "'" + "/", // handled below only when paired with -readonly
            "iptables", "nft ", "ufw ", "firewall-cmd", "kill ", "pkill ", "reboot", "shutdown",
            " > ", ">>", "tee ", "sed -i", "perl -pi", "find / ", "cat /etc/shadow",
        )
        if (forbidden.any { token -> token in raw }) {
            // Targeted sqlite3 is permitted only in explicit -readonly form.
            if (!(raw.contains("sqlite3 -readonly") && forbidden.filterNot { it.startsWith("sqlite3 ") }.none { it in raw })) {
                return false
            }
        }
        if (raw.contains(KEY_PATH) && !(raw.contains("[ -f") || raw.contains("[ ! -e"))) return false
        return true
    }

    private fun cleanupRunnerMarkers(fixtureDir: Path) {
        listOf(READY_FILE, COMPLETED_FILE, UNEXPECTED_AUTH_FILE, UNEXPECTED_COMMAND_FILE, RELEASE_FILE)
            .forEach { name -> runCatching { Files.deleteIfExists(fixtureDir.resolve(name)) } }
    }

    private fun waitForMarker(path: Path, timeoutMillis: Long) {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(path)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 6.7 runner release marker")
    }

    private companion object {
        const val ENV_FIXTURE_DIR = "VELUM_PHASE67_FIXTURE_DIR"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase67"
        const val FIXTURE_PASSWORD = "VELUM-phase67-test-only-password"
        const val CERT_PATH = "/etc/ssl/x-ui/fullchain.pem"
        const val KEY_PATH = "/etc/ssl/x-ui/privkey.pem"

        const val READY_FILE = "ready.properties"
        const val COMPLETED_FILE = "management.completed"
        const val UNEXPECTED_AUTH_FILE = "unexpected.auth"
        const val UNEXPECTED_COMMAND_FILE = "unexpected.command"
        const val RELEASE_FILE = "release.marker"
        const val RELEASE_TIMEOUT_MILLIS = 240_000L
        const val POLL_INTERVAL_MILLIS = 50L

        fun sanitize(value: String): String = value.replace("\r", "?").replace("\n", "?").take(240)

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
