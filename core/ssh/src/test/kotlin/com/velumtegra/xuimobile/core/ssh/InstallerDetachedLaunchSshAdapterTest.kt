package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.ReviewedInstallPlanPolicy
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.InstallerPlanStep
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedInstallPlan
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class InstallerDetachedLaunchSshAdapterTest {
    private val now = Instant.parse("2026-11-06T07:00:00Z")
    private val operationId = OperationId("detached-op")
    private val serverId = ServerId("server-a")
    private val accessId = ServerAccessId("access-a")
    private val managedId = ManagedInstallIdentityPolicy.forOperation(operationId)
    private val plan = canonicalPlan()

    // ---- dispatch / unknown fixtures ----------------------------------------------------

    @Test
    fun `confirmed hand-off runs three short commands after the CAS and records POST_VERIFY_REQUIRED without waiting`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val seenAdvances = mutableListOf<Int>()
        val handle = exactHandle { _, _ -> success() }.also { h -> h.onExecute = { seenAdvances += journal.advanceCount } }

        val result = InstallerSshExecutionAdapter(journal) { now }.launchDetached(plan, journal.current, handle)

        val launched = result as InstallerSshExecutionResult.DetachedWorkerLaunched
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, launched.durable.snapshot.checkpoint.semantics)
        assertEquals(3, handle.commands.size)
        // MUTATION_IN_FLIGHT CAS happened before the first command; POST_VERIFY after the last.
        assertEquals(listOf(1, 1, 1), seenAdvances)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, journal.advancedSnapshots.first().checkpoint.semantics)
        assertEquals(2, journal.advanceCount)
        val (guard, write, spawn) = handle.commands
        // Client commands never download, install, wait or publish the marker; the worker file does.
        listOf(guard, spawn).forEach { assertFalse(it.contains("curl")) }
        assertFalse(spawn.contains("while ") || spawn.contains("deadline"))
        assertFalse(guard.contains("install.sh") && guard.contains("XUI_NONINTERACTIVE"))
        assertTrue(write.contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_GIT_BLOB_SHA1))
        assertTrue(write.contains("XUI_NONINTERACTIVE=1"))
        assertTrue(spawn.contains("nohup setsid"))
        handle.configs.forEach {
            assertTrue(it.commandExecutionTimeout <= java.time.Duration.ofSeconds(10))
            assertTrue(it.stdoutCaptureLimitBytes <= 2 * 1024)
        }
    }

    @Test
    fun `guard held by another client is confirmed refusal that keeps the barrier and stops`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val handle = exactHandle { _, index -> if (index == 1) failure(77) else success() }

        val result = InstallerSshExecutionAdapter(journal) { now }.launchDetached(plan, journal.current, handle)

        val reconciliation = result as InstallerSshExecutionResult.ReconciliationRequired
        assertEquals(InstallerReconciliationReason.INSTALL_GUARD_HELD, reconciliation.reason)
        assertEquals(1, handle.commands.size)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliation.durable.snapshot.status)
    }

    @Test
    fun `unknown outcome on spawn keeps the barrier and is never retried`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val handle = exactHandle { _, index -> if (index == 3) unknown() else success() }

        val result = InstallerSshExecutionAdapter(journal) { now }.launchDetached(plan, journal.current, handle)

        val reconciliation = result as InstallerSshExecutionResult.ReconciliationRequired
        assertEquals(InstallerReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, reconciliation.reason)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, reconciliation.durable.snapshot.checkpoint.semantics)
        assertEquals(3, handle.commands.size)
    }

    @Test
    fun `undispatched and failed steps reconcile without replay`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val notDispatched = exactHandle { _, _ ->
            SshCommandResult(CommandDispatchState.NOT_DISPATCHED, CommandCompletion.Unknown("x"), CapturedOutput.EMPTY, CapturedOutput.EMPTY)
        }
        val first = InstallerSshExecutionAdapter(journal) { now }.launchDetached(plan, journal.current, notDispatched)
        assertEquals(
            InstallerReconciliationReason.DISPATCH_NOT_CONFIRMED,
            (first as InstallerSshExecutionResult.ReconciliationRequired).reason,
        )
        assertEquals(1, notDispatched.commands.size)

        val journal2 = FakeJournal(initialSnapshot())
        val failed = exactHandle { _, index -> if (index == 2) failure(73) else success() }
        val second = InstallerSshExecutionAdapter(journal2) { now }.launchDetached(plan, journal2.current, failed)
        assertEquals(
            InstallerReconciliationReason.REMOTE_STEP_FAILED,
            (second as InstallerSshExecutionResult.ReconciliationRequired).reason,
        )
        assertEquals(2, failed.commands.size)
    }

    @Test
    fun `wrong session or closed session is rejected before checkpoint or any command`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val wrong = FakeHandle(SessionBinding(SessionId("s"), accessId, SessionOwner.Operation(OperationId("other"))) , { _, _ -> success() })
        assertEquals(
            InstallerSshExecutionResult.Rejected(InstallerSshExecutionFailure.ExactSessionBindingMismatch),
            InstallerSshExecutionAdapter(journal) { now }.launchDetached(plan, journal.current, wrong),
        )
        val closed = exactHandle { _, _ -> success() }.also { it.close() }
        assertEquals(
            InstallerSshExecutionResult.Rejected(InstallerSshExecutionFailure.SessionClosed),
            InstallerSshExecutionAdapter(journal) { now }.launchDetached(plan, journal.current, closed),
        )
        assertEquals(0, journal.advanceCount)
        assertEquals(0, wrong.commands.size + closed.commands.size)
    }

    // ---- real shell ordering --------------------------------------------------------------

    @Test
    fun `worker publishes marker only after installer success and before terminal SUCCESS`() {
        val env = ShellEnv(installerBody =
            "if [ -e \"\$MARKER_PATH\" ]; then echo marker-present-during-install > \"\$LOG\"; " +
                "else echo marker-absent-during-install > \"\$LOG\"; fi; " +
                "i=0; while [ ! -f \"\$LOG.release\" ]; do i=\$((i+1)); " +
                "[ \"\$i\" -lt 15 ] || exit 70; sleep 1; done; exit 0")
        env.runSteps()
        assertFalse(File(env.work, "terminal").exists())
        File(env.log.path + ".release").writeText("release")

        env.awaitTerminal()
        assertTrue(File(env.work, "pid").readText().trim().matches(Regex("[1-9][0-9]*")))
        assertEquals(File(env.work, "pid").readText(), File(env.work, "pgid").readText())
        assertEquals("SUCCESS\n", File(env.work, "terminal").readText())
        assertEquals("marker-absent-during-install\n", env.log.readText())
        assertEquals(ManagedInstallMarkerProtocol.encode(managedId), env.marker.readText())
        assertTrue(File(env.work, "heartbeat").readText().trim().all { it.isDigit() })
        // The pinned installer copy is removed after a successful install; state markers stay.
        assertFalse(File(env.work, "install.sh").exists())
        assertFalse(File(env.markerDir, ".identity.${managedId.value}.tmp").exists())
        assertEquals("rw-------", env.perms(env.marker))
    }

    @Test
    fun `failed installer or hash mismatch never publishes a marker and writes terminal FAILED`() {
        val failing = ShellEnv(installerBody = "exit 3")
        failing.runSteps()
        failing.awaitTerminal()
        assertEquals("FAILED:3\n", File(failing.work, "terminal").readText())
        assertFalse(failing.marker.exists())

        val badHash = ShellEnv(installerBody = "echo should-not-run > \"\$LOG\"; exit 0", corruptHash = true)
        badHash.runSteps()
        badHash.awaitTerminal()
        assertEquals("FAILED:74\n", File(badHash.work, "terminal").readText())
        assertFalse(badHash.log.exists())
        assertFalse(badHash.marker.exists())
    }

    @Test
    fun `existing marker is never overwritten and terminal is FAILED 73`() {
        val env = ShellEnv(installerBody = "exit 0")
        env.markerDir.mkdirs()
        env.marker.writeText("FOREIGN\n")
        env.runSteps()
        env.awaitTerminal()
        assertEquals("FAILED:73\n", File(env.work, "terminal").readText())
        assertEquals("FOREIGN\n", env.marker.readText())
    }

    @Test
    fun `cross client guard is atomic and not released by the worker or a second prepare`() {
        val env = ShellEnv(installerBody = "exit 0")
        env.runSteps()
        env.awaitTerminal()
        assertTrue(File(env.root, ".install-guard").isDirectory)
        // Another client (different operation id => different work dir) cannot pass the guard.
        val other = env.compiledFor(OperationId("another-client-op"))
        val (guard, _, _) = other.map { env.localize(it.command.rawForTransport()) }
        assertEquals(77, env.sh(guard))
        assertTrue(File(env.root, ".install-guard").isDirectory)
    }

    // ---- fixtures -----------------------------------------------------------------------

    private inner class ShellEnv(installerBody: String, corruptHash: Boolean = false) {
        private val tmp: File = Files.createTempDirectory("velum-detached").toFile().also { it.deleteOnExit() }
        val root = File(tmp, "installer-v1")
        val markerDir = File(tmp, "managed-install-v1")
        val marker = File(markerDir, "identity")
        val log = File(tmp, "installer.log")
        val work = File(root, managedId.value)
        private val bin = File(tmp, "bin").also { it.mkdirs() }
        private val blobSha: String
        private val installerText = "#!/bin/sh\nMARKER_PATH='${marker.path}'\nLOG='${log.path}'\n$installerBody\n"

        init {
            assumeTrue(File("/bin/sh").exists() && listOf("setsid", "nohup", "sha1sum", "awk", "install", "ln").all { which(it) })
            // Fake curl: writes the "pinned installer" to the -o target; no network is ever used.
            val source = File(tmp, "installer-source.sh").also { it.writeText(installerText) }
            File(bin, "curl").writeText(
                "#!/bin/sh\nwhile [ \$# -gt 0 ]; do if [ \"\$1\" = -o ]; then out=\$2; fi; shift; done\ncp '${source.path}' \"\$out\"\n",
            )
            File(bin, "curl").setExecutable(true)
            blobSha = gitBlobSha1(installerText.toByteArray()).let { if (corruptHash) "0".repeat(40) else it }
        }

        fun localize(raw: String): String = raw
            .replace("/var/lib/velum-tegra/installer/v1", root.path)
            .replace("/var/lib/velum-tegra/managed-install/v1", markerDir.path)
            .replace(InstallerReviewedCommandCompiler.PINNED_INSTALLER_GIT_BLOB_SHA1, blobSha)

        fun compiledFor(op: OperationId) =
            requireNotNull(InstallerReviewedCommandCompiler.compileDetached(canonicalPlan(op))).steps

        fun runSteps() {
            val steps = requireNotNull(InstallerReviewedCommandCompiler.compileDetached(plan)).steps
            // Mirrors the production order exactly: guard/prepare, write worker, spawn.
            steps.forEachIndexed { index, step -> assertEquals("step $index", 0, sh(localize(step.command.rawForTransport()))) }
        }

        fun sh(script: String): Int {
            val process = ProcessBuilder("/bin/sh", "-c", script)
                .redirectErrorStream(true)
                .also { it.environment()["PATH"] = bin.path + ":" + System.getenv("PATH") }
                .start()
            process.inputStream.readBytes()
            assertTrue(process.waitFor(30, TimeUnit.SECONDS))
            return process.exitValue()
        }

        fun awaitTerminal() {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
            while (!File(work, "terminal").exists() && System.nanoTime() < deadline) Thread.sleep(50)
            assertTrue("worker did not finish", File(work, "terminal").exists())
        }

        fun perms(file: File): String =
            java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath()))

        private fun which(tool: String) = (System.getenv("PATH") ?: "").split(':').any { File(it, tool).canExecute() }
    }

    private fun gitBlobSha1(content: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-1")
        digest.update("blob ${content.size}\u0000".toByteArray())
        digest.update(content)
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun canonicalPlan(op: OperationId = operationId): ReviewedInstallPlan {
        val id = ManagedInstallIdentityPolicy.forOperation(op)
        val cap = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1
        return ReviewedInstallPlan(
            scope = InstallerWorkerScope(op, serverId, accessId, id),
            capability = cap,
            steps = listOf(
                InstallerPlanStep.PrepareWorker(ReviewedInstallPlanPolicy.PREPARE_WORKER_TIMEOUT),
                InstallerPlanStep.FetchReviewedInstaller(cap, ReviewedInstallPlanPolicy.FETCH_INSTALLER_TIMEOUT),
                InstallerPlanStep.ExecuteReviewedInstaller(cap, ReviewedInstallPlanPolicy.EXECUTE_INSTALLER_TIMEOUT),
                InstallerPlanStep.WriteManagedMarker(id, ReviewedInstallPlanPolicy.WRITE_MARKER_TIMEOUT),
            ),
        )
    }

    private fun initialSnapshot(): VersionedOperationSnapshot {
        val started = now.minusSeconds(60)
        return VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = operationId,
                type = OperationType.INSTALL,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, started),
                startedAt = started,
                updatedAt = now.minusSeconds(10),
            ),
            OperationRevision(0),
        )
    }

    private fun exactHandle(responder: (String, Int) -> SshCommandResult) = FakeHandle(
        SessionBinding(SessionId("detached-session"), accessId, SessionOwner.Operation(operationId)),
        responder,
    )

    private fun success() = SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess, CapturedOutput.EMPTY, CapturedOutput.EMPTY)
    private fun failure(exit: Int) = SshCommandResult(
        CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedFailure("exit", exit), CapturedOutput.EMPTY, CapturedOutput.EMPTY,
    )
    private fun unknown() = SshCommandResult(
        CommandDispatchState.DISPATCHED, CommandCompletion.Unknown("lost"), CapturedOutput.EMPTY, CapturedOutput.EMPTY,
    )

    private class FakeHandle(
        override val binding: SessionBinding,
        private val responder: (String, Int) -> SshCommandResult,
    ) : SshSessionHandle {
        val commands = mutableListOf<String>()
        val configs = mutableListOf<SshTransportConfig>()
        var onExecute: () -> Unit = {}
        private var closed = false
        override val isOpen: Boolean get() = !closed
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            commands += command.rawForTransport()
            configs += config
            onExecute()
            return responder(command.rawForTransport(), commands.size)
        }
        override fun close() { closed = true }
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current: VersionedOperationSnapshot = initial
            private set
        var advanceCount = 0
            private set
        val advancedSnapshots = mutableListOf<OperationSnapshot>()
        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.AlreadyExists
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(listOf(current))
        override suspend fun advance(
            operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCount += 1
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            advancedSnapshots += next
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }
}
