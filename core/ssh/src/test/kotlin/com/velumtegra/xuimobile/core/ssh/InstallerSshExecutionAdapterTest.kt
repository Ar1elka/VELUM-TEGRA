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
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
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
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerSshExecutionAdapterTest {
    private val now = Instant.parse("2026-09-12T07:00:00Z")
    private val operationId = OperationId("install-operation-a")
    private val serverId = ServerId("server-a")
    private val accessId = ServerAccessId("access-a")
    private val managedInstallId = ManagedInstallIdentityPolicy.forOperation(operationId)
    private val plan = canonicalPlan(managedInstallId)

    @Test fun `archive prerequisite never installs before successful bounded download and hash verification`() {
        val script = InstallerReviewedCommandCompiler.ENSURE_SQLITE_CLI_STEP
        val archive = script.substringAfter("case \"\$file\" in")
        assertTrue(archive.contains("pool/updates/*.deb)"))
        assertTrue(archive.contains("http://archive.debian.org/debian-security/\$file"))
        val download = archive.indexOf("curl -fsS --max-time 120")
        val checksum = archive.indexOf("sha256sum -c --quiet -")
        val install = archive.indexOf("dpkg -i")
        assertTrue(download >= 0 && download < checksum && checksum < install)
        assertTrue(archive.substring(download, install).split("&&").size >= 3)
        assertTrue(script.contains("apt-cache policy sqlite3"))
        assertTrue(script.contains("apt-cache show \"sqlite3=\$cand\""))
        assertFalse(script.contains("--allow-unauthenticated"))
        assertFalse(script.contains("sources.list"))
    }

    @Test fun `sqlite prerequisite waits for apt lock and cleans the downloaded package`() {
        val script = InstallerReviewedCommandCompiler.ENSURE_SQLITE_CLI_STEP
        assertTrue(script.contains("command -v sqlite3"))
        assertTrue(script.contains("DPkg::Lock::Timeout=600"))
        assertTrue(script.contains("DEBIAN_FRONTEND=noninteractive"))
        assertTrue(script.contains("rm -f \"\$deb\""))
        assertFalse(script.contains("kill "))
        assertFalse(script.contains("rm /var/lib/dpkg/lock"))
    }

    @Test fun `missing curl is provisioned before fetching and cannot bypass pinned installer verification`() {
        val fetch = requireNotNull(InstallerReviewedCommandCompiler.compile(plan)).steps[1].command.rawForTransport()
        val provision = fetch.indexOf("apt-get install -y -q --no-install-recommends")
        val requireCurl = fetch.indexOf("command -v curl >/dev/null 2>&1 || exit 69")
        val download = fetch.indexOf("curl --proto '=https'")
        assertTrue(provision >= 0 && provision < requireCurl && requireCurl < download)
        assertTrue(fetch.contains("curl ca-certificates"))
        assertTrue(fetch.contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_URL))
        assertTrue(fetch.contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_GIT_BLOB_SHA1))
    }

    @Test fun `readiness allows only curl to be provisioned through apt`() {
        val raw = FreshInstallReadinessCommandCompiler.requiredTools.command.rawForTransport()
        assertTrue(raw.contains("elif [ \"\$t\" = 'curl' ] && command -v 'apt-get'"))
        assertTrue(raw.contains("else printf '%s A\\n'"))
        assertFalse(raw.contains("apt-get install"))
    }

    @Test
    fun `compiler accepts only the exact canonical plan and pins reviewed upstream source`() {
        val compiled = requireNotNull(InstallerReviewedCommandCompiler.compile(plan))
        assertEquals(4, compiled.steps.size)
        assertEquals(
            listOf("PREPARE_WORKER", "FETCH_REVIEWED_INSTALLER", "EXECUTE_REVIEWED_INSTALLER", "WRITE_MANAGED_MARKER"),
            compiled.steps.map { it.kind.name },
        )

        val commands = compiled.steps.map { it.command.rawForTransport() }
        val fetch = commands[1]
        val execute = commands[2]
        assertTrue(fetch.contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_URL))
        assertTrue(fetch.contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_GIT_BLOB_SHA1))
        assertFalse(fetch.contains("/master/"))
        assertTrue(execute.contains("XUI_NONINTERACTIVE=1"))
        assertTrue(execute.contains("nohup setsid"))
        assertTrue(execute.contains("heartbeat"))
        assertTrue(execute.contains("deadline="))
        assertTrue(execute.contains(InstallerReviewedCommandCompiler.PINNED_3X_UI_VERSION))
        assertTrue(commands.last().contains(ManagedInstallMarkerProtocol.MARKER_PATH))
        assertTrue(compiled.steps.all { it.config.commandExecutionTimeout <= Duration.ofMinutes(15) })
    }

    @Test
    fun `forged timeout plan is rejected before SSH and journal mutation`() = runBlocking {
        val forged = plan.copy(
            steps = plan.steps.toMutableList().also {
                it[0] = InstallerPlanStep.PrepareWorker(Duration.ofSeconds(11))
            },
        )
        val journal = FakeJournal(initialSnapshot())
        val handle = exactHandle { _, _ -> error("must not execute") }

        val result = InstallerSshExecutionAdapter(journal) { now }.execute(forged, journal.current, handle)
        assertEquals(
            InstallerSshExecutionFailure.PlanOutsideApprovedPolicy,
            (result as InstallerSshExecutionResult.Rejected).failure,
        )
        assertEquals(0, journal.advanceCount)
        assertEquals(0, handle.executions)
    }

    @Test
    fun `wrong exact session binding fails before durable checkpoint or dispatch`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val handle = FakeHandle(
            SessionBinding(SessionId("wrong"), ServerAccessId("other-access"), SessionOwner.Operation(operationId)),
        ) { _, _ -> error("must not execute") }

        val result = InstallerSshExecutionAdapter(journal) { now }.execute(plan, journal.current, handle)
        assertEquals(
            InstallerSshExecutionFailure.ExactSessionBindingMismatch,
            (result as InstallerSshExecutionResult.Rejected).failure,
        )
        assertEquals(0, journal.advanceCount)
        assertEquals(0, handle.executions)
    }

    @Test
    fun `durable in-flight checkpoint must commit before first remote command`() = runBlocking {
        val journal = FakeJournal(initialSnapshot(), rejectNextAdvance = true)
        val handle = exactHandle { _, _ -> error("must not execute") }

        val result = InstallerSshExecutionAdapter(journal) { now }.execute(plan, journal.current, handle)
        assertEquals(
            InstallerSshExecutionFailure.PredispatchCheckpointRejected,
            (result as InstallerSshExecutionResult.Rejected).failure,
        )
        assertEquals(1, journal.advanceCount)
        assertEquals(0, handle.executions)
    }

    @Test
    fun `happy path stops at post verify required after exact managed marker readback`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val encodedMarker = ManagedInstallMarkerProtocol.encode(managedInstallId)
        val handle = exactHandle { _, index ->
            if (index == 5) success(encodedMarker) else success()
        }

        val result = InstallerSshExecutionAdapter(journal) { now }.execute(plan, journal.current, handle)
        val awaiting = result as InstallerSshExecutionResult.AwaitingVerification
        assertEquals(ManagedInstallMarkerReadbackState.MATCH, awaiting.markerReadback)
        assertEquals(OperationStatus.RUNNING, awaiting.durable.snapshot.status)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, awaiting.durable.snapshot.checkpoint.semantics)
        assertEquals("VERIFYING", awaiting.durable.snapshot.checkpoint.phaseName)
        assertEquals(5, handle.executions)
        assertEquals(2, journal.advanceCount)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, journal.advancedSnapshots[0].checkpoint.semantics)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, journal.advancedSnapshots[1].checkpoint.semantics)
    }

    @Test
    fun `post dispatch uncertainty is never retried and becomes durable reconciliation required`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val handle = exactHandle { _, _ ->
            SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = CommandCompletion.Unknown("fixture transport loss"),
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )
        }

        val result = InstallerSshExecutionAdapter(journal) { now }.execute(plan, journal.current, handle)
        val reconciliation = result as InstallerSshExecutionResult.ReconciliationRequired
        assertEquals(InstallerReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, reconciliation.reason)
        assertTrue(reconciliation.reconciliationCheckpointRecorded)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliation.durable.snapshot.status)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, reconciliation.durable.snapshot.checkpoint.semantics)
        assertEquals(1, handle.executions)
        assertEquals(2, journal.advanceCount)
    }

    @Test
    fun `marker mismatch after successful mutation cannot publish success`() = runBlocking {
        val journal = FakeJournal(initialSnapshot())
        val otherMarker = ManagedInstallMarkerProtocol.encode(ManagedInstallId("v1-0123456789abcdef0123456789abcdef"))
        val handle = exactHandle { _, index -> if (index == 5) success(otherMarker) else success() }

        val result = InstallerSshExecutionAdapter(journal) { now }.execute(plan, journal.current, handle)
        val reconciliation = result as InstallerSshExecutionResult.ReconciliationRequired
        assertEquals(InstallerReconciliationReason.MANAGED_MARKER_MISMATCH, reconciliation.reason)
        assertTrue(reconciliation.reconciliationCheckpointRecorded)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliation.durable.snapshot.status)
        assertEquals(5, handle.executions)
    }

    private fun canonicalPlan(managedId: ManagedInstallId): ReviewedInstallPlan = ReviewedInstallPlan(
        scope = InstallerWorkerScope(operationId, serverId, accessId, managedId),
        capability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
        steps = listOf(
            InstallerPlanStep.PrepareWorker(ReviewedInstallPlanPolicy.PREPARE_WORKER_TIMEOUT),
            InstallerPlanStep.FetchReviewedInstaller(
                FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                ReviewedInstallPlanPolicy.FETCH_INSTALLER_TIMEOUT,
            ),
            InstallerPlanStep.ExecuteReviewedInstaller(
                FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                ReviewedInstallPlanPolicy.EXECUTE_INSTALLER_TIMEOUT,
            ),
            InstallerPlanStep.WriteManagedMarker(managedId, ReviewedInstallPlanPolicy.WRITE_MARKER_TIMEOUT),
        ),
    )

    private fun initialSnapshot(): VersionedOperationSnapshot {
        val started = now.minusSeconds(60)
        return VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = operationId,
                type = OperationType.INSTALL,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, started),
                startedAt = started,
                updatedAt = now.minusSeconds(10),
            ),
            revision = OperationRevision(0),
        )
    }

    private fun exactHandle(
        responder: (String, Int) -> SshCommandResult,
    ): FakeHandle = FakeHandle(
        SessionBinding(SessionId("installer-session"), accessId, SessionOwner.Operation(operationId)),
        responder,
    )

    private fun success(stdout: String = ""): SshCommandResult = SshCommandResult(
        dispatchState = CommandDispatchState.DISPATCHED,
        completion = CommandCompletion.ConfirmedSuccess,
        stdout = CapturedOutput.of(stdout.toByteArray(), truncated = false),
        stderr = CapturedOutput.EMPTY,
    )

    private class FakeHandle(
        override val binding: SessionBinding,
        private val responder: (String, Int) -> SshCommandResult,
    ) : SshSessionHandle {
        private var closed = false
        var executions: Int = 0
            private set

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            executions += 1
            return responder(command.rawForTransport(), executions)
        }

        override fun close() {
            closed = true
        }
    }

    private class FakeJournal(
        initial: VersionedOperationSnapshot,
        private var rejectNextAdvance: Boolean = false,
    ) : OperationJournal {
        var current: VersionedOperationSnapshot = initial
            private set
        var advanceCount: Int = 0
            private set
        val advancedSnapshots = mutableListOf<OperationSnapshot>()

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.AlreadyExists

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(listOf(current))

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCount += 1
            if (rejectNextAdvance) {
                rejectNextAdvance = false
                return OperationJournalResult.StorageFailure("fixture")
            }
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) {
                return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            }
            advancedSnapshots += next
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }
}
