package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VisibleDiscoveryOperationLauncherTest {
    private val serverId = ServerId("server-56a")
    private val accessId = ServerAccessId("access-56a")
    private val operationId = OperationId("operation-56a")
    private val instant = Instant.parse("2026-09-06T08:10:00Z")

    @Test
    fun `creates exact durable read only Discovery before starting same host OperationId`() = runSuspend {
        val journal = RecordingJournal()
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
        val launcher = launcher(journal, host)

        val result = launcher.start(serverId, accessId)

        assertTrue(result is DiscoveryOperationStartResult.Started)
        val started = result as DiscoveryOperationStartResult.Started
        assertEquals(operationId, started.scope.operationId)
        assertEquals(serverId, started.scope.serverId)
        assertEquals(accessId, started.scope.serverAccessId)
        assertEquals(OperationRevision(0), started.revision)
        assertEquals(operationId, host.startedOperationId)

        val snapshot = requireNotNull(journal.created)
        assertEquals(operationId, snapshot.operationId)
        assertEquals(OperationType.DISCOVERY, snapshot.type)
        assertEquals(OperationTarget.ServerTarget(serverId, accessId), snapshot.target)
        assertEquals(OperationStatus.RUNNING, snapshot.status)
        assertEquals(CheckpointSemantics.READ_ONLY, snapshot.checkpoint.semantics)
        assertEquals("DISCOVER", snapshot.checkpoint.phaseName)
        assertEquals(instant, snapshot.startedAt)
        assertEquals(instant, snapshot.updatedAt)
    }

    @Test
    fun `journal create failure never starts Android host`() = runSuspend {
        val journal = RecordingJournal(
            createResult = OperationJournalResult.StorageFailure("db unavailable"),
        )
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)

        val result = launcher(journal, host).start(serverId, accessId)

        assertEquals(
            DiscoveryOperationStartResult.JournalFailure(
                DiscoveryOperationJournalFailureKind.STORAGE,
                "db unavailable",
            ),
            result,
        )
        assertNull(host.startedOperationId)
    }

    @Test
    fun `host rejection keeps exact durable operation and reports same scope`() = runSuspend {
        val journal = RecordingJournal()
        val host = RecordingHostStart(ExactOperationHostStartResult.NOT_ALLOWED_FROM_CURRENT_STATE)

        val result = launcher(journal, host).start(serverId, accessId)

        assertTrue(result is DiscoveryOperationStartResult.HostStartNotAccepted)
        val rejected = result as DiscoveryOperationStartResult.HostStartNotAccepted
        assertEquals(operationId, rejected.scope.operationId)
        assertEquals(OperationRevision(0), rejected.revision)
        assertEquals(ExactOperationHostStartResult.NOT_ALLOWED_FROM_CURRENT_STATE, rejected.reason)
        assertEquals(operationId, requireNotNull(journal.created).operationId)
    }

    @Test
    fun `host rejection publishes only safe process notice for exact tracked operation`() = runSuspend {
        val journal = RecordingJournal()
        val host = RecordingHostStart(ExactOperationHostStartResult.SECURITY_OR_POLICY_DENIED)
        val registry = DiscoveryResultRegistry()

        val result = launcher(journal, host, registry).start(serverId, accessId)

        assertTrue(result is DiscoveryOperationStartResult.HostStartNotAccepted)
        assertTrue(registry.isTracked(operationId))
        assertEquals(
            DiscoveryProcessNotice.HostStartRejected,
            registry.latestNotice(operationId),
        )
    }

    @Test
    fun `operation id collision is surfaced and never substitutes another id`() = runSuspend {
        val journal = RecordingJournal(createResult = OperationJournalResult.AlreadyExists)
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)

        val result = launcher(journal, host).start(serverId, accessId)

        assertEquals(DiscoveryOperationStartResult.OperationIdCollision(operationId), result)
        assertNull(host.startedOperationId)
    }

    @Test
    fun `resume starts only the supplied exact existing nonterminal Discovery OperationId`() = runSuspend {
        val existing = OperationId("existing-operation")
        val journal = RecordingJournal(
            existing = VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = existing,
                    type = OperationType.DISCOVERY,
                    target = OperationTarget.ServerTarget(serverId, accessId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("DISCOVER", CheckpointSemantics.READ_ONLY, instant),
                    startedAt = instant,
                    updatedAt = instant,
                ),
                OperationRevision(3),
            ),
        )
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
        val launcher = launcher(journal, host)

        val result = launcher.resume(existing)

        assertEquals(DiscoveryOperationResumeResult.StartRequestAccepted, result)
        assertEquals(existing, host.startedOperationId)
        assertNull(journal.created)
    }

    @Test
    fun `resume rejects non Discovery durable operation before Android host`() = runSuspend {
        val existing = OperationId("not-discovery")
        val journal = RecordingJournal(
            existing = VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = existing,
                    type = OperationType.QUICK_INSPECT,
                    target = OperationTarget.ServerTarget(serverId, accessId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("QUICK", CheckpointSemantics.READ_ONLY, instant),
                    startedAt = instant,
                    updatedAt = instant,
                ),
                OperationRevision(1),
            ),
        )
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)

        assertEquals(
            DiscoveryOperationResumeResult.NotRelaunchable(
                DiscoveryOperationRelaunchBlock.NOT_DISCOVERY_CONTRACT,
            ),
            launcher(journal, host).resume(existing),
        )
        assertNull(host.startedOperationId)
    }

    @Test
    fun `resume rejects terminal Discovery before Android host`() = runSuspend {
        val existing = OperationId("terminal-discovery")
        val terminalAt = instant.plusSeconds(2)
        val journal = RecordingJournal(
            existing = VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = existing,
                    type = OperationType.DISCOVERY,
                    target = OperationTarget.ServerTarget(serverId, accessId),
                    status = OperationStatus.SUCCEEDED,
                    checkpoint = OperationCheckpoint("DISCOVERY_RESULT_NONE", CheckpointSemantics.TERMINAL, terminalAt),
                    startedAt = instant,
                    updatedAt = terminalAt,
                ),
                OperationRevision(1),
            ),
        )
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)

        assertEquals(
            DiscoveryOperationResumeResult.NotRelaunchable(DiscoveryOperationRelaunchBlock.TERMINAL),
            launcher(journal, host).resume(existing),
        )
        assertNull(host.startedOperationId)
    }

    private fun launcher(
        journal: RecordingJournal,
        host: RecordingHostStart,
        registry: DiscoveryResultRegistry = DiscoveryResultRegistry(),
    ) = VisibleDiscoveryOperationLauncher(
        journal = journal,
        hostStart = host,
        resultRegistry = registry,
        now = { instant },
        operationIdFactory = { operationId },
    )

    private class RecordingHostStart(
        private val result: ExactOperationHostStartResult,
    ) : DiscoveryHostStartPort {
        var startedOperationId: OperationId? = null

        override fun start(operationId: OperationId): ExactOperationHostStartResult {
            startedOperationId = operationId
            return result
        }
    }

    private class RecordingJournal(
        private val createResult: OperationJournalResult<VersionedOperationSnapshot>? = null,
        private val existing: VersionedOperationSnapshot? = null,
    ) : OperationJournal {
        var created: OperationSnapshot? = null

        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
            created = initial
            return createResult ?: OperationJournalResult.Success(
                VersionedOperationSnapshot(initial, OperationRevision(0)),
            )
        }

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            existing?.takeIf { it.snapshot.operationId == operationId }
                ?.let { OperationJournalResult.Success(it) }
                ?: OperationJournalResult.NotFound

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(emptyList())

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> = OperationJournalResult.NotFound

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.NotFound
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext
            override fun resumeWith(result: Result<T>) {
                outcome = result
            }
        })
        return checkNotNull(outcome).getOrThrow()
    }
}
