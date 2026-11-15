package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationProof
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementFailureKind
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequenceResult
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagementResultProjectionTest {
    private val operationId = OperationId("management-projection-op")
    private val serverId = ServerId("management-projection-server")
    private val accessId = ServerAccessId("management-projection-access")
    private val installationId = XuiInstallationId("management-projection-installation")
    private val startedAt = Instant.parse("2026-09-06T12:10:00Z")
    private val completedAt = startedAt.plusSeconds(5)

    @Test
    fun `matching process local live snapshot is projected only at exact committed revision`() = runSuspend {
        val current = terminal(ManagementTerminalKind.RESULT)
        val registry = ManagementResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishCompleted(operationId, liveSnapshot(), current.revision)

        assertEquals(
            ManagementReadResult.Detailed(liveSnapshot()),
            ManagementResultProjector(FakeJournal(current), registry).read(operationId),
        )
    }

    @Test
    fun `process death fallback exposes only durable category scope and time not fresh proof`() = runSuspend {
        val current = terminal(ManagementTerminalKind.RESULT)

        assertEquals(
            ManagementReadResult.DurableTerminal(
                ManagementTerminalSummary(scope(), ManagementTerminalKind.RESULT, completedAt),
            ),
            ManagementResultProjector(FakeJournal(current), ManagementResultRegistry()).read(operationId),
        )
    }

    @Test
    fun `process local detail with stale committed revision fails closed`() = runSuspend {
        val current = terminal(ManagementTerminalKind.RESULT)
        val registry = ManagementResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishCompleted(operationId, liveSnapshot(), OperationRevision(current.revision.value + 1))

        assertTrue(
            ManagementResultProjector(FakeJournal(current), registry).read(operationId) is
                ManagementReadResult.ContractViolation,
        )
    }

    @Test
    fun `readback failure detail is exposed only with matching failed terminal revision`() = runSuspend {
        val current = terminal(ManagementTerminalKind.READBACK_FAILED)
        val registry = ManagementResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishReadbackFailure(operationId, ManagementFailureKind.MALFORMED_READBACK, current.revision)

        assertEquals(
            ManagementReadResult.DetailedFailure(
                scope(),
                ManagementFailureKind.MALFORMED_READBACK,
                completedAt,
            ),
            ManagementResultProjector(FakeJournal(current), registry).read(operationId),
        )
    }

    @Test
    fun `nonterminal state exposes only safe process notice`() = runSuspend {
        val registry = ManagementResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishNotice(
            operationId,
            ManagementProcessNotice.Failure(ManagementFailureKind.AUTHENTICATION_REJECTED),
        )

        assertEquals(
            ManagementReadResult.InProgress(
                scope = scope(),
                status = OperationStatus.RUNNING,
                phaseName = "QUICK_INSPECT",
                processNotice = ManagementProcessNotice.Failure(ManagementFailureKind.AUTHENTICATION_REJECTED),
            ),
            ManagementResultProjector(FakeJournal(nonTerminal()), registry).read(operationId),
        )
    }

    @Test
    fun `untracked detail and notice cannot enter registry`() {
        val registry = ManagementResultRegistry()
        registry.publishNotice(operationId, ManagementProcessNotice.WaitingForNetwork)
        registry.publishCompleted(operationId, liveSnapshot(), OperationRevision(1))
        assertNull(registry.latestNotice(operationId))
        assertNull(registry.latestDetail(operationId))
    }

    @Test
    fun `host mapping exposes only safe Management enum categories`() {
        assertEquals(
            ManagementProcessNotice.WaitingForNetwork,
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.WaitForNetwork,
            ).toManagementProcessNotice(),
        )
        assertEquals(
            ManagementProcessNotice.Failure(ManagementFailureKind.EXACT_ACCESS_UNAVAILABLE),
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.RecoveryBlocked(RecoveryBlockReason.EXACT_ACCESS_MISSING),
            ).toManagementProcessNotice(),
        )
        assertEquals(
            ManagementProcessNotice.Failure(ManagementFailureKind.INTERNAL_INVARIANT_FAILURE),
            ExactOperationHostRuntimeBindResult.ContractViolation("RAW_REASON_MUST_NOT_ESCAPE")
                .toManagementProcessNotice(),
        )
    }

    private fun scope() = ManagementScope(operationId, serverId, accessId, installationId)

    private fun liveSnapshot(): ManagementLiveSnapshot {
        val identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = null,
        )
        val proof = InstallationProof(
            id = TargetProofId("proof-65b"),
            installationId = installationId,
            serverId = serverId,
            serverAccessId = accessId,
            observedIdentity = identity,
            observedAt = completedAt.minusSeconds(2),
            validUntil = completedAt.plusSeconds(28),
        )
        return ManagementLiveSnapshot(
            scope = scope(),
            identityStatus = ManagementIdentityStatus.Matched,
            serviceState = ManagementServiceState.ACTIVE,
            baselineStatus = ManagementBaselineStatus.Matched,
            freshProof = proof,
            observedAt = completedAt.minusSeconds(1),
        )
    }

    private fun nonTerminal() = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.QUICK_INSPECT,
            target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint("QUICK_INSPECT", CheckpointSemantics.READ_ONLY, startedAt),
            startedAt = startedAt,
            updatedAt = startedAt,
        ),
        revision = OperationRevision(0),
    )

    private fun terminal(kind: ManagementTerminalKind) = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.QUICK_INSPECT,
            target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
            status = kind.operationStatus,
            checkpoint = OperationCheckpoint(kind.phaseName, CheckpointSemantics.TERMINAL, completedAt),
            startedAt = startedAt,
            updatedAt = completedAt,
        ),
        revision = OperationRevision(1),
    )

    private class FakeJournal(private val current: VersionedOperationSnapshot) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.AlreadyExists
        override suspend fun get(operationId: OperationId) =
            if (current.snapshot.operationId == operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = OperationJournalResult.Success(emptyList<VersionedOperationSnapshot>())
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot) = OperationJournalResult.NotFound
        override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(object : Continuation<T> {
            override val context = EmptyCoroutineContext
            override fun resumeWith(result: Result<T>) { outcome = result }
        })
        return checkNotNull(outcome).getOrThrow()
    }
}
