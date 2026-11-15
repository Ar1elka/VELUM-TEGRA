package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFinding
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFindingCode
import com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.DeepDiagnosticSeverity
import com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot
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

class DeepDiagnosticResultProjectionTest {
    private val operationId = OperationId("deep-projection-op")
    private val serverId = ServerId("deep-projection-server")
    private val accessId = ServerAccessId("deep-projection-access")
    private val installationId = XuiInstallationId("deep-projection-installation")
    private val startedAt = Instant.parse("2026-09-06T16:40:00Z")
    private val completedAt = startedAt.plusSeconds(8)

    @Test
    fun `matching process local snapshot is projected only at exact committed revision`() = runSuspend {
        val current = terminal(DeepDiagnosticTerminalKind.RESULT)
        val registry = DeepDiagnosticResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishCompleted(operationId, deepSnapshot(), current.revision)

        assertEquals(
            DeepDiagnosticReadResult.Detailed(deepSnapshot()),
            DeepDiagnosticResultProjector(FakeJournal(current), registry).read(operationId),
        )
    }

    @Test
    fun `process death fallback exposes only durable category scope and time`() = runSuspend {
        val current = terminal(DeepDiagnosticTerminalKind.RESULT)

        assertEquals(
            DeepDiagnosticReadResult.DurableTerminal(
                DeepDiagnosticTerminalSummary(scope(), DeepDiagnosticTerminalKind.RESULT, completedAt),
            ),
            DeepDiagnosticResultProjector(FakeJournal(current), DeepDiagnosticResultRegistry()).read(operationId),
        )
    }

    @Test
    fun `process local detail with stale committed revision fails closed`() = runSuspend {
        val current = terminal(DeepDiagnosticTerminalKind.RESULT)
        val registry = DeepDiagnosticResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishCompleted(operationId, deepSnapshot(), OperationRevision(current.revision.value + 1))

        assertTrue(
            DeepDiagnosticResultProjector(FakeJournal(current), registry).read(operationId) is
                DeepDiagnosticReadResult.ContractViolation,
        )
    }

    @Test
    fun `readback failure detail requires matching failed terminal revision`() = runSuspend {
        val current = terminal(DeepDiagnosticTerminalKind.READBACK_FAILED)
        val registry = DeepDiagnosticResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishReadbackFailure(operationId, ManagementFailureKind.MALFORMED_READBACK, current.revision)

        assertEquals(
            DeepDiagnosticReadResult.DetailedFailure(
                scope(),
                ManagementFailureKind.MALFORMED_READBACK,
                completedAt,
            ),
            DeepDiagnosticResultProjector(FakeJournal(current), registry).read(operationId),
        )
    }

    @Test
    fun `nonterminal state exposes only safe process notice`() = runSuspend {
        val registry = DeepDiagnosticResultRegistry()
        registry.beginAttempt(operationId)
        registry.publishNotice(
            operationId,
            DeepDiagnosticProcessNotice.Failure(ManagementFailureKind.AUTHENTICATION_REJECTED),
        )

        assertEquals(
            DeepDiagnosticReadResult.InProgress(
                scope = scope(),
                status = OperationStatus.RUNNING,
                phaseName = "DEEP_DIAGNOSTIC",
                processNotice = DeepDiagnosticProcessNotice.Failure(ManagementFailureKind.AUTHENTICATION_REJECTED),
            ),
            DeepDiagnosticResultProjector(FakeJournal(nonTerminal()), registry).read(operationId),
        )
    }

    @Test
    fun `untracked detail and notice cannot enter registry`() {
        val registry = DeepDiagnosticResultRegistry()
        registry.publishNotice(operationId, DeepDiagnosticProcessNotice.WaitingForNetwork)
        registry.publishCompleted(operationId, deepSnapshot(), OperationRevision(1))
        assertNull(registry.latestNotice(operationId))
        assertNull(registry.latestDetail(operationId))
    }

    @Test
    fun `host mapping exposes only safe Deep Diagnostic enum categories`() {
        assertEquals(
            DeepDiagnosticProcessNotice.WaitingForNetwork,
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.WaitForNetwork,
            ).toDeepDiagnosticProcessNotice(),
        )
        assertEquals(
            DeepDiagnosticProcessNotice.Failure(ManagementFailureKind.EXACT_ACCESS_UNAVAILABLE),
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.RecoveryBlocked(RecoveryBlockReason.EXACT_ACCESS_MISSING),
            ).toDeepDiagnosticProcessNotice(),
        )
        assertEquals(
            DeepDiagnosticProcessNotice.Failure(ManagementFailureKind.INTERNAL_INVARIANT_FAILURE),
            ExactOperationHostRuntimeBindResult.ContractViolation("RAW_REASON_MUST_NOT_ESCAPE")
                .toDeepDiagnosticProcessNotice(),
        )
    }

    private fun scope() = DeepDiagnosticScope(operationId, serverId, accessId, installationId)

    private fun deepSnapshot(): DeepDiagnosticSnapshot {
        val management = ManagementLiveSnapshot(
            scope = ManagementScope(operationId, serverId, accessId, installationId),
            identityStatus = ManagementIdentityStatus.Matched,
            serviceState = ManagementServiceState.ACTIVE,
            baselineStatus = ManagementBaselineStatus.Matched,
            freshProof = null,
            observedAt = completedAt.minusSeconds(2),
        )
        return DeepDiagnosticSnapshot(
            scope = scope(),
            managementSnapshot = management,
            findings = setOf(
                DeepDiagnosticFinding(
                    DeepDiagnosticFindingCode.BINARY_VERSION_UNAVAILABLE,
                    DeepDiagnosticSeverity.INFO,
                ),
            ),
            overallStatus = DeepDiagnosticOverallStatus.HEALTHY,
            observedAt = completedAt.minusSeconds(1),
        )
    }

    private fun nonTerminal() = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.DEEP_DIAGNOSTIC,
            target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint("DEEP_DIAGNOSTIC", CheckpointSemantics.READ_ONLY, startedAt),
            startedAt = startedAt,
            updatedAt = startedAt,
        ),
        revision = OperationRevision(0),
    )

    private fun terminal(kind: DeepDiagnosticTerminalKind) = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.DEEP_DIAGNOSTIC,
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
