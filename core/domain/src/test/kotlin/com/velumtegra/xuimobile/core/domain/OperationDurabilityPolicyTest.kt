package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationDurabilityPolicyTest {
    private val startedAt = Instant.parse("2026-08-30T10:00:00Z")
    private val operationId = OperationId("op-durable")

    private fun snapshot(
        revision: Long = 1,
        status: OperationStatus = OperationStatus.RUNNING,
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
        updatedAt: Instant = startedAt.plusSeconds(20),
    ): VersionedOperationSnapshot = VersionedOperationSnapshot(
        snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.RECOVERY,
            target = OperationTarget.ServerTarget(ServerId("server-a"), ServerAccessId("access-a")),
            status = status,
            checkpoint = OperationCheckpoint("phase-$revision", semantics, updatedAt),
            startedAt = startedAt,
            updatedAt = updatedAt,
        ),
        revision = OperationRevision(revision),
    )

    private fun entry(
        revision: Long,
        status: OperationStatus = OperationStatus.RUNNING,
        semantics: CheckpointSemantics = if (revision == 1L) CheckpointSemantics.MUTATION_IN_FLIGHT else CheckpointSemantics.READ_ONLY,
        at: Instant = startedAt.plusSeconds((revision + 1) * 10),
    ) = OperationJournalEntry(
        operationId = operationId,
        revision = OperationRevision(revision),
        status = status,
        checkpoint = OperationCheckpoint("phase-$revision", semantics, at),
        recordedAt = at,
    )

    @Test
    fun `contiguous journal evidence matches current snapshot`() {
        val current = snapshot()
        val latest = entry(1)
        val result = OperationDurabilityPolicy.validateEvidence(
            current,
            OperationJournalEvidence(2, 0, 1, latest),
        )
        assertEquals(OperationDurabilityValidation.Valid, result)
    }

    @Test
    fun `missing revision is corruption even when max revision matches`() {
        val result = OperationDurabilityPolicy.validateEvidence(
            snapshot(revision = 2, updatedAt = startedAt.plusSeconds(30)),
            OperationJournalEvidence(2, 0, 2, entry(2, at = startedAt.plusSeconds(30))),
        )
        assertTrue(result is OperationDurabilityValidation.Corrupt)
    }

    @Test
    fun `latest journal checkpoint must match snapshot`() {
        val current = snapshot()
        val wrongLatest = entry(1).copy(
            checkpoint = OperationCheckpoint("other-phase", CheckpointSemantics.MUTATION_IN_FLIGHT, startedAt.plusSeconds(20)),
        )
        assertTrue(
            OperationDurabilityPolicy.validateEvidence(
                current,
                OperationJournalEvidence(2, 0, 1, wrongLatest),
            ) is OperationDurabilityValidation.Corrupt,
        )
    }

    @Test
    fun `full history rejects revision gap`() {
        val current = snapshot(revision = 2, updatedAt = startedAt.plusSeconds(30))
        val history = listOf(
            entry(0),
            entry(2, at = startedAt.plusSeconds(30)),
        )
        assertTrue(OperationDurabilityPolicy.validateHistory(current, history) is OperationDurabilityValidation.Corrupt)
    }

    @Test
    fun `full history rejects advance after terminal entry`() {
        val current = snapshot()
        val history = listOf(
            entry(0, status = OperationStatus.FAILED, semantics = CheckpointSemantics.TERMINAL),
            entry(1),
        )
        assertTrue(OperationDurabilityPolicy.validateHistory(current, history) is OperationDurabilityValidation.Corrupt)
    }

    @Test
    fun `terminal current state is valid when terminal journal agrees`() {
        val at = startedAt.plusSeconds(20)
        val current = snapshot(
            status = OperationStatus.SUCCEEDED,
            semantics = CheckpointSemantics.TERMINAL,
            updatedAt = at,
        )
        val history = listOf(
            entry(0),
            entry(1, status = OperationStatus.SUCCEEDED, semantics = CheckpointSemantics.TERMINAL, at = at),
        )
        assertEquals(OperationDurabilityValidation.Valid, OperationDurabilityPolicy.validateHistory(current, history))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `retention batch cannot be zero`() {
        TerminalRetentionBatchSize(0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `retention batch is bounded`() {
        TerminalRetentionBatchSize(101)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `retention cutoff cannot be in the future`() {
        TerminalOperationRetentionRequest(
            updatedBefore = startedAt.plusSeconds(1),
            observedAt = startedAt,
        )
    }
}
