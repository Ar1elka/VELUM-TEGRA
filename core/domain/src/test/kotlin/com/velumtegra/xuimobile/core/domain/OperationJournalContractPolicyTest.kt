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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class OperationJournalContractPolicyTest {
    private val startedAt = Instant.parse("2026-08-30T08:00:00Z")

    private fun snapshot(
        operationId: OperationId = OperationId("op-1"),
        type: OperationType = OperationType.DISCOVERY,
        target: OperationTarget = OperationTarget.ServerTarget(ServerId("server-1"), ServerAccessId("access-1")),
        status: OperationStatus = OperationStatus.RUNNING,
        semantics: CheckpointSemantics = CheckpointSemantics.READ_ONLY,
        checkpointAt: Instant = startedAt.plusSeconds(10),
        updatedAt: Instant = checkpointAt,
        operationStartedAt: Instant = startedAt,
    ) = OperationSnapshot(
        operationId = operationId,
        type = type,
        target = target,
        status = status,
        checkpoint = OperationCheckpoint("phase", semantics, checkpointAt),
        startedAt = operationStartedAt,
        updatedAt = updatedAt,
    )

    @Test
    fun `valid advance keeps exact operation identity`() {
        val previous = snapshot()
        val next = snapshot(
            status = OperationStatus.WAITING,
            checkpointAt = startedAt.plusSeconds(20),
            updatedAt = startedAt.plusSeconds(20),
        )

        assertEquals(OperationSnapshotValidation.Valid, OperationJournalContractPolicy.validateAdvance(previous, next))
    }

    @Test
    fun `target drift is rejected`() {
        val previous = snapshot()
        val next = snapshot(
            target = OperationTarget.ServerTarget(ServerId("server-1"), ServerAccessId("access-2")),
            checkpointAt = startedAt.plusSeconds(20),
            updatedAt = startedAt.plusSeconds(20),
        )

        assertTrue(OperationJournalContractPolicy.validateAdvance(previous, next) is OperationSnapshotValidation.Invalid)
    }

    @Test
    fun `type drift is rejected`() {
        val previous = snapshot()
        val next = snapshot(
            type = OperationType.QUICK_INSPECT,
            checkpointAt = startedAt.plusSeconds(20),
            updatedAt = startedAt.plusSeconds(20),
        )

        assertTrue(OperationJournalContractPolicy.validateAdvance(previous, next) is OperationSnapshotValidation.Invalid)
    }

    @Test
    fun `startedAt drift is rejected`() {
        val previous = snapshot()
        val next = snapshot(
            operationStartedAt = startedAt.plusSeconds(1),
            checkpointAt = startedAt.plusSeconds(20),
            updatedAt = startedAt.plusSeconds(20),
        )

        assertTrue(OperationJournalContractPolicy.validateAdvance(previous, next) is OperationSnapshotValidation.Invalid)
    }

    @Test
    fun `updatedAt rewind is rejected`() {
        val previous = snapshot(
            checkpointAt = startedAt.plusSeconds(20),
            updatedAt = startedAt.plusSeconds(20),
        )
        val next = snapshot(
            checkpointAt = startedAt.plusSeconds(15),
            updatedAt = startedAt.plusSeconds(15),
        )

        assertTrue(OperationJournalContractPolicy.validateAdvance(previous, next) is OperationSnapshotValidation.Invalid)
    }

    @Test
    fun `terminal snapshot requires terminal checkpoint semantics`() {
        val invalid = snapshot(
            status = OperationStatus.SUCCEEDED,
            semantics = CheckpointSemantics.COMMIT_VERIFIED,
        )

        assertTrue(OperationJournalContractPolicy.validateInitial(invalid) is OperationSnapshotValidation.Invalid)
    }

    @Test
    fun `terminal checkpoint requires terminal status`() {
        val invalid = snapshot(
            status = OperationStatus.RUNNING,
            semantics = CheckpointSemantics.TERMINAL,
        )

        assertTrue(OperationJournalContractPolicy.validateInitial(invalid) is OperationSnapshotValidation.Invalid)
    }

    @Test
    fun `terminal operation cannot advance`() {
        val previous = snapshot(
            status = OperationStatus.SUCCEEDED,
            semantics = CheckpointSemantics.TERMINAL,
        )
        val next = previous.copy(
            updatedAt = previous.updatedAt.plusSeconds(1),
            checkpoint = previous.checkpoint.copy(recordedAt = previous.checkpoint.recordedAt.plusSeconds(1)),
        )

        assertTrue(OperationJournalContractPolicy.validateAdvance(previous, next) is OperationSnapshotValidation.Invalid)
    }
}
