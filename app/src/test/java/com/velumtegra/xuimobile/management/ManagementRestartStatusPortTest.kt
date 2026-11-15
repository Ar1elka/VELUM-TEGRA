package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.*
import org.junit.Test

class ManagementRestartStatusPortTest {
    private val at = Instant.parse("2026-10-14T10:00:00Z")
    private fun snapshot(semantics: CheckpointSemantics, status: OperationStatus = OperationStatus.RUNNING,
        phase: String = "fixture-phase", access: String = "ssh-1", type: OperationType = OperationType.RESTART) =
        VersionedOperationSnapshot(OperationSnapshot(OperationId("operation-1"), type,
            OperationTarget.InstallationTarget(ServerId("server-1"), ServerAccessId(access), XuiInstallationId("install-1")),
            status, OperationCheckpoint(phase, semantics, at), at, at), OperationRevision(1))
    private fun port(current: VersionedOperationSnapshot) = JournalManagementRestartStatusPort(object : OperationJournal {
        override suspend fun get(operationId: OperationId) = OperationJournalResult.Success(current)
        override suspend fun listNonTerminal() = OperationJournalResult.Success(listOf(current))
        override suspend fun create(initial: OperationSnapshot) = error("Status must not write journal")
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot) = error("Status must not write journal")
        override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
    })
    private suspend fun read(p: ManagementRestartStatusPort, id: String = "operation-1") = p.readExact(id, "server-1", "install-1", "ssh-1")

    @Test fun `foreign id profile and operation type cannot become visible restart outcome`() = runSuspend {
        assertNull(read(port(snapshot(CheckpointSemantics.RESTART_IN_FLIGHT)), "foreign-operation"))
        assertNull(read(port(snapshot(CheckpointSemantics.RESTART_IN_FLIGHT, access = "foreign-access"))))
        assertNull(read(port(snapshot(CheckpointSemantics.MUTATION_NOT_STARTED, type = OperationType.QUICK_INSPECT))))
    }

    @Test fun `restart in flight permits only check and never advertises success or cancellation`() = runSuspend {
        val observation = checkNotNull(read(port(snapshot(CheckpointSemantics.RESTART_IN_FLIGHT))))
        assertFalse(observation.succeeded); assertFalse(observation.terminal)
        assertTrue(observation.mayCheckReadOnly); assertFalse(observation.mayCancelBeforeDispatch)
    }

    @Test fun `only exact verified terminal phase advertises restart success`() = runSuspend {
        assertFalse(checkNotNull(read(port(snapshot(CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED, "OTHER_SUCCEEDED")))).succeeded)
        val success = checkNotNull(read(port(snapshot(CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED, "RESTART_SUCCEEDED"))))
        assertTrue(success.succeeded); assertTrue(success.terminal)
        assertFalse(success.mayCheckReadOnly); assertFalse(success.mayCancelBeforeDispatch)
    }

    @Test fun `preflight failure is terminal with no restart success`() = runSuspend {
        val observation = checkNotNull(read(port(snapshot(CheckpointSemantics.TERMINAL, OperationStatus.FAILED, "RESTART_PREFLIGHT_DIRECT_ROOT_REQUIRED"))))
        assertTrue(observation.terminal); assertFalse(observation.succeeded)
        assertTrue(observation.text.contains("root")); assertFalse(observation.mayCheckReadOnly)
    }

    @Test fun `journal list remains exact and does not choose latest automatically`() = runSuspend {
        assertTrue(port(snapshot(CheckpointSemantics.MUTATION_NOT_STARTED, access = "foreign-access"))
            .unfinishedExact("server-1", "install-1", "ssh-1").isEmpty())
        val exact = port(snapshot(CheckpointSemantics.MUTATION_NOT_STARTED)).unfinishedExact("server-1", "install-1", "ssh-1")
        assertEquals(listOf(UnfinishedManagementRestart("operation-1", at)), exact)
    }
}
private fun <T> runSuspend(block: suspend () -> T): T {
    var outcome: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(result: Result<T>) { outcome = result }
    })
    return checkNotNull(outcome).getOrThrow()
}
