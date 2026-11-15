package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class ManagementInspectionReportAndHistoryTest {
    private val op = OperationId("inspection-exact")
    private val server = ServerId("server")
    private val install = XuiInstallationId("installation")
    private val access = ServerAccessId("access")
    private val time = Instant.parse("2026-10-15T12:00:00Z")
    private val revision = OperationRevision(2)

    @Test fun deepReportKeepsCriticalFindingsEvenWhenInspectionAndServiceSucceeded() = runBlocking {
        val current = terminal(OperationType.DEEP_DIAGNOSTIC)
        val registry = DeepDiagnosticResultRegistry()
        val findings = setOf(DeepDiagnosticFinding(DeepDiagnosticFindingCode.CERTIFICATE_EXPIRED,
            DeepDiagnosticSeverity.CRITICAL))
        val snapshot = DeepDiagnosticSnapshot(DeepDiagnosticScope(op, server, access, install),
            live(), findings, DeepDiagnosticOverallStatus.CRITICAL, time.plusSeconds(2))
        registry.beginAttempt(op)
        registry.publishCompleted(op, snapshot, revision)
        val result = reader(current, deep = registry).status(InspectionKind.DEEP_DIAGNOSTIC,
            op.value, server.value, install.value, access.value)
        assertTrue(result.terminal && result.succeeded)
        assertEquals(ManagementServiceState.ACTIVE, result.serviceState)
        assertEquals(DeepDiagnosticOverallStatus.CRITICAL, result.detail?.overall)
        assertEquals(findings, result.detail?.findings?.toSet())
        assertEquals(snapshot.observedAt, result.detail?.observedAt)
    }

    @Test fun quickReportPreservesSpecificIdentityDriftAndMissingBaselineEvidence() = runBlocking {
        val registry = ManagementResultRegistry()
        val snapshot = live().copy(identityStatus = ManagementIdentityStatus.Drift(setOf(
            ManagementIdentityDrift.MANAGED_MARKER_MISMATCH)), baselineStatus = ManagementBaselineStatus.Insufficient(
            setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED)))
        registry.beginAttempt(op)
        registry.publishCompleted(op, snapshot, revision)
        val result = reader(terminal(), quick = registry).status(InspectionKind.QUICK_INSPECT,
            op.value, server.value, install.value, access.value)
        assertEquals(snapshot.identityStatus, result.detail?.identity)
        assertEquals(snapshot.baselineStatus, result.detail?.baseline)
        assertNull(result.detail?.overall)
    }

    @Test fun processDeathExposesOnlyDurableCompletionTimeWithoutHealthOrFindings() = runBlocking {
        val result = reader(terminal(OperationType.DEEP_DIAGNOSTIC)).status(InspectionKind.DEEP_DIAGNOSTIC,
            op.value, server.value, install.value, access.value)
        assertTrue(result.terminal)
        assertFalse(result.succeeded)
        assertEquals(time.plusSeconds(5), result.completedAt)
        assertNull(result.detail)
        assertNull(result.serviceState)
        assertNull(result.observedAt)
    }

    @Test fun wrongOperationIdWithSameTargetCannotExposeAnotherReport() = runBlocking {
        val registry = ManagementResultRegistry()
        registry.beginAttempt(op)
        registry.publishCompleted(op, live(), revision)
        val result = reader(terminal(), quick = registry).status(InspectionKind.QUICK_INSPECT,
            "different-operation", server.value, install.value, access.value)
        assertNull(result.detail)
        assertNull(result.serviceState)
        assertFalse(result.succeeded)
    }

    @Test fun durableReadbackFailureRetainsFailureCategoryWithoutRemoteFacts() = runBlocking {
        val normal = terminal(OperationType.DEEP_DIAGNOSTIC)
        val failed = normal.copy(snapshot = normal.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = normal.snapshot.checkpoint.copy(phaseName = "DEEP_DIAGNOSTIC_FAILED")))
        val result = reader(failed).status(InspectionKind.DEEP_DIAGNOSTIC,
            op.value, server.value, install.value, access.value)
        assertTrue(result.text.contains("ошибкой"))
        assertTrue(result.terminal)
        assertFalse(result.succeeded)
        assertNull(result.detail)
        assertNull(result.serviceState)
    }

    @Test fun foreignAccessCannotExposeProcessLocalDiagnosticFacts() = runBlocking {
        val registry = ManagementResultRegistry()
        registry.beginAttempt(op)
        registry.publishCompleted(op, live(), revision)
        val result = reader(terminal(), quick = registry).status(InspectionKind.QUICK_INSPECT,
            op.value, server.value, install.value, "foreign-access")
        assertNull(result.detail)
        assertNull(result.serviceState)
    }

    @Test fun staleProcessRevisionDoesNotBecomeReportDetail() = runBlocking {
        val registry = ManagementResultRegistry()
        registry.beginAttempt(op)
        registry.publishCompleted(op, live(), OperationRevision(1))
        val result = reader(terminal(), quick = registry).status(InspectionKind.QUICK_INSPECT,
            op.value, server.value, install.value, access.value)
        assertNull(result.detail)
        assertFalse(result.succeeded)
    }

    @Test fun inventoryShowsFiftyNewestAndTruthfullyMarksOlderRecords() = runBlocking {
        val rows = (0..50).reversed().map { terminal(id = OperationId("op-" + it.toString().padStart(3, '0'))) }
        val port = JournalManagementInspectionHistoryPort(InstallationInspectionInventory { s, i ->
            assertEquals(server, s); assertEquals(install, i); OperationJournalResult.Success(rows)
        })
        val result = port.readExact(server.value, install.value) as InspectionHistoryRead.Page
        assertEquals(50, result.entries.size)
        assertTrue(result.hasOlder)
        assertEquals("op-000", result.entries.first().operationId)
        assertEquals("op-049", result.entries.last().operationId)
        assertEquals(OperationStatus.SUCCEEDED, result.entries.first().status)
    }

    @Test fun foreignAndDuplicateInventoryRowsFailClosed() = runBlocking {
        suspend fun read(rows: List<VersionedOperationSnapshot>) = JournalManagementInspectionHistoryPort(
            InstallationInspectionInventory { _, _ -> OperationJournalResult.Success(rows) })
            .readExact(server.value, install.value)
        val row = terminal()
        assertEquals(InspectionHistoryRead.Unavailable, read(listOf(row, row)))
        assertEquals(InspectionHistoryRead.Unavailable, read(listOf(row.copy(snapshot = row.snapshot.copy(
            target = OperationTarget.InstallationTarget(ServerId("foreign"), access, install))))))
    }

    @Test fun mutatedOrUnknownTerminalHistoryCannotMasqueradeAsInspectionHistory() = runBlocking {
        val normal = terminal()
        val unknown = normal.copy(snapshot = normal.snapshot.copy(checkpoint = normal.snapshot.checkpoint.copy(
            phaseName = "UNKNOWN_TERMINAL")))
        val port = JournalManagementInspectionHistoryPort(InstallationInspectionInventory { _, _ ->
            OperationJournalResult.Success(listOf(unknown)) })
        assertEquals(InspectionHistoryRead.Unavailable, port.readExact(server.value, install.value))
        val mutation = normal.copy(snapshot = normal.snapshot.copy(type = OperationType.RESTART))
        val other = JournalManagementInspectionHistoryPort(InstallationInspectionInventory { _, _ ->
            OperationJournalResult.Success(listOf(mutation)) })
        assertEquals(InspectionHistoryRead.Unavailable, other.readExact(server.value, install.value))
    }

    @Test fun storageFailureIsUnavailableRatherThanAnEmptySuccessfulHistory() = runBlocking {
        val port = JournalManagementInspectionHistoryPort(InstallationInspectionInventory { _, _ ->
            OperationJournalResult.StorageFailure("private internal reason") })
        assertEquals(InspectionHistoryRead.Unavailable, port.readExact(server.value, install.value))
    }

    private fun terminal(type: OperationType = OperationType.QUICK_INSPECT, id: OperationId = op) =
        VersionedOperationSnapshot(OperationSnapshot(id, type,
            OperationTarget.InstallationTarget(server, access, install), OperationStatus.SUCCEEDED,
            OperationCheckpoint(if (type == OperationType.DEEP_DIAGNOSTIC) "DEEP_DIAGNOSTIC_RESULT" else "QUICK_INSPECT_RESULT",
                CheckpointSemantics.TERMINAL, time.plusSeconds(5)), time, time.plusSeconds(5)), revision)

    private fun live() = ManagementLiveSnapshot(ManagementScope(op, server, access, install),
        ManagementIdentityStatus.Matched, ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched,
        null, time.plusSeconds(1))

    private fun reader(current: VersionedOperationSnapshot, quick: ManagementResultRegistry = ManagementResultRegistry(),
        deep: DeepDiagnosticResultRegistry = DeepDiagnosticResultRegistry()): ManagementInspectionStatusReader {
        val journal = object : OperationJournal {
            override suspend fun get(operationId: OperationId) = OperationJournalResult.Success(current)
            override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> = throw AssertionError("No inventory fallback")
            override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> = throw AssertionError("Read must not create")
            override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision,
                next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> = throw AssertionError("Read must not advance")
            override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> = throw AssertionError("No alternate record")
        }
        return ManagementInspectionStatusReader(ManagementResultProjector(journal, quick),
            DeepDiagnosticResultProjector(journal, deep), journal)
    }
}
