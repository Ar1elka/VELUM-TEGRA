package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VisibleDeepDiagnosticOperationLauncherTest {
    private val serverId = ServerId("server-66c")
    private val accessId = ServerAccessId("access-66c")
    private val installationId = XuiInstallationId("installation-66c")
    private val operationId = OperationId("operation-66c")
    private val instant = Instant.parse("2026-09-06T16:30:00Z")

    @Test
    fun `creates exact durable DEEP_DIAGNOSTIC only after exact Management relation is available`() = runSuspend {
        val journal = RecordingJournal()
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
        val result = launcher(journal, host).start(installationId, accessId)

        assertTrue(result is DeepDiagnosticOperationStartResult.Started)
        val started = result as DeepDiagnosticOperationStartResult.Started
        assertEquals(operationId, started.scope.operationId)
        assertEquals(serverId, started.scope.serverId)
        assertEquals(accessId, started.scope.serverAccessId)
        assertEquals(installationId, started.scope.installationId)
        assertEquals(operationId, host.startedOperationId)

        val snapshot = requireNotNull(journal.created)
        assertEquals(OperationType.DEEP_DIAGNOSTIC, snapshot.type)
        assertEquals(OperationTarget.InstallationTarget(serverId, accessId, installationId), snapshot.target)
        assertEquals(OperationStatus.RUNNING, snapshot.status)
        assertEquals("DEEP_DIAGNOSTIC", snapshot.checkpoint.phaseName)
        assertEquals(CheckpointSemantics.READ_ONLY, snapshot.checkpoint.semantics)
    }

    @Test
    fun `missing exact ManagementAccess fails before journal create and Android host`() = runSuspend {
        val journal = RecordingJournal()
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
        val result = launcher(
            journal = journal,
            host = host,
            accessRepository = FakeManagementAccessRepository(RepositoryResult.NotFound),
        ).start(installationId, accessId)

        assertEquals(DeepDiagnosticOperationStartResult.TargetUnavailable, result)
        assertNull(journal.created)
        assertNull(host.startedOperationId)
    }

    @Test
    fun `host rejection preserves exact durable operation and only safe process notice`() = runSuspend {
        val journal = RecordingJournal()
        val host = RecordingHostStart(ExactOperationHostStartResult.SECURITY_OR_POLICY_DENIED)
        val registry = DeepDiagnosticResultRegistry()
        val result = launcher(journal, host, registry = registry).start(installationId, accessId)

        assertTrue(result is DeepDiagnosticOperationStartResult.HostStartNotAccepted)
        assertTrue(registry.isTracked(operationId))
        assertEquals(DeepDiagnosticProcessNotice.HostStartRejected, registry.latestNotice(operationId))
        assertEquals(operationId, requireNotNull(journal.created).operationId)
    }

    @Test
    fun `resume rejects operation whose exact Management relation disappeared`() = runSuspend {
        val existing = VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = operationId,
                type = OperationType.DEEP_DIAGNOSTIC,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("DEEP_DIAGNOSTIC", CheckpointSemantics.READ_ONLY, instant),
                startedAt = instant,
                updatedAt = instant,
            ),
            revision = OperationRevision(2),
        )
        val journal = RecordingJournal(existing = existing)
        val host = RecordingHostStart(ExactOperationHostStartResult.START_REQUEST_ACCEPTED)
        val result = launcher(
            journal = journal,
            host = host,
            accessRepository = FakeManagementAccessRepository(RepositoryResult.NotFound),
        ).resume(operationId)

        assertEquals(
            DeepDiagnosticOperationResumeResult.NotRelaunchable(
                DeepDiagnosticOperationRelaunchBlock.EXACT_MANAGEMENT_TARGET_UNAVAILABLE,
            ),
            result,
        )
        assertNull(host.startedOperationId)
    }

    private fun launcher(
        journal: RecordingJournal,
        host: RecordingHostStart,
        registry: DeepDiagnosticResultRegistry = DeepDiagnosticResultRegistry(),
        installationRepository: XuiInstallationRepository = FakeInstallationRepository(),
        accessRepository: ManagementAccessRepository = FakeManagementAccessRepository(),
    ) = VisibleDeepDiagnosticOperationLauncher(
        journal = journal,
        installationRepository = installationRepository,
        managementAccessRepository = accessRepository,
        hostStart = host,
        resultRegistry = registry,
        now = { instant },
        operationIdFactory = { operationId },
    )

    private fun installation() = XuiInstallation(
        id = installationId,
        serverId = serverId,
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
            listenAddress = null,
            capturedAt = instant.minusSeconds(60),
        ),
    )

    private inner class FakeInstallationRepository(
        private val result: RepositoryResult<VersionedRecord<XuiInstallation>> = RepositoryResult.Success(
            VersionedRecord(installation(), RecordRevision(1)),
        ),
    ) : XuiInstallationRepository {
        override suspend fun get(installationId: XuiInstallationId) = result
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(emptyList<VersionedRecord<XuiInstallation>>())
        override suspend fun create(installation: XuiInstallation) = RepositoryResult.ConstraintConflict("unused")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = RepositoryResult.ConstraintConflict("unused")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = RepositoryResult.ConstraintConflict("unused")
    }

    private inner class FakeManagementAccessRepository(
        private val result: RepositoryResult<ManagementAccess> = RepositoryResult.Success(
            ManagementAccess(installationId, accessId),
        ),
    ) : ManagementAccessRepository {
        override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = result
        override suspend fun listForInstallation(installationId: XuiInstallationId) = RepositoryResult.Success(emptyList<ManagementAccess>())
        override suspend fun listForServerAccess(serverAccessId: ServerAccessId) = RepositoryResult.Success(emptyList<ManagementAccess>())
        override suspend fun create(access: ManagementAccess) = RepositoryResult.ConstraintConflict("unused")
        override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = RepositoryResult.ConstraintConflict("unused")
    }

    private class RecordingHostStart(
        private val result: ExactOperationHostStartResult,
    ) : DeepDiagnosticHostStartPort {
        var startedOperationId: OperationId? = null
        override fun start(operationId: OperationId): ExactOperationHostStartResult {
            startedOperationId = operationId
            return result
        }
    }

    private class RecordingJournal(
        private val existing: VersionedOperationSnapshot? = null,
    ) : OperationJournal {
        var created: OperationSnapshot? = null
        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
            created = initial
            return OperationJournalResult.Success(VersionedOperationSnapshot(initial, OperationRevision(0)))
        }
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            existing?.takeIf { it.snapshot.operationId == operationId }
                ?.let { OperationJournalResult.Success(it) }
                ?: OperationJournalResult.NotFound
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
