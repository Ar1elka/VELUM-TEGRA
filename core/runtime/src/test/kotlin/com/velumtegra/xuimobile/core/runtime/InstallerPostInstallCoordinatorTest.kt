package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.InstallerManagementPublicationRequest
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallFacts
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRequest
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.InstallerWorkerEvidence
import com.velumtegra.xuimobile.core.model.InstallerWorkerProcessState
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.InstallerWorkerTerminalState
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.CapturedOutput
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteReconciliation
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteVerificationResult
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallRemoteVerifier
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerPostInstallCoordinatorTest {
    private val now = Instant.parse("2026-09-12T07:00:00Z")
    private val operationId = OperationId("install-post-verify-runtime")
    private val serverId = ServerId("server-a")
    private val accessId = ServerAccessId("access-a")
    private val managedId = ManagedInstallIdentityPolicy.forOperation(operationId)
    private val scope = InstallerWorkerScope(operationId, serverId, accessId, managedId)

    @Test
    fun verifiedRemoteFactsPublishExactManagementStateThenTerminalize() = runBlocking {
        val journal = FakeJournal(postVerifySnapshot())
        val publisher = FakePublisher()
        val verifier = FakeVerifier(verifiedRemote())
        val coordinator = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }

        val result = coordinator.reconcileAndPublish(journal.current, session())
        val success = result as InstallerPostInstallCoordinatorResult.Succeeded

        assertEquals(OperationStatus.SUCCEEDED, success.durable.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, success.durable.snapshot.checkpoint.semantics)
        assertEquals(InstallerPostInstallPolicy.installationIdFor(scope), success.installationId)
        assertEquals(1, publisher.installerCalls)
        assertEquals(0, publisher.discoveryCalls)
        assertEquals(2, journal.advanceCount)
        assertEquals(CheckpointSemantics.COMMIT_VERIFIED, journal.advanced[0].checkpoint.semantics)
        assertEquals(CheckpointSemantics.TERMINAL, journal.advanced[1].checkpoint.semantics)
    }

    @Test
    fun markerMismatchCannotReachAtomicPublisher() = runBlocking {
        val journal = FakeJournal(postVerifySnapshot())
        val publisher = FakePublisher()
        val verifier = FakeVerifier(
            verifiedRemote(goodFacts().copy(markerReadback = ManagedInstallMarkerReadbackState.MISMATCH)),
        )

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .reconcileAndPublish(journal.current, session())
        val reconciliation = result as InstallerPostInstallCoordinatorResult.ReconciliationRequired

        assertEquals(InstallerPostInstallReconciliationReason.REMOTE_FACTS_REJECTED, reconciliation.reason)
        assertEquals(0, publisher.installerCalls)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliation.durable.snapshot.status)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, reconciliation.durable.snapshot.checkpoint.semantics)
    }

    @Test
    fun unreadableManagedMarkerStaysPostVerifyReconciliationAndNeverPublishes() = runBlocking {
        val journal = FakeJournal(postVerifySnapshot())
        val publisher = FakePublisher()
        val verifier = FakeVerifier(
            InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                InstallerPostInstallRemoteReconciliation.MANAGED_MARKER_UNREADABLE,
            ),
        )

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .reconcileAndPublish(journal.current, session())
        val reconciliation = result as InstallerPostInstallCoordinatorResult.ReconciliationRequired

        assertEquals(InstallerPostInstallReconciliationReason.MANAGED_MARKER_UNREADABLE, reconciliation.reason)
        assertEquals(0, publisher.installerCalls)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliation.durable.snapshot.status)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, reconciliation.durable.snapshot.checkpoint.semantics)
    }

    @Test
    fun stillRunningDetachedWorkerWaitsWithoutPublishingOrJournalRewrite() = runBlocking {
        val journal = FakeJournal(postVerifySnapshot())
        val publisher = FakePublisher()
        val evidence = InstallerWorkerEvidence(
            scope = scope,
            heartbeatAt = now.minusSeconds(1),
            primaryProcessState = InstallerWorkerProcessState.ALIVE,
            primaryObservedAt = now,
            terminalState = InstallerWorkerTerminalState.NONE,
        )
        val verifier = FakeVerifier(InstallerPostInstallRemoteVerificationResult.WorkerStillRunning(evidence))

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .reconcileAndPublish(journal.current, session())

        assertTrue(result is InstallerPostInstallCoordinatorResult.AwaitingWorker)
        assertEquals(0, publisher.installerCalls)
        assertEquals(0, journal.advanceCount)
    }

    @Test
    fun commitVerifiedRecoveryFinishesLocallyWithoutRemoteReadbackOrRepublish() = runBlocking {
        val journal = FakeJournal(postVerifySnapshot().copy(
            snapshot = postVerifySnapshot().snapshot.copy(
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    "INSTALLER_COMMIT_VERIFIED",
                    CheckpointSemantics.COMMIT_VERIFIED,
                    now.minusSeconds(1),
                ),
                updatedAt = now.minusSeconds(1),
            ),
        ))
        val publisher = FakePublisher()
        val verifier = FakeVerifier(errorResult = true)

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .reconcileAndPublish(journal.current, session())

        assertTrue(result is InstallerPostInstallCoordinatorResult.Succeeded)
        assertEquals(0, verifier.calls)
        assertEquals(0, publisher.installerCalls)
        assertEquals(1, journal.advanceCount)
        assertEquals(CheckpointSemantics.TERMINAL, journal.current.snapshot.checkpoint.semantics)
    }

    @Test
    fun commitVerifiedCanFinishThroughLocalOnlyApiWithoutSession() = runBlocking {
        val base = postVerifySnapshot()
        val journal = FakeJournal(
            base.copy(
                snapshot = base.snapshot.copy(
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint(
                        "INSTALLER_COMMIT_VERIFIED",
                        CheckpointSemantics.COMMIT_VERIFIED,
                        now.minusSeconds(1),
                    ),
                    updatedAt = now.minusSeconds(1),
                ),
            ),
        )
        val publisher = FakePublisher()
        val verifier = FakeVerifier(errorResult = true)

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .finishCommitted(journal.current)

        assertTrue(result is InstallerPostInstallCoordinatorResult.Succeeded)
        assertEquals(0, verifier.calls)
        assertEquals(0, publisher.installerCalls)
        assertEquals(1, journal.advanceCount)
        assertEquals(OperationStatus.SUCCEEDED, journal.current.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, journal.current.snapshot.checkpoint.semantics)
    }

    @Test
    fun commitVerifiedWithNonRunningStatusCannotClaimSuccess() = runBlocking {
        val base = postVerifySnapshot()
        val journal = FakeJournal(
            base.copy(
                snapshot = base.snapshot.copy(
                    status = OperationStatus.RECONCILIATION_REQUIRED,
                    checkpoint = OperationCheckpoint(
                        "INSTALLER_COMMIT_VERIFIED",
                        CheckpointSemantics.COMMIT_VERIFIED,
                        now.minusSeconds(1),
                    ),
                    updatedAt = now.minusSeconds(1),
                ),
            ),
        )
        val publisher = FakePublisher()
        val verifier = FakeVerifier(errorResult = true)

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .reconcileAndPublish(journal.current, session())

        assertEquals(
            InstallerPostInstallCoordinatorResult.Rejected(
                InstallerPostInstallCoordinatorFailure.NotAtCommitBoundary,
            ),
            result,
        )
        assertEquals(0, verifier.calls)
        assertEquals(0, publisher.installerCalls)
        assertEquals(0, journal.advanceCount)
    }

    @Test
    fun localStorageFailureRemainsPostVerifyReconciliationAndNeverClaimsSuccess() = runBlocking {
        val journal = FakeJournal(postVerifySnapshot())
        val publisher = FakePublisher(ManagementEnrollmentPublicationResult.StorageFailure)
        val verifier = FakeVerifier(verifiedRemote())

        val result = InstallerPostInstallCoordinator(verifier, publisher, journal) { now }
            .reconcileAndPublish(journal.current, session())
        val reconciliation = result as InstallerPostInstallCoordinatorResult.ReconciliationRequired

        assertEquals(InstallerPostInstallReconciliationReason.LOCAL_PUBLICATION_STORAGE_FAILURE, reconciliation.reason)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, reconciliation.durable.snapshot.status)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, reconciliation.durable.snapshot.checkpoint.semantics)
        assertEquals(1, publisher.installerCalls)
    }

    private fun verifiedRemote(facts: InstallerPostInstallFacts = goodFacts()) =
        InstallerPostInstallRemoteVerificationResult.Verified(
            facts = facts,
            workerEvidence = InstallerWorkerEvidence(
                scope = scope,
                heartbeatAt = now.minusSeconds(2),
                primaryProcessState = InstallerWorkerProcessState.DEAD,
                primaryObservedAt = now,
                terminalState = InstallerWorkerTerminalState.SUCCESS,
                terminalObservedAt = now,
            ),
        )

    private fun goodFacts() = InstallerPostInstallFacts(
        markerReadback = ManagedInstallMarkerReadbackState.MATCH,
        serviceUnitPresent = true,
        binaryPresent = true,
        rootPresent = true,
        databasePresent = true,
        serviceState = ManagementServiceState.ACTIVE,
        panelPort = 23456,
        webBasePath = "/panel/",
        listenAddress = null,
        listenerPresent = true,
        observedAt = now,
    )

    private fun postVerifySnapshot(): VersionedOperationSnapshot {
        val started = now.minusSeconds(120)
        return VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = operationId,
                type = OperationType.INSTALL,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("VERIFYING", CheckpointSemantics.POST_VERIFY_REQUIRED, now.minusSeconds(5)),
                startedAt = started,
                updatedAt = now.minusSeconds(5),
            ),
            OperationRevision(4),
        )
    }

    private fun session(): SshSessionHandle = object : SshSessionHandle {
        override val binding = SessionBinding(SessionId("session"), accessId, SessionOwner.Operation(operationId))
        override val isOpen: Boolean = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult =
            SshCommandResult(
                com.velumtegra.xuimobile.core.ssh.CommandDispatchState.NOT_DISPATCHED,
                CommandCompletion.Unknown("unused"),
                CapturedOutput.EMPTY,
                CapturedOutput.EMPTY,
            )
        override fun close() = Unit
    }

    private class FakeVerifier(
        private val result: InstallerPostInstallRemoteVerificationResult? = null,
        private val errorResult: Boolean = false,
    ) : InstallerPostInstallRemoteVerifier {
        var calls = 0
            private set

        override suspend fun verify(
            scope: InstallerWorkerScope,
            session: SshSessionHandle,
        ): InstallerPostInstallRemoteVerificationResult {
            calls += 1
            if (errorResult) error("remote verifier must not be called")
            return requireNotNull(result)
        }
    }

    private class FakePublisher(
        private val forced: ManagementEnrollmentPublicationResult? = null,
    ) : ManagementEnrollmentPublisher {
        var installerCalls = 0
            private set
        var discoveryCalls = 0
            private set

        override suspend fun publish(request: ManagementEnrollmentRequest): ManagementEnrollmentPublicationResult {
            discoveryCalls += 1
            error("Discovery enrollment path must not be used by Installer")
        }

        override suspend fun publishInstaller(
            request: InstallerManagementPublicationRequest,
        ): ManagementEnrollmentPublicationResult {
            installerCalls += 1
            forced?.let { return it }
            val installation = request.newInstallation()
            return ManagementEnrollmentPublicationResult.Published(
                installation = VersionedRecord(installation, RecordRevision(0)),
                managementAccess = ManagementAccess(installation.id, request.scope.serverAccessId),
                installationCreated = true,
                managementAccessCreated = true,
            )
        }
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current = initial
            private set
        var advanceCount = 0
            private set
        val advanced = mutableListOf<OperationSnapshot>()

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
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) {
                return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            }
            advanceCount += 1
            advanced += next
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }
}
