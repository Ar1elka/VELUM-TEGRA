package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationReinstallRuntimeCoordinatorTest {
    @Test
    fun `fresh reinstall consumes one preflight and dispatches once`() = runBlocking {
        val fixture = Fixture()
        fixture.registerPreflight()

        assertEquals(
            ExistingInstallationReinstallPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationReinstallRuntimeResult.Dispatch

        assertTrue(result.result is ExistingInstallationReinstallDispatchResult.PostVerifyRequired)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(false, fixture.coordinator.discardPreflight(fixture.operationId))
    }

    @Test
    fun `old admission becomes stale after compound checkpoint and cannot verify or publish`() = runBlocking {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)

        val second = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationReinstallRuntimeResult.StalePlan

        assertEquals(OperationRevision(0), second.expectedRevision)
        assertEquals(OperationRevision(1), second.actualRevision)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(0, fixture.postVerifyCalls)
        assertEquals(0, fixture.publisher.calls)
    }

    @Test
    fun `new recovery admission never redispatches and terminalizes only after verified same row republish`() = runBlocking {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)
        fixture.releaseAdmission(fixture.admission)

        val recovered = fixture.recoveryAdmission()
        val result = fixture.coordinator.execute(recovered, fixture.binding)
            as ExistingInstallationReinstallRuntimeResult.Completed
        val committed = result.result as ExistingInstallationReinstallCompletionResult.Committed

        assertEquals(OperationStatus.SUCCEEDED, committed.durable.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, committed.durable.snapshot.checkpoint.semantics)
        assertEquals("REINSTALL_SUCCEEDED_VERIFIED_REPUBLISHED", committed.durable.snapshot.checkpoint.phaseName)
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(1, fixture.postVerifyCalls)
        assertEquals(1, fixture.publisher.calls)
        assertEquals(fixture.installationId, fixture.publisher.lastRequest?.installationId)
        assertEquals(RecordRevision(3), fixture.publisher.lastRequest?.expectedRevision)
        assertEquals(fixture.installation.identity, fixture.publisher.lastRequest?.expectedIdentity)
        assertEquals(fixture.verifiedBaseline, fixture.publisher.lastRequest?.verifiedBaseline)
        assertEquals(fixture.installationId, committed.publication?.installation?.value?.id)
        assertEquals(fixture.managedInstallId, committed.publication?.installation?.value?.identity?.managedInstallId)
        assertEquals(
            listOf(
                CheckpointSemantics.MUTATION_IN_FLIGHT,
                CheckpointSemantics.POST_VERIFY_REQUIRED,
                CheckpointSemantics.COMMIT_VERIFIED,
                CheckpointSemantics.TERMINAL,
            ),
            fixture.journal.advancedSemantics,
        )
        fixture.releaseAdmission(recovered)
    }

    @Test
    fun `process recreation at mutation not started cannot reconstruct reinstall authority`() = runBlocking {
        val fixture = Fixture()
        val recreated = fixture.newCoordinatorWithEmptyEntryRegistry()

        assertEquals(
            ExistingInstallationReinstallPreparationResult.FreshPreflightRequired,
            recreated.prepareTransport(fixture.admission),
        )
        assertEquals(
            ExistingInstallationReinstallRuntimeResult.FreshPreflightRequired,
            recreated.execute(fixture.admission, fixture.binding),
        )
        assertEquals(0, fixture.dispatchCalls)
    }

    @Test
    fun `durable same server blocker stops before one shot authority is consumed`() = runBlocking {
        val fixture = Fixture()
        fixture.registerPreflight()
        fixture.journal.nonTerminal = listOf(fixture.journal.current, fixture.otherUnsafeOperation())

        val result = fixture.coordinator.execute(fixture.admission, fixture.binding)
            as ExistingInstallationReinstallRuntimeResult.BlockedByDurableMutation

        assertEquals(1, result.blockers.size)
        assertEquals(fixture.otherOperationId, result.blockers.single().operationId)
        assertEquals(0, fixture.dispatchCalls)
        assertEquals(
            ExistingInstallationReinstallPreparationResult.TransportRequired,
            fixture.coordinator.prepareTransport(fixture.admission),
        )
    }

    @Test
    fun `publication rejection remains reconciliation and never replays remote compound plan`() = runBlocking {
        val fixture = Fixture(
            publicationResult = ExistingInstallationReinstallPublicationResult.Rejected(
                ExistingInstallationReinstallPublicationRejection.INSTALLATION_REVISION_STALE,
            ),
        )
        fixture.registerPreflight()
        fixture.coordinator.execute(fixture.admission, fixture.binding)
        fixture.releaseAdmission(fixture.admission)

        val recovered = fixture.recoveryAdmission()
        val result = fixture.coordinator.execute(recovered, fixture.binding)
            as ExistingInstallationReinstallRuntimeResult.Reconciliation

        assertTrue(result.remote is ExistingInstallationReinstallPostVerifyResult.Verified)
        assertEquals(
            ExistingInstallationReinstallPublicationResult.Rejected(
                ExistingInstallationReinstallPublicationRejection.INSTALLATION_REVISION_STALE,
            ),
            result.publication,
        )
        assertEquals(1, fixture.dispatchCalls)
        assertEquals(1, fixture.postVerifyCalls)
        assertEquals(1, fixture.publisher.calls)
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, fixture.journal.current.snapshot.checkpoint.semantics)
        fixture.releaseAdmission(recovered)
    }

    private class Fixture(
        publicationResult: ExistingInstallationReinstallPublicationResult? = null,
    ) {
        val now = Instant.parse("2026-09-14T13:30:00Z")
        val operationId = OperationId("phase97-runtime-reinstall")
        val otherOperationId = OperationId("phase97-runtime-other")
        val serverId = ServerId("phase97-runtime-server")
        val accessId = ServerAccessId("phase97-runtime-access")
        val installationId = XuiInstallationId("phase97-runtime-installation")
        val managedInstallId = ManagedInstallId("v1-fedcba9876543210fedcba9876543210")
        val installation = XuiInstallation(
            id = installationId,
            serverId = serverId,
            ownership = InstallationOwnership.MANAGED,
            identity = InstallationIdentity(
                serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                managedInstallId = managedInstallId,
            ),
            baseline = InstallationBaseline(
                serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                panelPort = 2053,
                webBasePath = "/panel/",
                listenAddress = "127.0.0.1",
                capturedAt = now.minusSeconds(600),
            ),
        )
        val verifiedBaseline = installation.baseline.copy(
            panelPort = 24443,
            webBasePath = "/reinstalled/",
            capturedAt = now.plusSeconds(2),
        )
        private val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.97", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("phase97-runtime-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase97-runtime"),
        )
        val journal = FakeJournal(
            VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = operationId,
                    type = OperationType.REINSTALL,
                    target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(10)),
                    startedAt = now.minusSeconds(60),
                    updatedAt = now.minusSeconds(10),
                ),
                OperationRevision(0),
            ),
        )
        val installationRepository = FakeInstallationRepository(VersionedRecord(installation, RecordRevision(3)))
        private val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val sessionRegistry = ExactSessionRegistry()
        private val serverMutationRegistry = ServerMutationLeaseRegistry()
        private val entryRegistry = ExistingInstallationReinstallEntryRegistry()
        val binding = SessionBinding(SessionId("phase97-runtime-session"), accessId, SessionOwner.Operation(operationId))
        private val handle = FakeHandle(binding)
        var dispatchCalls = 0
        var postVerifyCalls = 0

        private val dispatchPort = ExistingInstallationReinstallDispatchPort { _, _, current, _ ->
            dispatchCalls += 1
            val advanced = journal.advance(
                operationId,
                current.revision,
                current.snapshot.copy(
                    checkpoint = OperationCheckpoint("REINSTALL_COMPOUND_DISPATCHED", CheckpointSemantics.MUTATION_IN_FLIGHT, now),
                    updatedAt = now,
                ),
            ) as OperationJournalResult.Success
            ExistingInstallationReinstallDispatchResult.PostVerifyRequired(advanced.value)
        }
        private val postVerifyPort = ExistingInstallationReinstallPostVerifyPort { current, exactManagedInstallId, exactSession ->
            postVerifyCalls += 1
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, current.snapshot.checkpoint.semantics)
            assertEquals(managedInstallId, exactManagedInstallId)
            assertEquals(binding, exactSession.binding)
            val scope = InstallerWorkerScope(operationId, serverId, accessId, managedInstallId)
            ExistingInstallationReinstallPostVerifyResult.Verified(
                facts = InstallerPostInstallFacts(
                    markerReadback = ManagedInstallMarkerReadbackState.MATCH,
                    serviceUnitPresent = true,
                    binaryPresent = true,
                    rootPresent = true,
                    databasePresent = true,
                    serviceState = ManagementServiceState.ACTIVE,
                    panelPort = verifiedBaseline.panelPort,
                    webBasePath = verifiedBaseline.webBasePath,
                    listenAddress = verifiedBaseline.listenAddress,
                    listenerPresent = true,
                    observedAt = verifiedBaseline.capturedAt,
                ),
                verifiedBaseline = verifiedBaseline,
                workerEvidence = InstallerWorkerEvidence(
                    scope = scope,
                    heartbeatAt = now,
                    primaryProcessState = InstallerWorkerProcessState.DEAD,
                    primaryObservedAt = now,
                    terminalState = InstallerWorkerTerminalState.SUCCESS,
                    terminalObservedAt = now,
                ),
            )
        }
        val publisher = FakePublisher(
            installationRepository,
            accessId,
            publicationResult,
        )

        val admission: RecoveryRuntimeAdmission
        val coordinator: ExistingInstallationReinstallRuntimeCoordinator

        init {
            sessionRegistry.install(handle)
            admission = newAdmission(journal.current, RecoveryAction.RECONNECT_EXACT_OWNER)
            coordinator = createCoordinator(entryRegistry)
        }

        fun registerPreflight() {
            assertEquals(
                ExistingInstallationReinstallEntryRegistrationResult.Registered,
                coordinator.registerPreflight(verifiedPreflight(journal.current, installation, access, now)),
            )
        }

        fun recoveryAdmission(): RecoveryRuntimeAdmission =
            newAdmission(journal.current, RecoveryAction.RECONCILE_READ_ONLY)

        fun releaseAdmission(admission: RecoveryRuntimeAdmission) {
            assertEquals(OperationRuntimeReleaseResult.RELEASED, runtimeRegistry.release(admission.runtimeLease))
        }

        fun newCoordinatorWithEmptyEntryRegistry(): ExistingInstallationReinstallRuntimeCoordinator =
            createCoordinator(ExistingInstallationReinstallEntryRegistry())

        fun otherUnsafeOperation(): VersionedOperationSnapshot = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = otherOperationId,
                type = OperationType.UNINSTALL,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint("OTHER_UNCERTAIN", CheckpointSemantics.MUTATION_IN_FLIGHT, now.minusSeconds(2)),
                startedAt = now.minusSeconds(30),
                updatedAt = now.minusSeconds(2),
            ),
            OperationRevision(2),
        )

        private fun newAdmission(current: VersionedOperationSnapshot, action: RecoveryAction): RecoveryRuntimeAdmission {
            val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
            return RecoveryRuntimeAdmission(
                ColdStartRecoveryPlan(
                    operationId = operationId,
                    target = current.snapshot.target,
                    expectedRevision = current.revision,
                    action = action,
                    automaticAllowed = true,
                ),
                lease,
            )
        }

        private fun createCoordinator(entries: ExistingInstallationReinstallEntryRegistry) =
            ExistingInstallationReinstallRuntimeCoordinator(
                journal = journal,
                installationRepository = installationRepository,
                runtimeRegistry = runtimeRegistry,
                sessionRegistry = sessionRegistry,
                serverMutationRegistry = serverMutationRegistry,
                entryRegistry = entries,
                dispatchPort = dispatchPort,
                postVerifyPort = postVerifyPort,
                publisher = publisher,
                now = { now.plusSeconds(journal.current.revision.value) },
            )
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current = initial
        var nonTerminal: List<VersionedOperationSnapshot> = listOf(initial)
        val advancedSemantics = mutableListOf<CheckpointSemantics>()

        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.StorageFailure("not used")
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(nonTerminal.map { if (it.snapshot.operationId == current.snapshot.operationId) current else it })
        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            advancedSemantics += next.checkpoint.semantics
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }

    private class FakeInstallationRepository(initial: VersionedRecord<XuiInstallation>) : XuiInstallationRepository {
        var record = initial
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
            if (installationId == record.value.id) RepositoryResult.Success(record) else RepositoryResult.NotFound
        override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(record))
        override suspend fun create(installation: XuiInstallation) = RepositoryResult.StorageFailure("not used")
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = RepositoryResult.StorageFailure("not used")
    }

    private class FakePublisher(
        private val repository: FakeInstallationRepository,
        private val accessId: ServerAccessId,
        private val forced: ExistingInstallationReinstallPublicationResult?,
    ) : ManagementEnrollmentPublisher {
        var calls = 0
        var lastRequest: ExistingInstallationReinstallPublicationRequest? = null
        override suspend fun publish(request: ManagementEnrollmentRequest) = ManagementEnrollmentPublicationResult.StorageFailure
        override suspend fun publishInstaller(request: InstallerManagementPublicationRequest) = ManagementEnrollmentPublicationResult.StorageFailure
        override suspend fun republishReinstall(
            request: ExistingInstallationReinstallPublicationRequest,
        ): ExistingInstallationReinstallPublicationResult {
            calls += 1
            lastRequest = request
            forced?.let { return it }
            val current = repository.record
            if (current.revision != request.expectedRevision) {
                return ExistingInstallationReinstallPublicationResult.Rejected(
                    ExistingInstallationReinstallPublicationRejection.INSTALLATION_REVISION_STALE,
                )
            }
            val updated = request.updatedInstallation(current.value)
            val next = RecordRevision(current.revision.value + 1)
            repository.record = VersionedRecord(updated, next)
            return ExistingInstallationReinstallPublicationResult.Published(
                repository.record,
                ManagementAccess(request.installationId, accessId),
                baselineUpdated = current.value.baseline != updated.baseline,
            )
        }
    }

    private class FakeHandle(override val binding: SessionBinding) : SshSessionHandle {
        override val isOpen: Boolean = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult =
            error("runtime port test must not execute raw SSH")
        override fun close() = Unit
    }

    companion object {
        private fun verifiedPreflight(
            current: VersionedOperationSnapshot,
            installation: XuiInstallation,
            access: ServerAccess,
            now: Instant,
        ): VerifiedExistingInstallationActionPreflight {
            val proof = InstallationProof(
                TargetProofId("phase97-runtime-proof"),
                installation.id,
                installation.serverId,
                access.id,
                installation.identity,
                now.minusSeconds(3),
                now.plusSeconds(120),
            )
            val verifiedTarget = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now)
                as TargetVerificationResult.Verified).target
            val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, verifiedTarget, now)
                as ExistingInstallationActionAuthorizationResult.Verified).authorization
            val evidence = ExistingInstallationPreflightEvidence(
                scope = ExistingInstallationActionScope(
                    current.snapshot.operationId,
                    current.revision.value,
                    installation.serverId,
                    access.id,
                    installation.id,
                    OperationType.REINSTALL,
                    installation.ownership,
                    installation.identity.managedInstallId,
                ),
                installationProof = proof,
                accessPathState = ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
                layoutCapability = ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
                privilegeCapability = ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
                mutationBarrierState = ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
                observedAt = now.minusSeconds(2),
                validUntil = now.plusSeconds(60),
            )
            return (ExistingInstallationActionPreflightPolicy.verify(
                authorization, current, installation, evidence, now,
            ) as ExistingInstallationActionPreflightResult.Verified).preflight
        }
    }
}
