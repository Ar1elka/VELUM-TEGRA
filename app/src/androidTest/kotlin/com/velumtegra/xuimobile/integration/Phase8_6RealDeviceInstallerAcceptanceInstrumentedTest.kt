package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.FreshInstallAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.FreshInstallVerificationResult
import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ReviewedInstallPlanPolicy
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.FreshInstallConflictState
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPreflightProof
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.runtime.InstallerPostInstallCoordinator
import com.velumtegra.xuimobile.core.runtime.InstallerPostInstallCoordinatorResult
import com.velumtegra.xuimobile.core.runtime.InstallerPostInstallReconciliationReason
import com.velumtegra.xuimobile.core.ssh.InstallerPostInstallSshVerifier
import com.velumtegra.xuimobile.core.ssh.InstallerReconciliationReason
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionAdapter
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionFailure
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real-device Phase 8.6 acceptance over USB adb-reverse into the host-only Apache MINA witness.
 * The fixture executes no host shell/process: every remote effect below is a synthetic response to
 * one byte-exact reviewed production command.
 */
@RunWith(AndroidJUnit4::class)
class Phase8_6RealDeviceInstallerAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun reviewedInstallerFlowIsExactFailClosedNonReplayAndPublishesOnlyVerifiedManagement() = runBlocking {
        val fixturePort = requiredPort(ARG_FIXTURE_PORT)
        val fingerprint = requiredArgument(ARG_FIXTURE_FINGERPRINT)
        val runTag = requiredArgument(ARG_RUN_TAG).also {
            require(it.matches(Regex("[a-f0-9]{12}"))) { "Invalid Phase 8.6 run tag" }
        }
        require(fingerprint.startsWith("SHA256:") && fingerprint.length > 7) { "Invalid fixture fingerprint" }

        val dbName = "phase8_6_installer_${runTag}_${UUID.randomUUID().toString().take(8)}.db"
        var database: VelumDatabase? = null
        val secretId = SecretId("phase86-secret-$runTag")
        val secretStore = StaticSecretStore(secretId, FIXTURE_PASSWORD)
        try {
            context.deleteDatabase(dbName)
            val db = VelumDatabaseFactory.open(context, dbName)
            database = db
            val journal = RoomOperationJournal(db)
            val serverRepo = RoomServerRepository(db)
            val accessWriter = RoomCredentialReferenceWriter(db)
            val installationRepo = RoomXuiInstallationRepository(db)
            val managementRepo = RoomManagementAccessRepository(db)
            val webRepo = RoomWebPanelAccessRepository(db)
            val publisher = RoomManagementEnrollmentPublisher(db)

            val serverId = ServerId("phase86-server-$runTag")
            val accessId = ServerAccessId("phase86-access-$runTag")
            val access = ServerAccess(
                id = accessId,
                serverId = serverId,
                endpoint = SshEndpoint(LOOPBACK_HOST, fixturePort),
                username = FIXTURE_USERNAME,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(fingerprint),
            )
            serverRepo.create(Server(serverId, "Phase 8.6 installer fixture", FIXED_NOW.minusSeconds(120)))
                .requireRepositorySuccess("create Phase 8.6 Server")
            accessWriter.createServerAccess(access)
                .requireRepositorySuccess("create Phase 8.6 ServerAccess")

            val sessionCounter = AtomicInteger(0)
            val connectionFactory = JschSshConnectionFactory(secretStore) {
                SessionId("phase86-session-${sessionCounter.incrementAndGet()}-$runTag")
            }
            val adapter = InstallerSshExecutionAdapter(journal, now = { FIXED_NOW })
            val verifier = InstallerPostInstallSshVerifier(now = { FIXED_NOW })
            val coordinator = InstallerPostInstallCoordinator(
                remoteVerifier = verifier,
                publisher = publisher,
                journal = journal,
                now = { FIXED_NOW },
            )

            // 1) Happy path: full fresh target -> exact reviewed plan -> POST_VERIFY_REQUIRED ->
            // read-only worker/marker/facts -> atomic XuiInstallation + ManagementAccess -> terminal.
            val successId = operationId("success", runTag)
            val successCurrent = createFreshOperation(journal, successId, serverId, accessId)
            val successPlan = reviewedPlan(successCurrent)
            connect(connectionFactory, access, SessionOwner.Operation(successId)).use { session ->
                val executed = adapter.execute(successPlan, successCurrent, session)
                val awaiting = executed as? InstallerSshExecutionResult.AwaitingVerification
                    ?: throw AssertionError("Happy-path Installer execution did not reach verification: $executed")
                assertEquals(ManagedInstallMarkerReadbackState.MATCH, awaiting.markerReadback)
                assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, awaiting.durable.snapshot.checkpoint.semantics)

                val completed = coordinator.reconcileAndPublish(awaiting.durable, session)
                val succeeded = completed as? InstallerPostInstallCoordinatorResult.Succeeded
                    ?: throw AssertionError("Post-install coordinator did not publish verified success: $completed")
                assertEquals(OperationStatus.SUCCEEDED, succeeded.durable.snapshot.status)
                assertEquals(CheckpointSemantics.TERMINAL, succeeded.durable.snapshot.checkpoint.semantics)

                val installation = installationRepo.get(succeeded.installationId)
                    .requireRepositorySuccess("read Phase 8.6 published installation")
                assertEquals(serverId, installation.value.serverId)
                assertEquals(ManagedInstallIdentityPolicy.forOperation(successId), installation.value.identity.managedInstallId)
                assertEquals(PANEL_PORT, installation.value.baseline.panelPort)
                assertEquals(WEB_BASE_PATH, installation.value.baseline.webBasePath)
                assertEquals(
                    accessId,
                    managementRepo.get(succeeded.installationId, accessId)
                        .requireRepositorySuccess("read Phase 8.6 ManagementAccess")
                        .serverAccessId,
                )
                assertTrue("Installer publication must not create WebPanelAccess", webRepo.list().requireRepositorySuccess("list WebPanelAccess").isEmpty())
            }

            // 2) Dispatch uncertainty: second reviewed mutation closes without exit-status. The
            // durable operation becomes reconciliation-required and a direct re-entry is rejected
            // before any remote command can replay.
            val uncertainId = operationId("uncertain", runTag)
            val uncertainCurrent = createFreshOperation(journal, uncertainId, serverId, accessId)
            val uncertainPlan = reviewedPlan(uncertainCurrent)
            connect(connectionFactory, access, SessionOwner.Operation(uncertainId)).use { session ->
                val uncertain = adapter.execute(uncertainPlan, uncertainCurrent, session)
                val required = uncertain as? InstallerSshExecutionResult.ReconciliationRequired
                    ?: throw AssertionError("Dispatch uncertainty did not require reconciliation: $uncertain")
                assertEquals(InstallerReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, required.reason)
                assertEquals(OperationStatus.RECONCILIATION_REQUIRED, required.durable.snapshot.status)
                assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, required.durable.snapshot.checkpoint.semantics)
                assertTrue("Channel-only uncertainty must preserve the parent exact SSH session", session.isOpen)

                val replay = adapter.execute(uncertainPlan, required.durable, session)
                assertEquals(
                    InstallerSshExecutionFailure.NotAtPredispatchCheckpoint,
                    (replay as InstallerSshExecutionResult.Rejected).failure,
                )
            }

            // 3) Stale heartbeat + UNKNOWN process cannot be promoted to success. Coordinator stays
            // at POST_VERIFY_REQUIRED and performs no marker/facts publication path.
            val unknownId = operationId("unknown", runTag)
            val unknownCurrent = createPostVerifyOperation(journal, unknownId, serverId, accessId, OperationStatus.RECONCILIATION_REQUIRED)
            connect(connectionFactory, access, SessionOwner.Operation(unknownId)).use { session ->
                val result = coordinator.reconcileAndPublish(unknownCurrent, session)
                val required = result as? InstallerPostInstallCoordinatorResult.ReconciliationRequired
                    ?: throw AssertionError("Stale UNKNOWN worker evidence was not fail-closed: $result")
                assertEquals(InstallerPostInstallReconciliationReason.WORKER_STATE_UNKNOWN, required.reason)
                assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, required.durable.snapshot.checkpoint.semantics)
            }

            // 4) Fresh heartbeat is an independent liveness channel: even with PROCESS=UNKNOWN it
            // yields AwaitingWorker, not terminal success/failure, and no local publication.
            val heartbeatId = operationId("heartbeat", runTag)
            val heartbeatCurrent = createPostVerifyOperation(journal, heartbeatId, serverId, accessId, OperationStatus.RUNNING)
            connect(connectionFactory, access, SessionOwner.Operation(heartbeatId)).use { session ->
                val result = coordinator.reconcileAndPublish(heartbeatCurrent, session)
                val waiting = result as? InstallerPostInstallCoordinatorResult.AwaitingWorker
                    ?: throw AssertionError("Fresh independent heartbeat did not keep worker live: $result")
                assertEquals(heartbeatCurrent, waiting.durable)
            }

            // 5) Exact operation ownership: an authenticated session owned by another OperationId
            // is rejected before the first remote mutation command.
            val wrongPlanId = operationId("wrong-owner-plan", runTag)
            val wrongPlanCurrent = createFreshOperation(journal, wrongPlanId, serverId, accessId)
            val wrongPlan = reviewedPlan(wrongPlanCurrent)
            val differentOwner = OperationId("phase86-wrong-owner-binding-$runTag")
            connect(connectionFactory, access, SessionOwner.Operation(differentOwner)).use { session ->
                val rejected = adapter.execute(wrongPlan, wrongPlanCurrent, session)
                assertEquals(
                    InstallerSshExecutionFailure.ExactSessionBindingMismatch,
                    (rejected as InstallerSshExecutionResult.Rejected).failure,
                )
            }

            // Only the happy path may publish. The four fail-closed/waiting cases must leave no
            // additional managed installation and must never manufacture WebPanelAccess.
            assertEquals(1, installationRepo.listForServer(serverId).requireRepositorySuccess("list Phase 8.6 installations").size)
            assertEquals(1, managementRepo.listForServerAccess(accessId).requireRepositorySuccess("list Phase 8.6 ManagementAccess").size)
            assertTrue(webRepo.list().requireRepositorySuccess("final Phase 8.6 WebPanelAccess list").isEmpty())
            assertEquals(EXPECTED_AUTH, sessionCounter.get())
        } finally {
            secretStore.close()
            database?.close()
            context.deleteDatabase(dbName)
        }
    }

    private suspend fun createFreshOperation(
        journal: RoomOperationJournal,
        operationId: OperationId,
        serverId: ServerId,
        accessId: ServerAccessId,
    ): VersionedOperationSnapshot {
        val startedAt = FIXED_NOW.minusSeconds(90)
        val snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.INSTALL,
            target = OperationTarget.ServerTarget(serverId, accessId),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, startedAt),
            startedAt = startedAt,
            updatedAt = startedAt,
        )
        return journal.create(snapshot).requireOperationSuccess("create ${operationId.value}")
    }

    private suspend fun createPostVerifyOperation(
        journal: RoomOperationJournal,
        operationId: OperationId,
        serverId: ServerId,
        accessId: ServerAccessId,
        status: OperationStatus,
    ): VersionedOperationSnapshot {
        val startedAt = FIXED_NOW.minusSeconds(90)
        val updatedAt = FIXED_NOW.minusSeconds(10)
        val snapshot = OperationSnapshot(
            operationId = operationId,
            type = OperationType.INSTALL,
            target = OperationTarget.ServerTarget(serverId, accessId),
            status = status,
            checkpoint = OperationCheckpoint("VERIFYING", CheckpointSemantics.POST_VERIFY_REQUIRED, updatedAt),
            startedAt = startedAt,
            updatedAt = updatedAt,
        )
        return journal.create(snapshot).requireOperationSuccess("create post-verify ${operationId.value}")
    }

    private fun reviewedPlan(current: VersionedOperationSnapshot) = when (
        val verified = FreshInstallAuthorizationPolicy.verify(
            operation = current.snapshot,
            proof = FreshInstallPreflightProof(
                id = TargetProofId("proof-${current.snapshot.operationId.value}"),
                scope = FreshInstallScope(
                    operationId = current.snapshot.operationId,
                    serverId = (current.snapshot.target as OperationTarget.ServerTarget).serverId,
                    serverAccessId = current.snapshot.target.serverAccessId,
                ),
                platform = DiscoveryPlatform("ubuntu", "24.04"),
                installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
                conflictState = FreshInstallConflictState.PROVEN_CLEAR,
                observedAt = FIXED_NOW.minusSeconds(30),
                validUntil = FIXED_NOW.plusSeconds(300),
            ),
            now = FIXED_NOW,
        )
    ) {
        is FreshInstallVerificationResult.Verified -> ReviewedInstallPlanPolicy.build(verified.target)
        is FreshInstallVerificationResult.Rejected -> error("Fresh-install authorization rejected fixture target: ${verified.reason}")
    }

    private suspend fun connect(
        factory: JschSshConnectionFactory,
        access: ServerAccess,
        owner: SessionOwner,
    ): SshSessionHandle = when (val result = factory.connect(access, owner)) {
        is SshConnectResult.Connected -> result.handle
        is SshConnectResult.Failed -> throw AssertionError("Phase 8.6 SSH connect failed: ${result.failure::class.java.simpleName}")
    }

    private fun operationId(label: String, runTag: String) = OperationId("phase86-$label-$runTag")

    private fun requiredArgument(name: String): String =
        InstrumentationRegistry.getArguments().getString(name)?.trim()?.takeIf { it.isNotEmpty() }
            ?: error("Missing required instrumentation argument: $name")

    private fun requiredPort(name: String): Int =
        requiredArgument(name).toIntOrNull()?.takeIf { it in 1..65535 }
            ?: error("Invalid required port argument: $name")

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(action: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(action: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private class StaticSecretStore(
        private val secretId: SecretId,
        password: String,
    ) : SecretStore, AutoCloseable {
        private val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.AlreadyExists

        override suspend fun read(secretId: SecretId): SecretReadResult =
            if (secretId == this.secretId) {
                SecretReadResult.Found(SecretMaterial.fromBytes(passwordBytes))
            } else {
                SecretReadResult.NotFound
            }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult = SecretDeleteResult.AlreadyAbsent
        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(secretId))

        override fun close() {
            java.util.Arrays.fill(passwordBytes, 0)
        }
    }

    private companion object {
        const val ARG_FIXTURE_PORT = "phase86.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase86.fixtureFingerprint"
        const val ARG_RUN_TAG = "phase86.runTag"
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase86"
        const val FIXTURE_PASSWORD = "VELUM-phase86-test-only-password"
        const val PANEL_PORT = 23456
        const val WEB_BASE_PATH = "/phase86/"
        const val EXPECTED_AUTH = 5
        val FIXED_NOW: Instant = Instant.parse("2026-09-12T08:00:00Z")
    }
}
