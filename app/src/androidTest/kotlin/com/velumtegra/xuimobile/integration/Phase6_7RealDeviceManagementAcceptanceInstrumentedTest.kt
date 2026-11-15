package com.velumtegra.xuimobile.integration

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.room3.withWriteTransaction
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRequest
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus
import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.management.DeepDiagnosticOperationStartResult
import com.velumtegra.xuimobile.management.DeepDiagnosticReadResult
import com.velumtegra.xuimobile.management.ManagementOperationStartResult
import com.velumtegra.xuimobile.management.ManagementReadResult
import com.velumtegra.xuimobile.management.VisibleDeepDiagnosticOperationLauncher
import com.velumtegra.xuimobile.management.VisibleManagementQuickInspectOperationLauncher
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleEvidence
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleState
import com.velumtegra.xuimobile.runtime.ExactOperationShortService
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Production-shaped Phase 6.7 real-device acceptance for QUICK_INSPECT and DEEP_DIAGNOSTIC. */
@RunWith(AndroidJUnit4::class)
class Phase6_7RealDeviceManagementAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactManagementQuickAndDeepRunReadOnlyThroughProductionHost() = runBlocking {
        val fixturePort = readFixturePort()
        val fixtureFingerprint = readFixtureFingerprint()
        val runTag = readRunTag()

        val serverId = ServerId("phase6-7-server-$runTag")
        val exactAccessId = ServerAccessId("phase6-7-exact-access-$runTag")
        val poisonAccessId = ServerAccessId("phase6-7-poison-access-$runTag")
        val installationId = XuiInstallationId("phase6-7-installation-$runTag")
        val exactSecretId = SecretId("phase6-7-exact-secret-$runTag")
        val poisonSecretId = SecretId("phase6-7-poison-secret-$runTag")

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val accessWriter = RoomCredentialReferenceWriter(database)
        val installationRepository = RoomXuiInstallationRepository(database)
        val managementRepository = RoomManagementAccessRepository(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val connectivityManager = requireNotNull(context.getSystemService(ConnectivityManager::class.java))

        val operationIds = mutableListOf<OperationId>()
        var observerRegistered = false

        try {
            awaitValidatedDefaultNetwork(connectivityManager)
            val baselineConnectivityGeneration = application.operationRuntimeCoordinator.connectivitySnapshot().generation
            assertTrue(application.connectivityObserver.register())
            observerRegistered = true
            awaitStableOnlineObservationAfter(baselineConnectivityGeneration)

            createSecret(secretStore, exactSecretId, FIXTURE_PASSWORD)
            createSecret(secretStore, poisonSecretId, POISON_PASSWORD)

            serverRepository.create(
                Server(serverId, "Phase 6.7 Management acceptance", Instant.now()),
            ).requireRepositorySuccess("create Phase 6.7 Server")
            accessWriter.createServerAccess(
                ServerAccess(
                    id = exactAccessId,
                    serverId = serverId,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = FIXTURE_USERNAME,
                    auth = SshAuthRef.Password(exactSecretId),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
            ).requireRepositorySuccess("create exact Phase 6.7 ServerAccess")
            accessWriter.createServerAccess(
                ServerAccess(
                    id = poisonAccessId,
                    serverId = serverId,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = POISON_USERNAME,
                    auth = SshAuthRef.Password(poisonSecretId),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
            ).requireRepositorySuccess("create poison Phase 6.7 ServerAccess")

            // Phase 6 closure requires the real production enrollment -> QUICK_INSPECT chain,
            // not a test-only direct insertion of XuiInstallation + ManagementAccess. Publish the
            // exact ADOPTED candidate through the canonical RoomManagementEnrollmentPublisher,
            // then feed the returned durable identities directly into the production launchers.
            val installation = canonicalInstallation(installationId, serverId)
            val enrollmentPublisher = RoomManagementEnrollmentPublisher(database)
            val enrollmentResult = enrollmentPublisher.publish(
                ManagementEnrollmentRequest(
                    proof = canonicalEnrollmentProof(
                        runTag = runTag,
                        serverId = serverId,
                        serverAccessId = exactAccessId,
                        identity = installation.identity,
                    ),
                    baseline = installation.baseline,
                    proposedInstallationId = installationId,
                ),
            )
            val enrollment = enrollmentResult as? ManagementEnrollmentPublicationResult.Published
                ?: throw AssertionError("Production Management enrollment was not published: ${enrollmentResult::class.java.simpleName}")
            assertTrue("Closure acceptance requires a newly published exact installation", enrollment.installationCreated)
            assertTrue("Closure acceptance requires a newly published exact ManagementAccess", enrollment.managementAccessCreated)
            assertEquals(installation, enrollment.installation.value)
            val initialInstallationRevision = enrollment.installation.revision
            val exactManagementAccess = ManagementAccess(installationId, exactAccessId)
            assertEquals(exactManagementAccess, enrollment.managementAccess)
            assertEquals(2, accessRepository.listForServer(serverId).requireRepositorySuccess("list Phase 6.7 accesses").size)
            assertEquals(0L, database.installationDao().webPanelReferenceCount(installationId.value))

            val quickHostGeneration = application.operationHostLifecycleRegistry.latest()?.generation ?: 0L
            val quickStart = withVisibleActivity { activity ->
                application.visibleManagementQuickInspectOperationLauncher(activity).start(installationId, exactAccessId)
            }
            val quickStarted = quickStart as? ManagementOperationStartResult.Started
                ?: throw AssertionError("Production QUICK_INSPECT entry was not accepted: ${quickStart::class.java.simpleName}")
            operationIds += quickStarted.scope.operationId
            val quick = awaitManagementDetail(quickStarted.scope.operationId)
            // Detailed completion is published only from ManagementCompleted, which canonical transport
            // creates only after exact operation-owned SessionId closeSession cleanup has completed.
            assertEquals(ManagementIdentityStatus.Matched, quick.snapshot.identityStatus)
            assertEquals(ManagementServiceState.ACTIVE, quick.snapshot.serviceState)
            assertEquals(ManagementBaselineStatus.Matched, quick.snapshot.baselineStatus)
            assertNotNull("ADOPTED exact identity should yield a fresh process-local proof", quick.snapshot.freshProof)
            assertEquals(exactAccessId, quick.snapshot.scope.serverAccessId)
            assertTerminalJournal(journal, quickStarted.scope.operationId, OperationType.QUICK_INSPECT, "QUICK_INSPECT_RESULT")
            assertStoppedHost(quickStarted.scope.operationId, quickHostGeneration)

            val deepHostGeneration = application.operationHostLifecycleRegistry.latest()?.generation ?: quickHostGeneration
            val deepStart = withVisibleActivity { activity ->
                application.visibleDeepDiagnosticOperationLauncher(activity).start(installationId, exactAccessId)
            }
            val deepStarted = deepStart as? DeepDiagnosticOperationStartResult.Started
                ?: throw AssertionError("Production DEEP_DIAGNOSTIC entry was not accepted: ${deepStart::class.java.simpleName}")
            operationIds += deepStarted.scope.operationId
            val deep = awaitDeepDetail(deepStarted.scope.operationId)
            // Detailed completion is published only from DeepDiagnosticCompleted, which canonical transport
            // creates only after exact operation-owned SessionId closeSession cleanup has completed.
            assertEquals(DeepDiagnosticOverallStatus.HEALTHY, deep.snapshot.overallStatus)
            assertTrue("Healthy fixture must produce no Deep Diagnostic findings", deep.snapshot.findings.isEmpty())
            assertEquals(ManagementIdentityStatus.Matched, deep.snapshot.managementSnapshot.identityStatus)
            assertEquals(ManagementBaselineStatus.Matched, deep.snapshot.managementSnapshot.baselineStatus)
            assertEquals(ManagementServiceState.ACTIVE, deep.snapshot.managementSnapshot.serviceState)
            assertNotNull(deep.snapshot.managementSnapshot.freshProof)
            assertTerminalJournal(journal, deepStarted.scope.operationId, OperationType.DEEP_DIAGNOSTIC, "DEEP_DIAGNOSTIC_RESULT")
            assertStoppedHost(deepStarted.scope.operationId, deepHostGeneration)

            val durableInstallationAfterReadback = installationRepository.get(installationId)
                .requireRepositorySuccess("read Phase 6.7 XuiInstallation after read-only operations")
            assertEquals(installation, durableInstallationAfterReadback.value)
            assertEquals(initialInstallationRevision, durableInstallationAfterReadback.revision)
            assertEquals(
                exactManagementAccess,
                managementRepository.get(installationId, exactAccessId)
                    .requireRepositorySuccess("read exact Phase 6.7 ManagementAccess after read-only operations"),
            )
            assertEquals(0L, database.installationDao().webPanelReferenceCount(installationId.value))
            assertTrue(accessRepository.get(poisonAccessId) is RepositoryResult.Success)
        } finally {
            operationIds.forEach { stopAcceptanceHostIfRunning(it) }
            if (observerRegistered) application.connectivityObserver.unregister()
            cleanupFixture(
                database = database,
                journal = journal,
                serverRepository = serverRepository,
                accessRepository = accessRepository,
                installationRepository = installationRepository,
                managementRepository = managementRepository,
                secretStore = secretStore,
                serverId = serverId,
                installationId = installationId,
                accessIds = listOf(exactAccessId, poisonAccessId),
                secretIds = listOf(exactSecretId, poisonSecretId),
                operationIds = operationIds,
            )
            database.close()
        }
    }

    private fun canonicalInstallation(id: XuiInstallationId, serverId: ServerId) = XuiInstallation(
        id = id,
        serverId = serverId,
        ownership = InstallationOwnership.ADOPTED,
        identity = InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = 54321,
            webBasePath = "/panel/",
            listenAddress = "127.0.0.1",
            capturedAt = Instant.parse("2026-09-06T12:00:00Z"),
        ),
    )

    private fun canonicalEnrollmentProof(
        runTag: String,
        serverId: ServerId,
        serverAccessId: ServerAccessId,
        identity: InstallationIdentity,
    ) = DiscoveryProof(
        id = DiscoveryProofId("phase6-8-enrollment-proof-$runTag"),
        scope = DiscoveryScope(
            operationId = OperationId("phase6-8-enrollment-source-$runTag"),
            serverId = serverId,
            serverAccessId = serverAccessId,
        ),
        observedIdentity = identity,
        candidateBaseline = null,
        supportingSignals = setOf(
            DiscoveryProofSignal.SERVICE_UNIT,
            DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH,
            DiscoveryProofSignal.DATABASE_PATH,
        ),
        observedAt = Instant.parse("2026-09-06T11:59:59Z"),
    )

    private suspend fun <T> withVisibleActivity(block: suspend (MainActivity) -> T): T {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        return try {
            var activity: MainActivity? = null
            scenario.onActivity { activity = it }
            block(requireNotNull(activity))
        } finally {
            scenario.close()
        }
    }

    private suspend fun awaitManagementDetail(operationId: OperationId): ManagementReadResult.Detailed {
        val projector = application.managementResultProjector()
        val deadline = System.nanoTime() + RESULT_TIMEOUT_MILLIS * 1_000_000L
        var latest: ManagementReadResult? = null
        while (System.nanoTime() < deadline) {
            val current = projector.read(operationId)
            latest = current
            when (current) {
                is ManagementReadResult.Detailed -> return current
                is ManagementReadResult.InProgress -> if (current.processNotice != null) {
                    throw AssertionError("QUICK_INSPECT stopped with ${current.processNotice::class.java.simpleName}")
                }
                is ManagementReadResult.DetailedFailure -> throw AssertionError("QUICK_INSPECT failed: ${current.kind}")
                is ManagementReadResult.DurableTerminal -> {
                    // The durable terminal commit happens inside Management execution before the
                    // transport sequence closes the exact SessionId and the Service publishes its
                    // process-local detail. While this exact attempt is still tracked, RESULT can
                    // therefore be a short-lived terminal-to-detail handoff state, not process loss.
                    if (!application.managementResultRegistry.isTracked(operationId)) {
                        throw AssertionError("QUICK detailed result unavailable after process-local attempt was lost: ${current.summary.kind}")
                    }
                }
                is ManagementReadResult.ContractViolation -> throw AssertionError("QUICK projection violation: ${current.reason}")
                is ManagementReadResult.Unavailable -> throw AssertionError("QUICK projection unavailable: ${current.failure}")
                ManagementReadResult.NotFound -> throw AssertionError("QUICK operation disappeared")
            }
            delay(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for QUICK detail; latest=$latest")
    }

    private suspend fun awaitDeepDetail(operationId: OperationId): DeepDiagnosticReadResult.Detailed {
        val projector = application.deepDiagnosticResultProjector()
        val deadline = System.nanoTime() + RESULT_TIMEOUT_MILLIS * 1_000_000L
        var latest: DeepDiagnosticReadResult? = null
        while (System.nanoTime() < deadline) {
            val current = projector.read(operationId)
            latest = current
            when (current) {
                is DeepDiagnosticReadResult.Detailed -> return current
                is DeepDiagnosticReadResult.InProgress -> if (current.processNotice != null) {
                    throw AssertionError("DEEP_DIAGNOSTIC stopped with ${current.processNotice::class.java.simpleName}")
                }
                is DeepDiagnosticReadResult.DetailedFailure -> throw AssertionError("DEEP_DIAGNOSTIC failed: ${current.kind}")
                is DeepDiagnosticReadResult.DurableTerminal -> {
                    // Same canonical ordering as QUICK_INSPECT: durable terminal first, exact
                    // SessionId cleanup next, process-local detail publication after sequence return.
                    if (!application.deepDiagnosticResultRegistry.isTracked(operationId)) {
                        throw AssertionError("Deep detailed result unavailable after process-local attempt was lost: ${current.summary.kind}")
                    }
                }
                is DeepDiagnosticReadResult.ContractViolation -> throw AssertionError("Deep projection violation: ${current.reason}")
                is DeepDiagnosticReadResult.Unavailable -> throw AssertionError("Deep projection unavailable: ${current.failure}")
                DeepDiagnosticReadResult.NotFound -> throw AssertionError("Deep operation disappeared")
            }
            delay(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Deep detail; latest=$latest")
    }

    private suspend fun assertTerminalJournal(
        journal: RoomOperationJournal,
        operationId: OperationId,
        type: OperationType,
        phase: String,
    ) {
        val durable = journal.get(operationId).requireOperationSuccess("read Phase 6.7 terminal journal")
        assertEquals(type, durable.snapshot.type)
        assertEquals(OperationStatus.SUCCEEDED, durable.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, durable.snapshot.checkpoint.semantics)
        assertEquals(phase, durable.snapshot.checkpoint.phaseName)
        assertEquals(durable.snapshot.updatedAt, durable.snapshot.checkpoint.recordedAt)
    }

    private fun assertStoppedHost(operationId: OperationId, afterGeneration: Long): ExactOperationHostLifecycleEvidence {
        val evidence = awaitTerminalHostEvidence(operationId, afterGeneration)
        assertEquals(ExactOperationHostLifecycleState.STOPPED, evidence.state)
        return evidence
    }

    private fun awaitTerminalHostEvidence(operationId: OperationId, afterGeneration: Long): ExactOperationHostLifecycleEvidence {
        val deadline = System.nanoTime() + HOST_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadline) {
            val evidence = application.operationHostLifecycleRegistry.latest()
            if (evidence != null && evidence.operationId == operationId && evidence.generation > afterGeneration && evidence.state.isTerminal) return evidence
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for Phase 6.7 host cleanup; latest=${application.operationHostLifecycleRegistry.latest()}")
    }

    private fun stopAcceptanceHostIfRunning(operationId: OperationId) {
        val latest = application.operationHostLifecycleRegistry.latest()
        if (latest != null && latest.operationId == operationId && !latest.state.isTerminal) {
            context.stopService(Intent(context, ExactOperationShortService::class.java))
            awaitTerminalHostEvidence(operationId, latest.generation - 1)
        }
    }

    private fun awaitValidatedDefaultNetwork(connectivityManager: ConnectivityManager) {
        val deadline = System.nanoTime() + NETWORK_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadline) {
            val network = connectivityManager.activeNetwork
            val caps = network?.let { connectivityManager.getNetworkCapabilities(it) }
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for validated Android default network")
    }

    private fun awaitStableOnlineObservationAfter(afterGeneration: Long): ConnectivityObservation {
        val deadline = System.nanoTime() + NETWORK_TIMEOUT_MILLIS * 1_000_000L
        var candidate: Long? = null
        var stableSince = 0L
        while (System.nanoTime() < deadline) {
            val now = System.nanoTime()
            val observation = application.operationRuntimeCoordinator.connectivitySnapshot()
            if (observation.generation > afterGeneration && observation.state == ConnectivityState.ONLINE) {
                if (candidate != observation.generation) {
                    candidate = observation.generation
                    stableSince = now
                } else if (now - stableSince >= NETWORK_STABILITY_MILLIS * 1_000_000L) return observation
            } else {
                candidate = null
                stableSince = 0L
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for stable production ONLINE observation")
    }

    private suspend fun createSecret(store: AndroidKeystoreSecretStore, id: SecretId, value: String) {
        ensureSecretAbsent(store, id)
        val material = SecretMaterial.fromBytes(value.toByteArray(StandardCharsets.UTF_8))
        try { assertEquals(SecretCreateResult.Created, store.create(id, material)) } finally { material.close() }
    }

    private suspend fun cleanupFixture(
        database: VelumDatabase,
        journal: RoomOperationJournal,
        serverRepository: RoomServerRepository,
        accessRepository: RoomServerAccessRepository,
        installationRepository: RoomXuiInstallationRepository,
        managementRepository: RoomManagementAccessRepository,
        secretStore: AndroidKeystoreSecretStore,
        serverId: ServerId,
        installationId: XuiInstallationId,
        accessIds: List<ServerAccessId>,
        secretIds: List<SecretId>,
        operationIds: List<OperationId>,
    ) {
        operationIds.forEach { operationId ->
            val current = when (val result = journal.get(operationId)) {
                is OperationJournalResult.Success -> result.value
                OperationJournalResult.NotFound -> null
                else -> throw AssertionError("Cleanup could not read ${operationId.value}: ${result::class.java.simpleName}")
            }
            if (current != null) {
                val terminal = if (current.snapshot.status in TERMINAL_STATUSES && current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) current else {
                    val cleanupAt = laterThan(current.snapshot.updatedAt)
                    journal.advance(
                        operationId,
                        current.revision,
                        current.snapshot.copy(
                            status = OperationStatus.CANCELLED,
                            checkpoint = OperationCheckpoint("PHASE6_7_ACCEPTANCE_CLEANUP", CheckpointSemantics.TERMINAL, cleanupAt),
                            updatedAt = cleanupAt,
                        ),
                    ).requireOperationSuccess("terminalize Phase 6.7 operation")
                }
                database.withWriteTransaction {
                    database.operationDao().deleteJournalForOperation(operationId.value)
                    check(database.operationDao().deleteTerminalSnapshotCas(operationId.value, terminal.revision.value) == 1)
                }
                application.managementResultRegistry.clear(operationId)
                application.deepDiagnosticResultRegistry.clear(operationId)
            }
        }

        when (managementRepository.delete(installationId, accessIds.first())) {
            is RepositoryResult.Success, RepositoryResult.NotFound -> Unit
            else -> throw AssertionError("Cleanup could not delete ManagementAccess")
        }
        when (val installed = installationRepository.get(installationId)) {
            is RepositoryResult.Success -> installationRepository.delete(installationId, installed.value.revision)
                .requireRepositorySuccess("delete Phase 6.7 installation")
            RepositoryResult.NotFound -> Unit
            else -> throw AssertionError("Cleanup could not read Phase 6.7 installation")
        }
        accessIds.forEach { id ->
            when (accessRepository.delete(id)) {
                is RepositoryResult.Success, RepositoryResult.NotFound -> Unit
                else -> throw AssertionError("Cleanup could not delete ${id.value}")
            }
        }
        when (val server = serverRepository.get(serverId)) {
            is RepositoryResult.Success -> serverRepository.delete(serverId, server.value.revision)
                .requireRepositorySuccess("delete Phase 6.7 server")
            RepositoryResult.NotFound -> Unit
            else -> throw AssertionError("Cleanup could not read Phase 6.7 server")
        }
        secretIds.forEach { ensureSecretAbsent(secretStore, it) }
    }

    private suspend fun ensureSecretAbsent(store: AndroidKeystoreSecretStore, id: SecretId) {
        when (val result = store.delete(id)) {
            SecretDeleteResult.Deleted, SecretDeleteResult.AlreadyAbsent -> Unit
            is SecretDeleteResult.StorageFailure -> throw AssertionError("Secret cleanup failed: ${result.reason}")
        }
    }

    private fun readFixturePort(): Int = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_PORT)
        ?.toIntOrNull()?.takeIf { it in 1..65535 } ?: throw AssertionError("Runner provided invalid Phase 6.7 fixture port")

    private fun readFixtureFingerprint(): String = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_FINGERPRINT)
        ?.takeIf { it.startsWith("SHA256:") && it.length > 7 } ?: throw AssertionError("Runner provided invalid Phase 6.7 fingerprint")

    private fun readRunTag(): String = InstrumentationRegistry.getArguments().getString(ARG_RUN_TAG)
        ?.takeIf { it.matches(Regex("[a-f0-9]{12}")) } ?: throw AssertionError("Runner provided invalid Phase 6.7 run tag")

    private fun laterThan(value: Instant): Instant = Instant.now().let { if (it.isAfter(value)) it else value.plusNanos(1) }

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(action: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(action: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private companion object {
        const val FIXTURE_USERNAME = "velum-phase67"
        const val FIXTURE_PASSWORD = "VELUM-phase67-test-only-password"
        const val POISON_USERNAME = "velum-phase67-poison"
        const val POISON_PASSWORD = "VELUM-phase67-poison-test-only-password"
        const val ARG_FIXTURE_PORT = "phase67.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase67.fixtureFingerprint"
        const val ARG_RUN_TAG = "phase67.runTag"
        const val POLL_INTERVAL_MILLIS = 50L
        const val NETWORK_STABILITY_MILLIS = 1_000L
        const val NETWORK_TIMEOUT_MILLIS = 30_000L
        const val RESULT_TIMEOUT_MILLIS = 90_000L
        const val HOST_TIMEOUT_MILLIS = 30_000L
        val TERMINAL_STATUSES = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
    }
}
