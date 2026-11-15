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
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.DiscoveryResult
import com.velumtegra.xuimobile.core.model.DiscoveryTerminalKind
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.discovery.DiscoveryOperationStartResult
import com.velumtegra.xuimobile.discovery.DiscoveryReadResult
import com.velumtegra.xuimobile.discovery.VisibleDiscoveryOperationLauncher
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleEvidence
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleState
import com.velumtegra.xuimobile.runtime.ExactOperationShortService
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 5.7 production-shaped real-device Discovery acceptance.
 *
 * A deterministic Apache MINA fixture is exposed only through USB adb reverse. The test creates a
 * real durable Discovery operation through [VisibleDiscoveryOperationLauncher], lets the production
 * Phase 4 Service/runtime establish the exact SSH session, executes the canonical bounded read-only
 * probe plan, observes one detailed supported-installation result and exact host cleanup, and proves
 * that no XuiInstallation is silently adopted.
 *
 * A second poison ServerAccess exists on the same Server. The host fixture independently fails if
 * that fallback credential is ever attempted or if any command outside the canonical Discovery
 * allowlist is dispatched. The fixture itself executes no shell/process and mutates no host state.
 */
@RunWith(AndroidJUnit4::class)
class Phase5_7ReadOnlyDiscoveryInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun explicitEntryRunsExactReadOnlyDiscoveryAndProjectsProvenResult() = runBlocking {
        val fixturePort = readFixturePort()
        val fixtureFingerprint = readFixtureFingerprint()
        val runTag = readRunTag()

        val serverId = ServerId("phase5-7-server-$runTag")
        val exactAccessId = ServerAccessId("phase5-7-exact-access-$runTag")
        val poisonAccessId = ServerAccessId("phase5-7-poison-access-$runTag")
        val exactSecretId = SecretId("phase5-7-exact-secret-$runTag")
        val poisonSecretId = SecretId("phase5-7-poison-secret-$runTag")

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val installationRepository = RoomXuiInstallationRepository(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val connectivityManager = requireNotNull(
            context.getSystemService(ConnectivityManager::class.java),
        ) { "ConnectivityManager is unavailable" }

        var operationId: OperationId? = null
        var observerRegistered = false

        try {
            awaitValidatedDefaultNetwork(connectivityManager)
            val baselineConnectivityGeneration = application.operationRuntimeCoordinator.connectivitySnapshot().generation
            assertTrue(
                "Acceptance must own the production default-network observer registration before host start",
                application.connectivityObserver.register(),
            )
            observerRegistered = true
            awaitStableOnlineObservationAfter(baselineConnectivityGeneration)

            createSecret(secretStore, exactSecretId, FIXTURE_PASSWORD)
            createSecret(secretStore, poisonSecretId, POISON_PASSWORD)

            val createdAt = Instant.now()
            serverRepository.create(
                Server(
                    id = serverId,
                    displayName = "Phase 5.7 read-only Discovery acceptance",
                    createdAt = createdAt,
                ),
            ).requireRepositorySuccess("create Phase 5.7 Server")

            credentialWriter.createServerAccess(
                ServerAccess(
                    id = exactAccessId,
                    serverId = serverId,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = FIXTURE_USERNAME,
                    auth = SshAuthRef.Password(exactSecretId),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
            ).requireRepositorySuccess("create exact Phase 5.7 ServerAccess")
            credentialWriter.createServerAccess(
                ServerAccess(
                    id = poisonAccessId,
                    serverId = serverId,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = POISON_USERNAME,
                    auth = SshAuthRef.Password(poisonSecretId),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
            ).requireRepositorySuccess("create poison fallback ServerAccess")

            assertEquals(
                2,
                accessRepository.listForServer(serverId)
                    .requireRepositorySuccess("list exact + poison ServerAccess records")
                    .size,
            )
            assertTrue(
                "Discovery acceptance must begin with no durable XuiInstallation",
                installationRepository.listForServer(serverId)
                    .requireRepositorySuccess("read pre-Discovery installation list")
                    .isEmpty(),
            )

            val baselineHostGeneration = application.operationHostLifecycleRegistry.latest()?.generation ?: 0L
            val scenario = ActivityScenario.launch(MainActivity::class.java)
            val startResult = try {
                var launcher: VisibleDiscoveryOperationLauncher? = null
                scenario.onActivity { activity ->
                    launcher = application.visibleDiscoveryOperationLauncher(activity)
                }
                requireNotNull(launcher).start(serverId, exactAccessId)
            } finally {
                // Presentation lifetime is intentionally shorter than Discovery execution.
                scenario.close()
            }

            val started = startResult as? DiscoveryOperationStartResult.Started
                ?: throw AssertionError("Production explicit Discovery entry was not accepted: ${startResult::class.java.simpleName}")
            val startedOperationId = started.scope.operationId
            operationId = startedOperationId
            assertEquals(serverId, started.scope.serverId)
            assertEquals(exactAccessId, started.scope.serverAccessId)

            val detailed = awaitDetailedResult(startedOperationId)
            val result = detailed.result as? DiscoveryResult.ProvenSupportedInstallation
                ?: throw AssertionError("Phase 5.7 expected a proven supported installation, got ${detailed.result::class.java.simpleName}")

            assertEquals(started.scope, result.scope)
            assertEquals("x-ui.service", result.proof.observedIdentity.serviceUnit)
            assertEquals("/usr/local/x-ui/x-ui", result.proof.observedIdentity.binaryPath)
            assertEquals("/usr/local/x-ui", result.proof.observedIdentity.rootPath)
            assertEquals("/etc/x-ui/x-ui.db", result.proof.observedIdentity.databasePath)
            assertNull(result.proof.observedIdentity.managedInstallId)
            assertNull("Initial Discovery plan intentionally does not invent a panel baseline", result.proof.candidateBaseline)
            assertEquals(
                setOf(
                    DiscoveryProofSignal.SERVICE_UNIT,
                    DiscoveryProofSignal.BINARY_PATH,
                    DiscoveryProofSignal.ROOT_PATH,
                    DiscoveryProofSignal.DATABASE_PATH,
                ),
                result.proof.supportingSignals,
            )

            val durable = journal.get(startedOperationId)
                .requireOperationSuccess("read terminal Phase 5.7 durable operation")
            assertEquals(OperationType.DISCOVERY, durable.snapshot.type)
            assertEquals(
                OperationTarget.ServerTarget(serverId, exactAccessId),
                durable.snapshot.target,
            )
            assertEquals(OperationStatus.SUCCEEDED, durable.snapshot.status)
            assertEquals(CheckpointSemantics.TERMINAL, durable.snapshot.checkpoint.semantics)
            assertEquals(
                DiscoveryTerminalKind.PROVEN_SUPPORTED.phaseName,
                durable.snapshot.checkpoint.phaseName,
            )
            assertEquals(result.completedAt, durable.snapshot.updatedAt)
            assertEquals(result.completedAt, durable.snapshot.checkpoint.recordedAt)

            assertTrue(
                "Discovery result must not silently publish/adopt a durable XuiInstallation",
                installationRepository.listForServer(serverId)
                    .requireRepositorySuccess("read post-Discovery installation list")
                    .isEmpty(),
            )
            assertTrue(
                "Poison fallback ServerAccess must remain untouched/present",
                accessRepository.get(poisonAccessId) is RepositoryResult.Success,
            )

            val hostTerminal = awaitTerminalHostEvidence(startedOperationId, baselineHostGeneration)
            assertEquals(ExactOperationHostLifecycleState.STOPPED, hostTerminal.state)
            assertTrue(hostTerminal.generation > baselineHostGeneration)
        } finally {
            try {
                operationId?.let(::stopAcceptanceHostIfRunning)
            } finally {
                try {
                    if (observerRegistered) {
                        application.connectivityObserver.unregister()
                    }
                } finally {
                    try {
                        cleanupFixture(
                            database = database,
                            journal = journal,
                            serverRepository = serverRepository,
                            accessRepository = accessRepository,
                            secretStore = secretStore,
                            serverId = serverId,
                            accessIds = listOf(exactAccessId, poisonAccessId),
                            secretIds = listOf(exactSecretId, poisonSecretId),
                            operationId = operationId,
                        )
                    } finally {
                        database.close()
                    }
                }
            }
        }
    }

    private suspend fun awaitDetailedResult(operationId: OperationId): DiscoveryReadResult.Detailed {
        val projector = application.discoveryResultProjector()
        val deadlineNanos = System.nanoTime() + DISCOVERY_TIMEOUT_MILLIS * 1_000_000L
        var latest: DiscoveryReadResult? = null
        while (System.nanoTime() < deadlineNanos) {
            val current = projector.read(operationId)
            latest = current
            when (current) {
                is DiscoveryReadResult.Detailed -> return current
                is DiscoveryReadResult.InProgress -> {
                    if (current.processNotice != null) {
                        throw AssertionError(
                            "Discovery stopped before terminal RESULT with safe notice ${current.processNotice::class.java.simpleName}",
                        )
                    }
                }
                is DiscoveryReadResult.DurableTerminal -> throw AssertionError(
                    "Process-local detailed Discovery result disappeared before acceptance read: ${current.summary.kind}",
                )
                is DiscoveryReadResult.ContractViolation -> throw AssertionError(
                    "Discovery projection contract violation: ${current.reason}",
                )
                is DiscoveryReadResult.Unavailable -> throw AssertionError(
                    "Discovery projection unavailable: ${current.failure}",
                )
                DiscoveryReadResult.NotFound -> throw AssertionError("Discovery operation disappeared from durable journal")
            }
            delay(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for detailed Discovery RESULT; latest=$latest")
    }

    private fun awaitTerminalHostEvidence(
        operationId: OperationId,
        afterGeneration: Long,
    ): ExactOperationHostLifecycleEvidence {
        val deadlineNanos = System.nanoTime() + HOST_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val evidence = application.operationHostLifecycleRegistry.latest()
            if (
                evidence != null &&
                evidence.operationId == operationId &&
                evidence.generation > afterGeneration &&
                evidence.state.isTerminal
            ) {
                return evidence
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for terminal Phase 5.7 host evidence; latest=${application.operationHostLifecycleRegistry.latest()}",
        )
    }

    private fun stopAcceptanceHostIfRunning(operationId: OperationId) {
        val latest = application.operationHostLifecycleRegistry.latest()
        if (latest != null && latest.operationId == operationId && !latest.state.isTerminal) {
            context.stopService(Intent(context, ExactOperationShortService::class.java))
            val deadlineNanos = System.nanoTime() + HOST_TIMEOUT_MILLIS * 1_000_000L
            while (System.nanoTime() < deadlineNanos) {
                val current = application.operationHostLifecycleRegistry.latest()
                if (current != null && current.operationId == operationId && current.state.isTerminal) return
                Thread.sleep(POLL_INTERVAL_MILLIS)
            }
            throw AssertionError("Acceptance cleanup could not stop exact Phase 5.7 production host")
        }
    }

    private fun awaitValidatedDefaultNetwork(connectivityManager: ConnectivityManager) {
        val deadlineNanos = System.nanoTime() + NETWORK_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val network = connectivityManager.activeNetwork
            val capabilities = network?.let { connectivityManager.getNetworkCapabilities(it) }
            if (
                capabilities != null &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            ) {
                return
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for a validated Android default network")
    }

    private fun awaitStableOnlineObservationAfter(afterGeneration: Long): ConnectivityObservation {
        val deadlineNanos = System.nanoTime() + NETWORK_TIMEOUT_MILLIS * 1_000_000L
        var candidateGeneration: Long? = null
        var stableSinceNanos = 0L
        while (System.nanoTime() < deadlineNanos) {
            val now = System.nanoTime()
            val observation = application.operationRuntimeCoordinator.connectivitySnapshot()
            if (observation.generation > afterGeneration && observation.state == ConnectivityState.ONLINE) {
                if (candidateGeneration != observation.generation) {
                    candidateGeneration = observation.generation
                    stableSinceNanos = now
                } else if (now - stableSinceNanos >= NETWORK_STABILITY_MILLIS * 1_000_000L) {
                    return observation
                }
            } else {
                candidateGeneration = null
                stableSinceNanos = 0L
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for a stable production ONLINE observation; latest=" +
                application.operationRuntimeCoordinator.connectivitySnapshot(),
        )
    }

    private suspend fun createSecret(
        secretStore: AndroidKeystoreSecretStore,
        secretId: SecretId,
        value: String,
    ) {
        ensureSecretAbsent(secretStore, secretId)
        val material = SecretMaterial.fromBytes(value.toByteArray(StandardCharsets.UTF_8))
        try {
            assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
        } finally {
            material.close()
        }
    }

    private suspend fun cleanupFixture(
        database: VelumDatabase,
        journal: RoomOperationJournal,
        serverRepository: RoomServerRepository,
        accessRepository: RoomServerAccessRepository,
        secretStore: AndroidKeystoreSecretStore,
        serverId: ServerId,
        accessIds: List<ServerAccessId>,
        secretIds: List<SecretId>,
        operationId: OperationId?,
    ) {
        if (operationId != null) {
            val current = when (val result = journal.get(operationId)) {
                is OperationJournalResult.Success -> result.value
                OperationJournalResult.NotFound -> null
                else -> throw AssertionError(
                    "Acceptance cleanup could not read ${operationId.value}: ${result::class.java.simpleName}",
                )
            }
            if (current != null) {
                val terminal = if (
                    current.snapshot.status in TERMINAL_STATUSES &&
                    current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
                ) {
                    current
                } else {
                    val cleanupAt = laterThan(current.snapshot.updatedAt)
                    journal.advance(
                        operationId,
                        current.revision,
                        current.snapshot.copy(
                            status = OperationStatus.CANCELLED,
                            checkpoint = OperationCheckpoint(
                                phaseName = "PHASE5_7_ACCEPTANCE_CLEANUP",
                                semantics = CheckpointSemantics.TERMINAL,
                                recordedAt = cleanupAt,
                            ),
                            updatedAt = cleanupAt,
                        ),
                    ).requireOperationSuccess("terminalize Phase 5.7 operation for cleanup")
                }
                database.withWriteTransaction {
                    database.operationDao().deleteJournalForOperation(operationId.value)
                    check(
                        database.operationDao().deleteTerminalSnapshotCas(
                            operationId = operationId.value,
                            expectedRevision = terminal.revision.value,
                        ) == 1,
                    ) { "Acceptance cleanup lost exact terminal Phase 5.7 Operation row" }
                }
                application.discoveryResultRegistry.clear(operationId)
            }
        }

        accessIds.forEach { accessId ->
            when (val result = accessRepository.delete(accessId)) {
                is RepositoryResult.Success, RepositoryResult.NotFound -> Unit
                else -> throw AssertionError(
                    "Acceptance cleanup could not delete ${accessId.value}: ${result::class.java.simpleName}",
                )
            }
        }

        when (val current = serverRepository.get(serverId)) {
            is RepositoryResult.Success -> when (val result = serverRepository.delete(serverId, current.value.revision)) {
                is RepositoryResult.Success -> Unit
                else -> throw AssertionError(
                    "Acceptance cleanup could not delete ${serverId.value}: ${result::class.java.simpleName}",
                )
            }
            RepositoryResult.NotFound -> Unit
            else -> throw AssertionError(
                "Acceptance cleanup could not read ${serverId.value}: ${current::class.java.simpleName}",
            )
        }

        secretIds.forEach { secretId -> ensureSecretAbsent(secretStore, secretId) }
    }

    private suspend fun ensureSecretAbsent(secretStore: AndroidKeystoreSecretStore, secretId: SecretId) {
        when (val result = secretStore.delete(secretId)) {
            SecretDeleteResult.Deleted,
            SecretDeleteResult.AlreadyAbsent,
            -> Unit
            is SecretDeleteResult.StorageFailure -> throw AssertionError(
                "Acceptance SecretStore cleanup failed without exposing secret material: ${result.reason}",
            )
        }
    }

    private fun readFixturePort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_PORT)
            ?: throw AssertionError("Runner did not provide $ARG_FIXTURE_PORT")
        return raw.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw AssertionError("Runner provided invalid Phase 5.7 fixture port")
    }

    private fun readFixtureFingerprint(): String {
        val value = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_FINGERPRINT)
            ?: throw AssertionError("Runner did not provide $ARG_FIXTURE_FINGERPRINT")
        if (!value.startsWith("SHA256:") || value.length <= 7) {
            throw AssertionError("Runner provided invalid canonical fixture host-key fingerprint")
        }
        return value
    }

    private fun readRunTag(): String {
        val value = InstrumentationRegistry.getArguments().getString(ARG_RUN_TAG)
            ?: throw AssertionError("Runner did not provide $ARG_RUN_TAG")
        if (!value.matches(Regex("[a-f0-9]{12}"))) {
            throw AssertionError("Runner provided invalid Phase 5.7 run tag")
        }
        return value
    }

    private fun laterThan(value: Instant): Instant {
        val current = Instant.now()
        return if (current.isAfter(value)) current else value.plusNanos(1)
    }

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(action: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(action: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private companion object {
        const val FIXTURE_USERNAME = "velum-phase57"
        const val FIXTURE_PASSWORD = "VELUM-phase57-test-only-password"
        const val POISON_USERNAME = "velum-phase57-poison"
        const val POISON_PASSWORD = "VELUM-phase57-poison-test-only-password"

        const val ARG_FIXTURE_PORT = "phase57.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase57.fixtureFingerprint"
        const val ARG_RUN_TAG = "phase57.runTag"

        const val POLL_INTERVAL_MILLIS = 50L
        const val NETWORK_STABILITY_MILLIS = 1_500L
        const val NETWORK_TIMEOUT_MILLIS = 30_000L
        const val DISCOVERY_TIMEOUT_MILLIS = 60_000L
        const val HOST_TIMEOUT_MILLIS = 20_000L

        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}
