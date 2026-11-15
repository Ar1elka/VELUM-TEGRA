package com.velumtegra.xuimobile.integration

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import androidx.room3.withWriteTransaction
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.domain.CommitAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResumeAction
import com.velumtegra.xuimobile.core.domain.ResumePolicy
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InterruptionReason
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.RemoteVerificationState
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.DurableServerMutationBarrierPolicy
import com.velumtegra.xuimobile.core.runtime.ServerMutationBarrierDecision
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6E real-device post-dispatch Unknown/no-replay acceptance.
 *
 * A host-side Apache MINA fixture is exposed only through USB `adb reverse`. It authenticates a
 * fixed test-only credential, never invokes a shell, accepts exactly one deterministic read-only
 * token, and then deliberately withholds command completion. The PowerShell runner waits for the
 * host fixture to confirm that the exec request was actually received before it removes Android's
 * real default network.
 *
 * Because USB reverse is intentionally independent of the Android data network, this test closes
 * the exact production JSch session only after the production default-network observer has emitted
 * the newer OFFLINE generation. That deterministic close represents the unusable transport cleanup
 * after a real network-loss event. Since the server already confirmed the exec request, production
 * JSch must conservatively report DISPATCHED + Unknown. Durable MUTATION_IN_FLIGHT evidence must stay
 * unchanged, restored connectivity may authorize only RECONCILE_READ_ONLY, and the durable server
 * mutation barrier must remain closed. No real mutation command exists in this acceptance slice.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6EPostDispatchUnknownInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun serverConfirmedDispatchThenRealNetworkLossIsUnknownAndOnlyReadOnlyReconciliationIsAllowed() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val connectivityManager = requireNotNull(
            context.getSystemService(ConnectivityManager::class.java),
        ) { "ConnectivityManager is unavailable" }

        val originalControls = readOriginalConnectivityControls()
        val fixturePort = readFixturePort()
        val fixtureFingerprint = readFixtureFingerprint()
        var observerRegistered = false
        var handle: SshSessionHandle? = null

        try {
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            createFixtureCredential(secretStore)
            awaitValidatedDefaultNetwork(connectivityManager)

            val startedAt = Instant.now()
            val server = Server(
                id = SERVER_ID,
                displayName = "Phase 4.6E post-dispatch Unknown acceptance",
                createdAt = startedAt,
            )
            val access = ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", fixturePort),
                username = FIXTURE_USERNAME,
                auth = SshAuthRef.Password(SECRET_ID),
                pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
            )
            val initial = OperationSnapshot(
                operationId = OPERATION_ID,
                type = OperationType.RECOVERY,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6E_SYNTHETIC_MUTATION_IN_FLIGHT",
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            )

            serverRepository.create(server).requireRepositorySuccess("create acceptance Server")
            credentialWriter.createServerAccess(access).requireRepositorySuccess("create acceptance ServerAccess")
            val created = journal.create(initial).requireOperationSuccess("create acceptance Operation")

            val baselineObservation = application.operationRuntimeCoordinator.connectivitySnapshot()
            assertTrue(
                "Acceptance must own the only production default-network observer registration",
                application.connectivityObserver.register(),
            )
            observerRegistered = true

            awaitValidatedDefaultNetwork(connectivityManager)
            val initialOnline = awaitStableOnlineObservationAfter(baselineObservation.generation)
            assertTrue(
                "Phase 4.6E must start from a newer production ONLINE generation",
                initialOnline.generation > baselineObservation.generation,
            )

            val connect = JschSshConnectionFactory(secretStore).connect(
                access = access,
                owner = SessionOwner.Operation(OPERATION_ID),
                config = TEST_CONFIG,
            )
            val connected = connect as? SshConnectResult.Connected
                ?: throw AssertionError(
                    "Phase 4.6E deterministic host SSH connect failed: ${connect::class.java.simpleName}",
                )
            val connectedHandle = connected.handle
            handle = connectedHandle
            assertTrue("Exact production SSH session must be open before the dispatch probe", connectedHandle.isOpen)

            val activeCommand = async(Dispatchers.IO) {
                connectedHandle.execute(
                    command = RemoteCommand.create(
                        raw = FIXTURE_COMMAND,
                        redactedLabel = "phase46e-read-only-dispatch-probe",
                    ),
                    config = TEST_CONFIG,
                )
            }

            // The runner does not remove Android connectivity until the host fixture has written its
            // server-side dispatch marker for this exact exec request.
            val offlineObservation = awaitObservationAfter(
                afterGeneration = initialOnline.generation,
                expectedState = ConnectivityState.OFFLINE,
            )
            awaitNoPhysicalDefaultNetwork(connectivityManager)
            assertNull(
                "Runner promised a real no-default-network state after server-confirmed dispatch",
                connectivityManager.activeNetwork,
            )

            // USB reverse itself survives Android radio loss, so close the exact session only after
            // the production OFFLINE generation exists. This deterministically models transport
            // cleanup after the real loss without allowing the test fixture to fake dispatch order.
            connectedHandle.close()

            val commandResult = withTimeout(COMMAND_RESULT_TIMEOUT_MILLIS) {
                activeCommand.await()
            }
            assertEquals(
                "Server-confirmed exec must stay conservatively DISPATCHED after transport loss",
                CommandDispatchState.DISPATCHED,
                commandResult.dispatchState,
            )
            assertTrue(
                "Loss after confirmed dispatch must never become false success/failure",
                commandResult.completion is CommandCompletion.Unknown,
            )
            assertFalse("Exact session must be closed after loss cleanup", connectedHandle.isOpen)

            val durableAfterLoss = journal.get(OPERATION_ID)
                .requireOperationSuccess("read durable state after post-dispatch loss")
            assertEquals(
                "Transport Unknown must not silently rewrite durable operation truth",
                created,
                durableAfterLoss,
            )
            assertFalse(
                "Unknown command completion without authoritative remote verification cannot commit mutation truth",
                CommitAuthorizationPolicy.mayCommitRemoteMutation(
                    commandCompletion = commandResult.completion,
                    verification = RemoteVerificationState.UNVERIFIED,
                ),
            )

            restoreConnectivityControls(originalControls)
            awaitValidatedDefaultNetwork(connectivityManager)
            val restoredOnline = awaitStableOnlineObservationAfter(offlineObservation.generation)
            assertTrue(
                "Restored ONLINE generation must supersede the real OFFLINE generation",
                restoredOnline.generation > offlineObservation.generation,
            )

            val durableAfterRestore = journal.get(OPERATION_ID)
                .requireOperationSuccess("read durable state after connectivity restoration")
            assertEquals(created, durableAfterRestore)

            val resumePlan = ResumePolicy.plan(
                operation = durableAfterRestore.snapshot,
                interruption = InterruptionReason.NETWORK_LOSS,
                connectivity = ConnectivityState.ONLINE,
            )
            assertEquals(
                "Unsafe post-dispatch durable evidence may only resume through read-only reconciliation",
                ResumeAction.RECONCILE_READ_ONLY,
                resumePlan.action,
            )
            assertTrue("Read-only reconciliation may be scheduled automatically after network restoration", resumePlan.automaticAllowed)

            val barrier = DurableServerMutationBarrierPolicy.evaluate(
                serverId = SERVER_ID,
                durableOperations = listOf(durableAfterRestore.snapshot),
            )
            val blocked = barrier as? ServerMutationBarrierDecision.BlockedByUncertainMutation
                ?: throw AssertionError(
                    "MUTATION_IN_FLIGHT must keep the durable same-server mutation barrier closed; got " +
                        barrier::class.java.simpleName,
                )
            assertEquals(1, blocked.blockers.size)
            assertEquals(OPERATION_ID, blocked.blockers.single().operationId)
            assertEquals(OperationStatus.RUNNING, blocked.blockers.single().status)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, blocked.blockers.single().checkpointSemantics)

            // Give any accidental hidden replay path a bounded opportunity to reveal itself. The
            // host-side fixture independently fails unless its final exec-request count remains one.
            Thread.sleep(NO_REPLAY_SETTLE_MILLIS)
        } finally {
            try {
                handle?.close()
            } finally {
                try {
                    if (observerRegistered) {
                        assertTrue(
                            "Acceptance must unregister the exact production connectivity callback it registered",
                            application.connectivityObserver.unregister(),
                        )
                    }
                } finally {
                    try {
                        cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
                    } finally {
                        try {
                            database.close()
                        } finally {
                            restoreConnectivityControls(originalControls)
                        }
                    }
                }
            }
        }
    }

    private fun readOriginalConnectivityControls(): ConnectivityControls {
        val arguments = InstrumentationRegistry.getArguments()
        val airplane = arguments.getString(ARG_ORIGINAL_AIRPLANE)
            ?: throw AssertionError("Runner did not provide $ARG_ORIGINAL_AIRPLANE")
        val wifi = arguments.getString(ARG_ORIGINAL_WIFI)
            ?: throw AssertionError("Runner did not provide $ARG_ORIGINAL_WIFI")
        if (airplane !in setOf("0", "1") || wifi !in setOf("0", "1")) {
            throw AssertionError("Runner provided invalid original connectivity controls")
        }
        return ConnectivityControls(airplane = airplane, wifi = wifi)
    }

    private fun readFixturePort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_PORT)
            ?: throw AssertionError("Runner did not provide $ARG_FIXTURE_PORT")
        return raw.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw AssertionError("Runner provided invalid fixture port")
    }

    private fun readFixtureFingerprint(): String {
        val value = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_FINGERPRINT)
            ?: throw AssertionError("Runner did not provide $ARG_FIXTURE_FINGERPRINT")
        if (!value.startsWith("SHA256:") || value.length <= "SHA256:".length) {
            throw AssertionError("Runner provided invalid canonical fixture host-key fingerprint")
        }
        return value
    }

    private suspend fun createFixtureCredential(secretStore: AndroidKeystoreSecretStore) {
        ensureSecretAbsent(secretStore)
        val material = SecretMaterial.fromBytes(FIXTURE_PASSWORD.toByteArray(StandardCharsets.UTF_8))
        try {
            assertEquals(
                SecretCreateResult.Created,
                secretStore.create(SECRET_ID, material),
            )
        } finally {
            material.close()
        }
    }

    private fun restoreConnectivityControls(controls: ConnectivityControls) {
        runShellCommand(
            "cmd connectivity airplane-mode " + if (controls.airplane == "1") "enable" else "disable",
        )
        runShellCommand("svc wifi " + if (controls.wifi == "1") "enable" else "disable")
    }

    private fun runShellCommand(command: String) {
        val descriptor = InstrumentationRegistry.getInstrumentation()
            .uiAutomation
            .executeShellCommand(command)
        ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
            val buffer = ByteArray(1024)
            while (input.read(buffer) >= 0) {
                // Drain shell output so command completion is observed before the next acceptance step.
            }
        }
    }

    private fun awaitNoPhysicalDefaultNetwork(connectivityManager: ConnectivityManager) {
        val deadlineNanos = System.nanoTime() + NETWORK_PRECONDITION_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            if (connectivityManager.activeNetwork == null) {
                return
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Device still has an active default Network. Disable VPN/Ethernet/hotspot before this gate.",
        )
    }

    private fun awaitValidatedDefaultNetwork(connectivityManager: ConnectivityManager) {
        val deadlineNanos = System.nanoTime() + NETWORK_RESTORATION_TIMEOUT_MILLIS * 1_000_000L
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

    private fun awaitObservationAfter(
        afterGeneration: Long,
        expectedState: ConnectivityState,
    ): ConnectivityObservation {
        val deadlineNanos = System.nanoTime() + CONNECTIVITY_OBSERVATION_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val observation = application.operationRuntimeCoordinator.connectivitySnapshot()
            if (observation.generation > afterGeneration && observation.state == expectedState) {
                return observation
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for a newer production $expectedState observation; latest=" +
                application.operationRuntimeCoordinator.connectivitySnapshot(),
        )
    }

    private fun awaitStableOnlineObservationAfter(afterGeneration: Long): ConnectivityObservation {
        val deadlineNanos = System.nanoTime() + CONNECTIVITY_OBSERVATION_TIMEOUT_MILLIS * 1_000_000L
        var candidateGeneration: Long? = null
        var stableSinceNanos = 0L

        while (System.nanoTime() < deadlineNanos) {
            val now = System.nanoTime()
            val observation = application.operationRuntimeCoordinator.connectivitySnapshot()
            if (
                observation.generation > afterGeneration &&
                observation.state == ConnectivityState.ONLINE
            ) {
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
            "Timed out waiting for a stable newer production ONLINE observation; latest=" +
                application.operationRuntimeCoordinator.connectivitySnapshot(),
        )
    }

    private data class ConnectivityControls(
        val airplane: String,
        val wifi: String,
    )

    private suspend fun cleanupFixture(
        database: VelumDatabase,
        journal: RoomOperationJournal,
        serverRepository: RoomServerRepository,
        accessRepository: RoomServerAccessRepository,
        secretStore: AndroidKeystoreSecretStore,
    ) {
        val current = when (val result = journal.get(OPERATION_ID)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> null
            else -> throw AssertionError("Acceptance cleanup could not read Operation: ${result::class.java.simpleName}")
        }

        if (current != null) {
            val terminal = if (
                current.snapshot.status == OperationStatus.CANCELLED &&
                current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
            ) {
                current
            } else {
                val cleanupAt = laterThan(current.snapshot.updatedAt)
                val next = current.snapshot.copy(
                    status = OperationStatus.CANCELLED,
                    checkpoint = OperationCheckpoint(
                        phaseName = "PHASE4_6E_ACCEPTANCE_CLEANUP",
                        semantics = CheckpointSemantics.TERMINAL,
                        recordedAt = cleanupAt,
                    ),
                    updatedAt = cleanupAt,
                )
                journal.advance(OPERATION_ID, current.revision, next)
                    .requireOperationSuccess("terminalize acceptance Operation for exact cleanup")
            }

            database.withWriteTransaction {
                database.operationDao().deleteJournalForOperation(OPERATION_ID.value)
                check(
                    database.operationDao().deleteTerminalSnapshotCas(
                        operationId = OPERATION_ID.value,
                        expectedRevision = terminal.revision.value,
                    ) == 1,
                ) { "Acceptance cleanup lost exact terminal Operation row" }
            }
        }

        when (val accessDelete = accessRepository.delete(ACCESS_ID)) {
            is RepositoryResult.Success, RepositoryResult.NotFound -> Unit
            else -> throw AssertionError(
                "Acceptance cleanup could not delete exact ServerAccess: ${accessDelete::class.java.simpleName}",
            )
        }

        when (val serverCurrent = serverRepository.get(SERVER_ID)) {
            is RepositoryResult.Success -> when (
                val serverDelete = serverRepository.delete(SERVER_ID, serverCurrent.value.revision)
            ) {
                is RepositoryResult.Success -> Unit
                else -> throw AssertionError(
                    "Acceptance cleanup could not delete exact Server: ${serverDelete::class.java.simpleName}",
                )
            }
            RepositoryResult.NotFound -> Unit
            else -> throw AssertionError(
                "Acceptance cleanup could not read exact Server: ${serverCurrent::class.java.simpleName}",
            )
        }

        ensureSecretAbsent(secretStore)
    }

    private suspend fun ensureSecretAbsent(secretStore: AndroidKeystoreSecretStore) {
        when (val result = secretStore.delete(SECRET_ID)) {
            SecretDeleteResult.Deleted,
            SecretDeleteResult.AlreadyAbsent,
            -> Unit

            is SecretDeleteResult.StorageFailure -> throw AssertionError(
                "Acceptance SecretStore cleanup failed without exposing secret material: ${result.reason}",
            )
        }
    }

    private fun laterThan(value: Instant): Instant {
        val now = Instant.now()
        return if (now.isAfter(value)) now else value.plusNanos(1)
    }

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(label: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$label failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(label: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$label failed: ${this::class.java.simpleName}")
    }

    private companion object {
        val SERVER_ID = ServerId("phase4-6e-postdispatch-server")
        val ACCESS_ID = ServerAccessId("phase4-6e-postdispatch-access")
        val OPERATION_ID = OperationId("phase4-6e-postdispatch-operation")
        val SECRET_ID = SecretId("phase4-6e-test-credential")

        const val FIXTURE_USERNAME = "velum-phase46e"
        const val FIXTURE_PASSWORD = "VELUM-phase46e-test-only-password"
        const val FIXTURE_COMMAND = "phase46e-read-only-hang"

        const val ARG_ORIGINAL_AIRPLANE = "phase46e.originalAirplane"
        const val ARG_ORIGINAL_WIFI = "phase46e.originalWifi"
        const val ARG_FIXTURE_PORT = "phase46e.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase46e.fixtureFingerprint"

        const val NETWORK_PRECONDITION_TIMEOUT_MILLIS = 10_000L
        const val NETWORK_RESTORATION_TIMEOUT_MILLIS = 30_000L
        const val CONNECTIVITY_OBSERVATION_TIMEOUT_MILLIS = 30_000L
        const val COMMAND_RESULT_TIMEOUT_MILLIS = 20_000L
        const val NETWORK_STABILITY_MILLIS = 1_500L
        const val NO_REPLAY_SETTLE_MILLIS = 1_000L
        const val POLL_INTERVAL_MILLIS = 50L

        val TEST_CONFIG = SshTransportConfig(
            tcpConnectTimeout = Duration.ofSeconds(10),
            handshakeAndAuthTimeout = Duration.ofSeconds(10),
            channelOpenTimeout = Duration.ofSeconds(10),
            commandExecutionTimeout = Duration.ofSeconds(60),
            stdoutCaptureLimitBytes = 4 * 1024,
            stderrCaptureLimitBytes = 4 * 1024,
        )
    }
}
