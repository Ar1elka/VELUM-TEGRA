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
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
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
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.runtime.RetryDeniedReason
import com.velumtegra.xuimobile.core.runtime.RetryFailureCategory
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeAdmissionBridge
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBinding
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeTransportBridge
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequence
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportSequenceResult
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6F real-device fast-flap de-duplication acceptance.
 *
 * The host-side PowerShell fixture exposes one USB adb-reverse TCP endpoint. The first production
 * JSch connection is held open while the runner forces a real Android ONLINE -> OFFLINE -> ONLINE
 * flap. This test publishes app-private marker files only after the production
 * AndroidDefaultNetworkObserver has delivered the newer OFFLINE and then a stable newer ONLINE
 * generation. The runner therefore cannot release the first connection early.
 *
 * ExactOperationHostTransportSequence is intentionally used instead of issuing parallel direct
 * reconnect calls: it is the production bounded host scheduler that owns cross-generation
 * supersession. After the first stale connect is released, it may start only the latest observed
 * generation. RetryBudget(maxAttempts = 1) removes same-generation retry noise from this gate, so
 * the host fixture can require exactly two TCP connections total and max concurrency == 1.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6FFastNetworkFlapInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun inFlightReconnectAcrossRealOfflineOnlineFlapCoalescesToLatestGeneration() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val connectivityManager = requireNotNull(
            context.getSystemService(ConnectivityManager::class.java),
        ) { "ConnectivityManager is unavailable" }

        val admissionBridge = ExactOperationHostRuntimeAdmissionBridge(
            coordinator = application.operationRuntimeCoordinator,
            previousExitProvenance = application.exitInfoAdapter::previousExitProvenance,
        )
        val transportSequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(application.operationRuntimeCoordinator),
        )

        val originalControls = readOriginalConnectivityControls()
        val stallPort = readStallPort()
        val offlineMarker = File(context.filesDir, OFFLINE_MARKER_NAME)
        val onlineMarker = File(context.filesDir, ONLINE_MARKER_NAME)
        var observerRegistered = false
        var runtimeBinding: ExactOperationHostRuntimeBinding? = null

        try {
            offlineMarker.delete()
            onlineMarker.delete()
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            createDummyCredential(secretStore)
            awaitValidatedDefaultNetwork(connectivityManager)

            val startedAt = Instant.now()
            val server = Server(
                id = SERVER_ID,
                displayName = "Phase 4.6F fast network flap acceptance",
                createdAt = startedAt,
            )
            val access = ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", stallPort),
                username = "phase46f",
                auth = SshAuthRef.Password(SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            )
            val initial = OperationSnapshot(
                operationId = OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6F_FAST_NETWORK_FLAP",
                    semantics = CheckpointSemantics.READ_ONLY,
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

            val bind = admissionBridge.bind(OPERATION_ID)
            assertTrue(
                "Exact production admission must bind the acceptance operation, got ${bind::class.java.simpleName}",
                bind is ExactOperationHostRuntimeBindResult.Bound,
            )
            val boundRuntime = (bind as ExactOperationHostRuntimeBindResult.Bound).binding
            runtimeBinding = boundRuntime

            val sequence = async(Dispatchers.IO) {
                transportSequence.run(
                    runtimeBinding = boundRuntime,
                    budget = RetryBudget(maxAttempts = 1),
                    maxConnectivityGenerations = 2,
                )
            }

            // Runner waits until its host listener has accepted the first production TCP socket,
            // then removes Android's default network. This observation proves the real flap reached
            // the shared production coordinator while that first connect was still unresolved.
            val offline = awaitObservationAfter(
                afterGeneration = initialOnline.generation,
                expectedState = ConnectivityState.OFFLINE,
            )
            awaitNoPhysicalDefaultNetwork(connectivityManager)
            writeMarker(offlineMarker, offline)

            // Runner restores the exact original controls only after it can read the OFFLINE marker.
            // Keep waiting while the first TCP connect remains held by the host fixture.
            awaitValidatedDefaultNetwork(connectivityManager)
            val restoredOnline = awaitStableOnlineObservationAfter(offline.generation)
            assertTrue(
                "Restored ONLINE generation must supersede the real OFFLINE flap generation",
                restoredOnline.generation > offline.generation,
            )
            writeMarker(onlineMarker, restoredOnline)

            // Runner releases the first TCP connection only after it can read the ONLINE marker.
            // The stale first generation must then collapse to exactly one latest-generation chain.
            val sequenceResult = withTimeout(SEQUENCE_RESULT_TIMEOUT_MILLIS) {
                sequence.await()
            }
            val ended = sequenceResult as? ExactOperationHostTransportSequenceResult.Ended
                ?: throw AssertionError(
                    "Fast-flap transport sequence must end as a typed transport outcome; got " +
                        sequenceResult::class.java.simpleName,
                )
            val boundedFailure = ended.transportResult as? ExactOperationHostTransportResult.Failed
                ?: throw AssertionError(
                    "Latest generation must perform one no-retry transport attempt; got " +
                        ended.transportResult::class.java.simpleName,
                )
            assertEquals(RetryDeniedReason.ATTEMPT_LIMIT_REACHED, boundedFailure.retryDecision.reason)
            assertEquals(RetryFailureCategory.TRANSIENT_TRANSPORT, boundedFailure.retryDecision.failureCategory)

            val finalObservation = application.operationRuntimeCoordinator.connectivitySnapshot()
            assertEquals(
                "The sequence must finish on the same latest ONLINE generation acknowledged to the runner",
                restoredOnline.generation,
                finalObservation.generation,
            )
            assertEquals(ConnectivityState.ONLINE, finalObservation.state)
            assertTrue(
                "Real ONLINE -> OFFLINE -> ONLINE must advance at least two scheduling generations",
                finalObservation.generation >= initialOnline.generation + 2L,
            )
            assertEquals(
                created,
                journal.get(OPERATION_ID).requireOperationSuccess(
                    "read durable state after fast-flap reconnect coalescing",
                ),
            )
        } finally {
            try {
                runtimeBinding?.let { binding ->
                    assertEquals(
                        OperationRuntimeReleaseResult.RELEASED,
                        admissionBridge.release(binding),
                    )
                }
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
                            offlineMarker.delete()
                            onlineMarker.delete()
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

    private fun readStallPort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_STALL_PORT)
            ?: throw AssertionError("Runner did not provide $ARG_STALL_PORT")
        return raw.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw AssertionError("Runner provided invalid stall port")
    }

    private fun writeMarker(file: File, observation: ConnectivityObservation) {
        file.writeText(
            "generation=${observation.generation}\nstate=${observation.state.name}\n",
            StandardCharsets.UTF_8,
        )
    }

    private suspend fun createDummyCredential(secretStore: AndroidKeystoreSecretStore) {
        ensureSecretAbsent(secretStore)
        val material = SecretMaterial.fromBytes(DUMMY_PASSWORD.toByteArray(StandardCharsets.UTF_8))
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
                        phaseName = "PHASE4_6F_ACCEPTANCE_CLEANUP",
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
        val SERVER_ID = ServerId("phase4-6f-fast-flap-server")
        val ACCESS_ID = ServerAccessId("phase4-6f-fast-flap-access")
        val OPERATION_ID = OperationId("phase4-6f-fast-flap-operation")
        val SECRET_ID = SecretId("phase4-6f-dummy-credential")

        const val DUMMY_PASSWORD = "phase4-6f-not-a-real-credential"

        const val ARG_ORIGINAL_AIRPLANE = "phase46f.originalAirplane"
        const val ARG_ORIGINAL_WIFI = "phase46f.originalWifi"
        const val ARG_STALL_PORT = "phase46f.stallPort"

        const val OFFLINE_MARKER_NAME = "phase46f-offline.marker"
        const val ONLINE_MARKER_NAME = "phase46f-online.marker"

        const val NETWORK_PRECONDITION_TIMEOUT_MILLIS = 10_000L
        const val NETWORK_RESTORATION_TIMEOUT_MILLIS = 30_000L
        const val CONNECTIVITY_OBSERVATION_TIMEOUT_MILLIS = 30_000L
        const val SEQUENCE_RESULT_TIMEOUT_MILLIS = 30_000L
        const val NETWORK_STABILITY_MILLIS = 1_500L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
