package com.velumtegra.xuimobile.integration

import android.content.Context
import android.net.ConnectivityManager
import androidx.room3.withWriteTransaction
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
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
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeAdmissionBridge
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBinding
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeTransportBridge
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6B real-device OFFLINE-before-connect acceptance.
 *
 * The PowerShell runner places the USB-connected device into a temporary no-default-network state
 * before this test starts. The test then routes a real Android default-network observation into the
 * production process-scoped OperationRuntimeCoordinator and drives the same production admission +
 * transport bridge used by ExactOperationShortService.
 *
 * The exact acceptance ServerAccess deliberately references an absent SecretId. That missing secret
 * is a poison control: if transport incorrectly crosses the OFFLINE gate and reaches SSH credential
 * resolution, the result cannot be WaitForNetwork. PASS therefore requires the production transport
 * boundary to stop at OFFLINE scheduling evidence before any SSH/credential attempt is authorized.
 * No remote command is available in this slice and OperationJournal must remain byte-for-byte equal.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6BOfflineBeforeConnectInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun realOfflineObservationBlocksTransportBeforeCredentialPathAndLeavesJournalUntouched() = runBlocking {
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
        val transportBridge = ExactOperationHostRuntimeTransportBridge(
            application.operationRuntimeCoordinator,
        )

        var observerRegistered = false
        var runtimeBinding: ExactOperationHostRuntimeBinding? = null

        try {
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            ensureSecretAbsent(secretStore)
            awaitNoPhysicalDefaultNetwork(connectivityManager)

            val startedAt = Instant.now()
            val server = Server(
                id = SERVER_ID,
                displayName = "Phase 4.6B offline-before-connect acceptance",
                createdAt = startedAt,
            )
            val access = ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", 1),
                username = "phase46b",
                auth = SshAuthRef.Password(MISSING_SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            )
            val initial = OperationSnapshot(
                operationId = OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6B_OFFLINE_BEFORE_CONNECT",
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

            val offlineObservation = awaitOfflineObservationAfter(baselineObservation.generation)
            assertEquals(ConnectivityState.OFFLINE, offlineObservation.state)
            assertNull(
                "Runner promised no physical default network; a remaining Network invalidates this gate",
                connectivityManager.activeNetwork,
            )

            val bind = admissionBridge.bind(OPERATION_ID)
            assertTrue(
                "Exact production admission must bind the acceptance operation, got ${bind::class.java.simpleName}",
                bind is ExactOperationHostRuntimeBindResult.Bound,
            )
            val boundRuntime = (bind as ExactOperationHostRuntimeBindResult.Bound).binding
            runtimeBinding = boundRuntime

            val transport = transportBridge.begin(
                binding = boundRuntime,
                observation = offlineObservation,
                budget = RetryBudget(maxAttempts = 2),
            )
            assertEquals(
                "OFFLINE must stop before exact access/credential/SSH work",
                ExactOperationHostTransportResult.WaitForNetwork,
                transport,
            )
            assertEquals(
                created,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable state after OFFLINE transport gate"),
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
                        database.close()
                    }
                }
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
            "Device still has an active default Network. Use USB ADB; disable Ethernet/VPN/hotspot if present.",
        )
    }

    private fun awaitOfflineObservationAfter(afterGeneration: Long): ConnectivityObservation {
        val deadlineNanos = System.nanoTime() + CONNECTIVITY_OBSERVATION_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val observation = application.operationRuntimeCoordinator.connectivitySnapshot()
            if (
                observation.generation > afterGeneration &&
                observation.state == ConnectivityState.OFFLINE
            ) {
                return observation
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for a newer production OFFLINE observation; latest=" +
                application.operationRuntimeCoordinator.connectivitySnapshot(),
        )
    }

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
                        phaseName = "PHASE4_6B_ACCEPTANCE_CLEANUP",
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
        when (val result = secretStore.delete(MISSING_SECRET_ID)) {
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
        val SERVER_ID = ServerId("phase4-6b-offline-server")
        val ACCESS_ID = ServerAccessId("phase4-6b-offline-access")
        val OPERATION_ID = OperationId("phase4-6b-offline-operation")
        val MISSING_SECRET_ID = SecretId("phase4-6b-intentionally-missing-secret")

        const val NETWORK_PRECONDITION_TIMEOUT_MILLIS = 8_000L
        const val CONNECTIVITY_OBSERVATION_TIMEOUT_MILLIS = 8_000L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
