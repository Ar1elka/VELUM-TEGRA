package com.velumtegra.xuimobile.integration

import android.content.Context
import android.content.Intent
import androidx.room3.withWriteTransaction
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.MainActivity
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
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleEvidence
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleState
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import com.velumtegra.xuimobile.runtime.ExactOperationShortService
import com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6A real-device smoke gate for the production Android execution host.
 *
 * This test deliberately uses the production Application graph, production Room database,
 * production visible-user launcher and production ExactOperationShortService. The fixture points at
 * one exact acceptance-only ServerAccess whose SecretId is guaranteed absent, so no real remote
 * command can execute and no credential is supplied to the test.
 *
 * Connectivity is intentionally not a PASS precondition in 4.6A. Depending on real callback timing,
 * the bounded transport sequence may stop at WAIT_FOR_NETWORK or at the missing-secret transport
 * failure. Both are safe local outcomes. What this gate proves is that Android accepts the visible
 * start, the host reaches deterministic non-failure teardown, durable OperationJournal truth is not
 * rewritten, and a second exact start can acquire a fresh lifecycle generation instead of being
 * blocked by leaked runtime ownership.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6AExactHostLifecycleInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun visibleHostSurvivesActivityExitLeavesJournalUntouchedAndCanBeReacquired() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val secretStore = AndroidKeystoreSecretStore(context)

        try {
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            ensureSecretAbsent(secretStore)

            val startedAt = Instant.now()
            val server = Server(
                id = SERVER_ID,
                displayName = "Phase 4.6A exact-host acceptance",
                createdAt = startedAt,
            )
            val access = ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", 1),
                username = "phase46a",
                auth = SshAuthRef.Password(MISSING_SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:phase46a-local-fixture"),
            )
            val initial = OperationSnapshot(
                operationId = OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6A_READ_ONLY_HOST_SMOKE",
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            )

            serverRepository.create(server).requireRepositorySuccess("create acceptance Server")
            credentialWriter.createServerAccess(access).requireRepositorySuccess("create acceptance ServerAccess")
            val created = journal.create(initial).requireOperationSuccess("create acceptance Operation")

            val baselineGeneration = application.operationHostLifecycleRegistry.latest()?.generation ?: 0L
            val firstStart = startFromVisibleActivity()
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, firstStart)
            val firstTerminal = awaitTerminalEvidence(afterGeneration = baselineGeneration)
            assertEquals(OPERATION_ID, firstTerminal.operationId)
            assertEquals(ExactOperationHostLifecycleState.STOPPED, firstTerminal.state)
            assertEquals(
                created,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable state after first host"),
            )

            // A second exact visible start must obtain a fresh host generation. If the first host
            // leaked its runtime lease or teardown ownership, this cannot converge as a new host.
            val secondStart = startFromVisibleActivity()
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, secondStart)
            val secondTerminal = awaitTerminalEvidence(afterGeneration = firstTerminal.generation)
            assertEquals(OPERATION_ID, secondTerminal.operationId)
            assertEquals(ExactOperationHostLifecycleState.STOPPED, secondTerminal.state)
            assertTrue(
                "Second exact host must use a newer lifecycle generation",
                secondTerminal.generation > firstTerminal.generation,
            )
            assertEquals(
                created,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable state after second host"),
            )
        } finally {
            try {
                stopAcceptanceHostIfRunning()
            } finally {
                try {
                    cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
                } finally {
                    database.close()
                }
            }
        }
    }

    private fun startFromVisibleActivity(): ExactOperationHostStartResult {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        return try {
            var result: ExactOperationHostStartResult? = null
            scenario.onActivity { activity ->
                result = VisibleExactOperationHostLauncher(activity).start(OPERATION_ID)
            }
            requireNotNull(result) { "Visible host launcher did not return a start result" }
        } finally {
            // Activity lifetime is presentation only. Closing it immediately after Android accepts
            // the request is part of this gate: the Service/runtime must not be owned by the screen.
            scenario.close()
        }
    }

    private fun awaitTerminalEvidence(afterGeneration: Long): ExactOperationHostLifecycleEvidence {
        val deadlineNanos = System.nanoTime() + HOST_TERMINAL_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val evidence = application.operationHostLifecycleRegistry.latest()
            if (
                evidence != null &&
                evidence.operationId == OPERATION_ID &&
                evidence.generation > afterGeneration &&
                evidence.state.isTerminal
            ) {
                return evidence
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for terminal exact-host lifecycle evidence after generation $afterGeneration; " +
                "latest=${application.operationHostLifecycleRegistry.latest()}",
        )
    }

    private fun stopAcceptanceHostIfRunning() {
        val latest = application.operationHostLifecycleRegistry.latest()
        if (
            latest != null &&
            latest.operationId == OPERATION_ID &&
            !latest.state.isTerminal
        ) {
            context.stopService(Intent(context, ExactOperationShortService::class.java))
            val deadlineNanos = System.nanoTime() + CLEANUP_STOP_TIMEOUT_MILLIS * 1_000_000L
            while (System.nanoTime() < deadlineNanos) {
                val current = application.operationHostLifecycleRegistry.latest()
                if (
                    current != null &&
                    current.operationId == OPERATION_ID &&
                    current.state.isTerminal
                ) {
                    return
                }
                Thread.sleep(POLL_INTERVAL_MILLIS)
            }
            throw AssertionError(
                "Acceptance cleanup could not stop the exact production host before fixture deletion",
            )
        }
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
                        phaseName = "PHASE4_6A_ACCEPTANCE_CLEANUP",
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
        val SERVER_ID = ServerId("phase4-6a-host-smoke-server")
        val ACCESS_ID = ServerAccessId("phase4-6a-host-smoke-access")
        val OPERATION_ID = OperationId("phase4-6a-host-smoke-operation")
        val MISSING_SECRET_ID = SecretId("phase4-6a-intentionally-missing-secret")

        const val HOST_TERMINAL_TIMEOUT_MILLIS = 20_000L
        const val CLEANUP_STOP_TIMEOUT_MILLIS = 5_000L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
