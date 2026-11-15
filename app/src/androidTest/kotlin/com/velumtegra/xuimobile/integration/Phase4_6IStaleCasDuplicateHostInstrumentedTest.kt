package com.velumtegra.xuimobile.integration

import android.content.Context
import android.content.Intent
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
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
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
import com.velumtegra.xuimobile.core.runtime.StaleCasConflict
import com.velumtegra.xuimobile.core.runtime.StaleCasReloadResult
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleEvidence
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleState
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import com.velumtegra.xuimobile.runtime.ExactOperationShortService
import com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6I real-device stale-CAS + duplicate-host acceptance.
 *
 * Part 1 uses the real Room OperationJournal. A newer writer wins revision 1, then a writer holding
 * revision 0 attempts an otherwise-valid advance. Room must return StaleRevision, and the production
 * OperationRuntimeCoordinator may only reload the newest durable truth for re-plan; it must not
 * repeat the stale advance.
 *
 * Part 2 sends two real visible-user start requests for the same exact OperationId to the production
 * ExactOperationShortService. A host-side USB adb-reverse TCP stall keeps the first production JSch
 * connect in flight. The runner signals this test only after that socket is accepted. At that point
 * both Android start requests have been queued for one Service lifetime; lifecycle evidence must
 * still show one generation. The host witness separately requires exactly one TCP connection, so a
 * duplicate OperationRuntime/transport owner cannot hide behind idempotent UI evidence.
 *
 * No SSH server authenticates and no remote command exists in this gate.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6IStaleCasDuplicateHostInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun staleWriterReloadsNewestTruthAndDuplicateStartsKeepOneRuntimeHost() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val firstAcceptedSignal = File(context.filesDir, FIRST_ACCEPTED_SIGNAL_NAME)
        var scenario: ActivityScenario<MainActivity>? = null

        try {
            firstAcceptedSignal.delete()
            stopAcceptanceHostIfRunning()
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            createDummyCredential(secretStore)

            val startedAt = Instant.now()
            serverRepository.create(
                Server(
                    id = SERVER_ID,
                    displayName = "Phase 4.6I stale CAS + duplicate host acceptance",
                    createdAt = startedAt,
                ),
            ).requireRepositorySuccess("create acceptance Server")
            credentialWriter.createServerAccess(
                ServerAccess(
                    id = ACCESS_ID,
                    serverId = SERVER_ID,
                    endpoint = SshEndpoint("127.0.0.1", readStallPort()),
                    username = "phase46i",
                    auth = SshAuthRef.Password(SECRET_ID),
                    pinnedHostKey = HostKeyFingerprint(DUMMY_HOST_PIN),
                ),
            ).requireRepositorySuccess("create acceptance ServerAccess")

            val initial = OperationSnapshot(
                operationId = OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6I_STALE_BASE",
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            )
            val created = journal.create(initial).requireOperationSuccess("create acceptance Operation")

            // A newer durable writer wins first.
            val winnerAt = laterThan(created.snapshot.updatedAt)
            val winnerSnapshot = created.snapshot.copy(
                checkpoint = OperationCheckpoint(
                    phaseName = WINNER_PHASE,
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = winnerAt,
                ),
                updatedAt = winnerAt,
            )
            val winner = journal.advance(OPERATION_ID, created.revision, winnerSnapshot)
                .requireOperationSuccess("commit newer recovery winner")

            // The stale writer still owns revision 0. Its payload is deliberately otherwise valid
            // and newer in wall-clock time so the only rejection reason is stale CAS ownership.
            val staleAt = laterThan(winner.snapshot.updatedAt)
            val staleSnapshot = created.snapshot.copy(
                checkpoint = OperationCheckpoint(
                    phaseName = STALE_PHASE,
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = staleAt,
                ),
                updatedAt = staleAt,
            )
            val stale = journal.advance(OPERATION_ID, created.revision, staleSnapshot)
                as? OperationJournalResult.StaleRevision
                ?: throw AssertionError("Old revision writer did not receive StaleRevision")
            assertEquals(created.revision, stale.expected)
            assertEquals(winner.revision, stale.actual)

            val conflict = requireNotNull(
                StaleCasConflict.from(
                    operationId = OPERATION_ID,
                    target = created.snapshot.target,
                    attemptedExpectedRevision = created.revision,
                    stale = stale,
                ),
            ) { "Valid Room StaleRevision did not produce an exact stale-CAS conflict" }

            val reloaded = application.operationRuntimeCoordinator.reloadAfterStaleCas(conflict)
                as? StaleCasReloadResult.ReplanRequired
                ?: throw AssertionError("Production coordinator did not reload stale CAS as re-plan only")
            assertEquals(winner, reloaded.context.current)
            assertEquals(conflict, reloaded.context.staleConflict)
            assertEquals(
                winner,
                journal.get(OPERATION_ID).requireOperationSuccess("read winner after stale CAS reload"),
            )
            val historyAfterStale = journal.history(OPERATION_ID)
                .requireOperationSuccess("read history after stale CAS reload")
            assertEquals(2, historyAfterStale.size)
            assertEquals(WINNER_PHASE, historyAfterStale.last().checkpoint.phaseName)
            assertFalse(
                "Stale writer phase must never enter durable history",
                historyAfterStale.any { it.checkpoint.phaseName == STALE_PHASE },
            )

            // Queue two real visible-user Android Service starts back-to-back. Android assigns two
            // start requests, but ExactOperationShortService must bind only one lifecycle/runtime.
            val baselineGeneration = application.operationHostLifecycleRegistry.latest()?.generation ?: 0L
            val activeScenario = ActivityScenario.launch(MainActivity::class.java)
            scenario = activeScenario
            var firstStart: ExactOperationHostStartResult? = null
            var duplicateStart: ExactOperationHostStartResult? = null
            activeScenario.onActivity { activity ->
                val launcher = VisibleExactOperationHostLauncher(activity)
                firstStart = launcher.start(OPERATION_ID)
                duplicateStart = launcher.start(OPERATION_ID)
            }
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, firstStart)
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, duplicateStart)

            val foreground = awaitForegroundEvidence(afterGeneration = baselineGeneration)
            assertEquals(OPERATION_ID, foreground.operationId)
            assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, foreground.state)

            // The runner creates this app-private signal only after its host listener has accepted
            // the first production TCP socket. Holding that socket prevents normal retry/teardown
            // from confusing duplicate-start evidence.
            awaitRunnerFirstConnectSignal(firstAcceptedSignal)
            Thread.sleep(DUPLICATE_DELIVERY_SETTLE_MILLIS)

            val afterDuplicate = application.operationHostLifecycleRegistry.latest()
                ?: throw AssertionError("Production host lifecycle evidence disappeared")
            assertEquals(
                "Duplicate start must not create a second host generation",
                foreground.generation,
                afterDuplicate.generation,
            )
            assertEquals(OPERATION_ID, afterDuplicate.operationId)
            assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, afterDuplicate.state)
            assertEquals(
                winner,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable state after duplicate starts"),
            )

            // Stop only as acceptance cleanup while the first TCP connect is still held. This must
            // cancel the single runtime owner rather than allowing a normal transport retry.
            assertTrue(
                "Acceptance cleanup expected the production Service to be running",
                context.stopService(Intent(context, ExactOperationShortService::class.java)),
            )
            val stopped = awaitTerminalEvidence(foreground.generation)
            assertEquals(ExactOperationHostLifecycleState.STOPPED, stopped.state)
            assertEquals(foreground.generation, stopped.generation)
            assertEquals(
                winner,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable state after host cleanup"),
            )
        } finally {
            try {
                scenario?.close()
            } finally {
                try {
                    stopAcceptanceHostIfRunning()
                } finally {
                    try {
                        cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
                    } finally {
                        try {
                            database.close()
                        } finally {
                            firstAcceptedSignal.delete()
                        }
                    }
                }
            }
        }
    }

    private fun readStallPort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_STALL_PORT)
            ?: throw AssertionError("Runner did not provide $ARG_STALL_PORT")
        return raw.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw AssertionError("Runner provided invalid stall port")
    }

    private fun awaitRunnerFirstConnectSignal(signal: File) {
        val deadlineNanos = System.nanoTime() + FIRST_CONNECT_SIGNAL_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            if (signal.isFile) return
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Runner never confirmed the first production TCP connect")
    }

    private fun awaitForegroundEvidence(afterGeneration: Long): ExactOperationHostLifecycleEvidence {
        val deadlineNanos = System.nanoTime() + HOST_STATE_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val evidence = application.operationHostLifecycleRegistry.latest()
            if (
                evidence != null &&
                evidence.operationId == OPERATION_ID &&
                evidence.generation > afterGeneration &&
                evidence.state == ExactOperationHostLifecycleState.FOREGROUND_ACTIVE
            ) {
                return evidence
            }
            if (
                evidence != null &&
                evidence.operationId == OPERATION_ID &&
                evidence.generation > afterGeneration &&
                evidence.state.isTerminal
            ) {
                throw AssertionError("Exact host terminated before duplicate-host witness: $evidence")
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for one foreground exact-host generation; latest=" +
                application.operationHostLifecycleRegistry.latest(),
        )
    }

    private fun awaitTerminalEvidence(generation: Long): ExactOperationHostLifecycleEvidence {
        val deadlineNanos = System.nanoTime() + HOST_STATE_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val evidence = application.operationHostLifecycleRegistry.latest()
            if (
                evidence != null &&
                evidence.operationId == OPERATION_ID &&
                evidence.generation == generation &&
                evidence.state.isTerminal
            ) {
                return evidence
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for exact host generation $generation to stop; latest=" +
                application.operationHostLifecycleRegistry.latest(),
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
            awaitTerminalEvidence(latest.generation)
        }
    }

    private suspend fun createDummyCredential(secretStore: AndroidKeystoreSecretStore) {
        ensureSecretAbsent(secretStore)
        val material = SecretMaterial.fromBytes(DUMMY_PASSWORD.toByteArray(StandardCharsets.UTF_8))
        try {
            assertEquals(SecretCreateResult.Created, secretStore.create(SECRET_ID, material))
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
                        phaseName = "PHASE4_6I_ACCEPTANCE_CLEANUP",
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
        val SERVER_ID = ServerId("phase4-6i-stale-cas-duplicate-host-server")
        val ACCESS_ID = ServerAccessId("phase4-6i-stale-cas-duplicate-host-access")
        val OPERATION_ID = OperationId("phase4-6i-stale-cas-duplicate-host-operation")
        val SECRET_ID = SecretId("phase4-6i-stale-cas-duplicate-host-secret")

        const val ARG_STALL_PORT = "phase46iStallPort"
        const val FIRST_ACCEPTED_SIGNAL_NAME = "phase46i-first-accepted.signal"
        const val WINNER_PHASE = "PHASE4_6I_RECOVERED_WINNER"
        const val STALE_PHASE = "PHASE4_6I_STALE_WRITER_MUST_NOT_COMMIT"
        const val DUMMY_PASSWORD = "phase46i-dummy-password"
        const val DUMMY_HOST_PIN = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        const val FIRST_CONNECT_SIGNAL_TIMEOUT_MILLIS = 20_000L
        const val HOST_STATE_TIMEOUT_MILLIS = 10_000L
        const val DUPLICATE_DELIVERY_SETTLE_MILLIS = 300L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
