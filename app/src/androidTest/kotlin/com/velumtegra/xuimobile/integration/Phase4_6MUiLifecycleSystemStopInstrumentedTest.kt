package com.velumtegra.xuimobile.integration

import android.content.Context
import android.content.Intent
import androidx.lifecycle.Lifecycle
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
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
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
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6M real-device UI lifecycle + external Service-stop authority acceptance.
 *
 * One exact production shortService is kept alive at a host-local USB adb-reverse TCP stall while
 * MainActivity is recreated, moved to background CREATED state and returned to RESUMED. None of
 * those presentation transitions may create a replacement host/runtime or mutate durable truth.
 *
 * After both UI lifecycle transitions are proven against the same lifecycle generation, the host
 * runner stops the real non-exported Service through Android ActivityManager from the debuggable
 * app UID. The Service must converge through onDestroy/cleanup while OperationJournal remains the
 * authoritative, byte-equivalent durable snapshot. No remote command or SSH authentication exists.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6MUiLifecycleSystemStopInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun activityRecreationBackgroundForegroundAndExternalServiceStopKeepOneRuntimeAndJournalAuthoritative() =
        runBlocking {
            val database = VelumDatabaseFactory.open(context)
            val journal = RoomOperationJournal(database)
            val serverRepository = RoomServerRepository(database)
            val accessRepository = RoomServerAccessRepository(database)
            val credentialWriter = RoomCredentialReferenceWriter(database)
            val secretStore = AndroidKeystoreSecretStore(context)
            val hostAcceptedSignal = File(context.filesDir, HOST_ACCEPTED_SIGNAL_NAME)
            val lifecycleReadyMarker = File(context.filesDir, LIFECYCLE_READY_MARKER_NAME)
            var scenario: ActivityScenario<MainActivity>? = null

            try {
                hostAcceptedSignal.delete()
                lifecycleReadyMarker.delete()
                stopAcceptanceHostIfRunning()
                cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
                createDummyCredential(secretStore)

                val startedAt = Instant.now()
                serverRepository.create(
                    Server(
                        id = SERVER_ID,
                        displayName = "Phase 4.6M UI lifecycle/system stop acceptance",
                        createdAt = startedAt,
                    ),
                ).requireRepositorySuccess("create acceptance Server")
                credentialWriter.createServerAccess(
                    ServerAccess(
                        id = ACCESS_ID,
                        serverId = SERVER_ID,
                        endpoint = SshEndpoint("127.0.0.1", readStallPort()),
                        username = "phase46m",
                        auth = SshAuthRef.Password(SECRET_ID),
                        pinnedHostKey = HostKeyFingerprint(DUMMY_HOST_PIN),
                    ),
                ).requireRepositorySuccess("create acceptance ServerAccess")

                val initial = OperationSnapshot(
                    operationId = OPERATION_ID,
                    type = OperationType.INSTALL,
                    target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint(
                        phaseName = ACTIVE_READ_ONLY_PHASE,
                        semantics = CheckpointSemantics.READ_ONLY,
                        recordedAt = startedAt,
                    ),
                    startedAt = startedAt,
                    updatedAt = startedAt,
                )
                val durableBefore = journal.create(initial)
                    .requireOperationSuccess("create acceptance Operation")

                val activeScenario = ActivityScenario.launch(MainActivity::class.java)
                scenario = activeScenario
                val baselineGeneration = application.operationHostLifecycleRegistry.latest()?.generation ?: 0L
                var startResult: ExactOperationHostStartResult? = null
                activeScenario.onActivity { activity ->
                    startResult = VisibleExactOperationHostLauncher(activity).start(OPERATION_ID)
                }
                assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, startResult)

                val foreground = awaitForegroundEvidence(afterGeneration = baselineGeneration)
                awaitRunnerSignal(hostAcceptedSignal, "first production TCP/SSH connect")
                assertDurableUnchanged(journal, durableBefore, "after initial foreground host")

                // Real Activity destruction/recreation while the production Service/runtime is live.
                activeScenario.recreate()
                activeScenario.onActivity { /* wait until the replacement Activity reached RESUMED */ }
                assertSameForegroundGeneration(foreground.generation, "after Activity recreation")
                assertDurableUnchanged(journal, durableBefore, "after Activity recreation")

                // ActivityScenario CREATED maps to an Activity that has moved through onStop: UI is
                // backgrounded while the foreground Service remains the execution host.
                activeScenario.moveToState(Lifecycle.State.CREATED)
                Thread.sleep(UI_SETTLE_MILLIS)
                assertSameForegroundGeneration(foreground.generation, "while UI is backgrounded")
                assertDurableUnchanged(journal, durableBefore, "while UI is backgrounded")

                activeScenario.moveToState(Lifecycle.State.RESUMED)
                activeScenario.onActivity { /* explicit foreground synchronization point */ }
                Thread.sleep(UI_SETTLE_MILLIS)
                assertSameForegroundGeneration(foreground.generation, "after UI returns to foreground")
                assertDurableUnchanged(journal, durableBefore, "after UI returns to foreground")

                lifecycleReadyMarker.writeText(
                    "generation=${foreground.generation}\nstate=${ExactOperationHostLifecycleState.FOREGROUND_ACTIVE.name}\n",
                )

                // The host-side runner now invokes Android ActivityManager stop-service while this
                // instrumentation process remains alive. onDestroy must clean local ownership only.
                val stopped = awaitTerminalEvidence(foreground.generation)
                assertEquals(ExactOperationHostLifecycleState.STOPPED, stopped.state)
                assertDurableUnchanged(journal, durableBefore, "after external Service stop")

                Thread.sleep(NO_RESTART_GUARD_MILLIS)
                val latest = application.operationHostLifecycleRegistry.latest()
                assertEquals(OPERATION_ID, latest?.operationId)
                assertEquals(foreground.generation, latest?.generation)
                assertEquals(ExactOperationHostLifecycleState.STOPPED, latest?.state)
                assertDurableUnchanged(journal, durableBefore, "after post-stop no-restart guard")
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
                            hostAcceptedSignal.delete()
                            lifecycleReadyMarker.delete()
                            database.close()
                        }
                    }
                }
            }
        }

    private fun readStallPort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_STALL_PORT)
            ?: throw AssertionError("Missing instrumentation argument $ARG_STALL_PORT")
        val port = raw.toIntOrNull() ?: throw AssertionError("Invalid stall port: $raw")
        if (port !in 1..65535) throw AssertionError("Stall port out of range: $port")
        return port
    }

    private fun awaitRunnerSignal(signal: File, label: String) {
        val deadlineNanos = System.nanoTime() + RUNNER_SIGNAL_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            if (signal.isFile) return
            val latest = application.operationHostLifecycleRegistry.latest()
            if (latest != null && latest.operationId == OPERATION_ID && latest.state.isTerminal) {
                throw AssertionError("Host terminated before runner confirmed $label: $latest")
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Runner never confirmed $label")
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
                throw AssertionError("Exact host terminated before foreground witness: $evidence")
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for foreground host generation after $afterGeneration; latest=" +
                application.operationHostLifecycleRegistry.latest(),
        )
    }

    private fun assertSameForegroundGeneration(generation: Long, label: String) {
        val evidence = application.operationHostLifecycleRegistry.latest()
            ?: throw AssertionError("No lifecycle evidence $label")
        assertEquals("OperationId changed $label", OPERATION_ID, evidence.operationId)
        assertEquals("Lifecycle generation changed $label", generation, evidence.generation)
        assertEquals(
            "Host is not foreground-active $label",
            ExactOperationHostLifecycleState.FOREGROUND_ACTIVE,
            evidence.state,
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
            "Timed out waiting for externally stopped host generation $generation; latest=" +
                application.operationHostLifecycleRegistry.latest(),
        )
    }

    private suspend fun assertDurableUnchanged(
        journal: RoomOperationJournal,
        expected: VersionedOperationSnapshot,
        label: String,
    ) {
        assertEquals(
            label,
            expected,
            journal.get(OPERATION_ID).requireOperationSuccess("read durable truth $label"),
        )
    }

    private fun stopAcceptanceHostIfRunning() {
        val latest = application.operationHostLifecycleRegistry.latest()
        if (latest != null && latest.operationId == OPERATION_ID && !latest.state.isTerminal) {
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
                        phaseName = CLEANUP_PHASE,
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
        val SERVER_ID = ServerId("phase4-6m-ui-lifecycle-server")
        val ACCESS_ID = ServerAccessId("phase4-6m-ui-lifecycle-access")
        val OPERATION_ID = OperationId("phase4-6m-ui-lifecycle-operation")
        val SECRET_ID = SecretId("phase4-6m-ui-lifecycle-secret")

        const val ARG_STALL_PORT = "phase46mStallPort"
        const val HOST_ACCEPTED_SIGNAL_NAME = "phase46m-host-accepted.signal"
        const val LIFECYCLE_READY_MARKER_NAME = "phase46m-lifecycle-ready.marker"
        const val ACTIVE_READ_ONLY_PHASE = "PHASE4_6M_ACTIVE_READ_ONLY"
        const val CLEANUP_PHASE = "PHASE4_6M_ACCEPTANCE_CLEANUP"
        const val DUMMY_PASSWORD = "phase46m-dummy-password"
        const val DUMMY_HOST_PIN = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        const val RUNNER_SIGNAL_TIMEOUT_MILLIS = 20_000L
        const val HOST_STATE_TIMEOUT_MILLIS = 12_000L
        const val UI_SETTLE_MILLIS = 250L
        const val NO_RESTART_GUARD_MILLIS = 500L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
