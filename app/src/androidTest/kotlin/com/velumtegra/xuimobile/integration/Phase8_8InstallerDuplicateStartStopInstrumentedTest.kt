package com.velumtegra.xuimobile.integration

import android.content.Context
import android.content.Intent
import android.net.Uri
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
import com.velumtegra.xuimobile.core.domain.FreshInstallAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.FreshInstallVerificationResult
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.FreshInstallConflictState
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPreflightProof
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
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
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.runtime.CancellationClassificationPolicy
import com.velumtegra.xuimobile.core.runtime.CancellationDispatchEvidence
import com.velumtegra.xuimobile.core.runtime.CancellationDurableDisposition
import com.velumtegra.xuimobile.core.runtime.CancellationPlanInput
import com.velumtegra.xuimobile.core.runtime.CancellationResourceDisposition
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeEntryRegistrationResult
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleEvidence
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleState
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostUserStopRequest
import com.velumtegra.xuimobile.runtime.ExactOperationShortService
import com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 8.8 real-device exact user-Stop + cancellation acceptance.
 *
 * The same exact Installer OperationId is hosted twice against a host-local USB adb-reverse TCP stall. The
 * first generation uses a safe MUTATION_NOT_STARTED durable checkpoint plus a verified one-shot
 * Phase 8.7 fresh-install authorization. Its exact user Stop must
 * tear down only the current host and leave OperationJournal unchanged. The production cancellation
 * classifier must allow terminal cancellation for that proven pre-dispatch evidence.
 *
 * The fixture then advances only synthetic durable evidence to MUTATION_IN_FLIGHT; no remote mutation
 * is executed. The same OperationId starts a fresh host generation. Re-sending the old generation's
 * exact Stop request must be ignored, while the current generation's Stop must tear down the host
 * without rewriting durable mutation truth. Even deliberately stale BEFORE_MUTATION_DISPATCH caller
 * evidence must classify as REQUIRE_RECONCILIATION because the durable unsafe checkpoint wins.
 */
@RunWith(AndroidJUnit4::class)
class Phase8_8InstallerDuplicateStartStopInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactUserStopIsGenerationSafeAndCancellationNeverDowngradesDurableTruth() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val firstAcceptedSignal = File(context.filesDir, FIRST_ACCEPTED_SIGNAL_NAME)
        val secondAcceptedSignal = File(context.filesDir, SECOND_ACCEPTED_SIGNAL_NAME)
        var scenario: ActivityScenario<MainActivity>? = null

        try {
            firstAcceptedSignal.delete()
            secondAcceptedSignal.delete()
            stopAcceptanceHostIfRunning()
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            createDummyCredential(secretStore)

            val startedAt = Instant.now()
            serverRepository.create(
                Server(
                    id = SERVER_ID,
                    displayName = "Phase 8.8 exact user Stop acceptance",
                    createdAt = startedAt,
                ),
            ).requireRepositorySuccess("create acceptance Server")
            credentialWriter.createServerAccess(
                ServerAccess(
                    id = ACCESS_ID,
                    serverId = SERVER_ID,
                    endpoint = SshEndpoint("127.0.0.1", readStallPort()),
                    username = "phase88-stop",
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
                    phaseName = SAFE_PHASE,
                    semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            )
            val safeCurrent = journal.create(initial).requireOperationSuccess("create acceptance Operation")
            assertEquals(
                InstallerRuntimeEntryRegistrationResult.Registered,
                application.operationRuntimeCoordinator.registerInstallerFreshAuthorization(
                    verifiedFreshTarget(safeCurrent, startedAt.plusSeconds(1)),
                ),
            )

            val activeScenario = ActivityScenario.launch(MainActivity::class.java)
            scenario = activeScenario
            val firstGenerationBaseline = application.operationHostLifecycleRegistry.latest()?.generation ?: 0L
            var firstStart: ExactOperationHostStartResult? = null
            var duplicateStart: ExactOperationHostStartResult? = null
            activeScenario.onActivity { activity ->
                val launcher = VisibleExactOperationHostLauncher(activity)
                firstStart = launcher.start(OPERATION_ID)
                duplicateStart = launcher.start(OPERATION_ID)
            }
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, firstStart)
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, duplicateStart)

            val firstForeground = awaitForegroundEvidence(afterGeneration = firstGenerationBaseline)
            awaitRunnerSignal(firstAcceptedSignal, "first production TCP connect")
            Thread.sleep(DUPLICATE_DELIVERY_SETTLE_MILLIS)
            val afterDuplicate = application.operationHostLifecycleRegistry.latest()
                ?: throw AssertionError("Installer host lifecycle evidence disappeared after duplicate start")
            assertEquals(firstForeground.generation, afterDuplicate.generation)
            assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, afterDuplicate.state)

            sendExactUserStop(OPERATION_ID, firstForeground.generation)
            val firstStopped = awaitTerminalEvidence(firstForeground.generation)
            assertEquals(ExactOperationHostLifecycleState.USER_STOPPED, firstStopped.state)
            assertEquals(
                safeCurrent,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable truth after safe user Stop"),
            )

            val safeCancelPlan = CancellationClassificationPolicy.classify(
                CancellationPlanInput(
                    current = safeCurrent,
                    dispatchEvidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
                    terminalCancellationPermitted = true,
                ),
            )
            assertEquals(CancellationResourceDisposition.CLOSE_EXACT_RESOURCES, safeCancelPlan.resourceDisposition)
            assertEquals(CancellationDurableDisposition.TERMINAL_CANCEL_ALLOWED, safeCancelPlan.durableDisposition)
            assertEquals(safeCurrent.revision, safeCancelPlan.expectedRevision)
            assertEquals(safeCurrent.snapshot.target, safeCancelPlan.target)

            // Acceptance-only durable evidence: represent the moment after a future feature mutation
            // may have dispatched. No remote mutation or command is executed in this Phase 8.8 gate.
            val unsafeAt = laterThan(safeCurrent.snapshot.updatedAt)
            val unsafeSnapshot = safeCurrent.snapshot.copy(
                checkpoint = OperationCheckpoint(
                    phaseName = UNSAFE_PHASE,
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                    recordedAt = unsafeAt,
                ),
                updatedAt = unsafeAt,
            )
            val unsafeCurrent = journal.advance(OPERATION_ID, safeCurrent.revision, unsafeSnapshot)
                .requireOperationSuccess("advance synthetic unsafe checkpoint")

            // The safe generation is over. Drop any still-live one-shot authority explicitly before
            // representing an unsafe durable checkpoint; whether host cleanup already discarded it is
            // intentionally not part of this acceptance contract.
            application.operationRuntimeCoordinator.discardInstallerFreshAuthorization(OPERATION_ID)
            Thread.sleep(SERVICE_RESTART_SETTLE_MILLIS)
            var secondStart: ExactOperationHostStartResult? = null
            activeScenario.onActivity { activity ->
                secondStart = VisibleExactOperationHostLauncher(activity).start(OPERATION_ID)
            }
            assertEquals(ExactOperationHostStartResult.START_REQUEST_ACCEPTED, secondStart)

            val secondForeground = awaitForegroundEvidence(afterGeneration = firstForeground.generation)
            assertTrue(
                "Replacement host must use a strictly newer lifecycle generation",
                secondForeground.generation > firstForeground.generation,
            )
            awaitRunnerSignal(secondAcceptedSignal, "replacement production TCP connect")

            // Replaying the old notification identity for the same OperationId must not stop the
            // replacement generation. This exercises the real Service onStartCommand boundary.
            sendExactUserStop(OPERATION_ID, firstForeground.generation)
            Thread.sleep(STALE_STOP_SETTLE_MILLIS)
            val afterStaleStop = application.operationHostLifecycleRegistry.latest()
                ?: throw AssertionError("Lifecycle evidence disappeared after stale user Stop")
            assertEquals(secondForeground.generation, afterStaleStop.generation)
            assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, afterStaleStop.state)
            assertEquals(
                unsafeCurrent,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable truth after stale user Stop"),
            )

            sendExactUserStop(OPERATION_ID, secondForeground.generation)
            val secondStopped = awaitTerminalEvidence(secondForeground.generation)
            assertEquals(ExactOperationHostLifecycleState.USER_STOPPED, secondStopped.state)
            assertEquals(
                unsafeCurrent,
                journal.get(OPERATION_ID).requireOperationSuccess("read durable truth after unsafe user Stop"),
            )

            // Deliberately optimistic caller evidence must not downgrade authoritative durable
            // MUTATION_IN_FLIGHT state to terminal CANCELLED permission.
            val unsafeCancelPlan = CancellationClassificationPolicy.classify(
                CancellationPlanInput(
                    current = unsafeCurrent,
                    dispatchEvidence = CancellationDispatchEvidence.BEFORE_MUTATION_DISPATCH,
                    terminalCancellationPermitted = true,
                ),
            )
            assertEquals(CancellationResourceDisposition.CLOSE_EXACT_RESOURCES, unsafeCancelPlan.resourceDisposition)
            assertEquals(CancellationDurableDisposition.REQUIRE_RECONCILIATION, unsafeCancelPlan.durableDisposition)
            assertEquals(unsafeCurrent.revision, unsafeCancelPlan.expectedRevision)
            assertEquals(unsafeCurrent.snapshot.target, unsafeCancelPlan.target)
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
                            secondAcceptedSignal.delete()
                        }
                    }
                }
            }
        }
    }

    private fun verifiedFreshTarget(
        current: com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot,
        at: Instant,
    ) = when (
        val result = FreshInstallAuthorizationPolicy.verify(
            operation = current.snapshot,
            proof = FreshInstallPreflightProof(
                id = TargetProofId("phase88-stop-proof"),
                scope = FreshInstallScope(
                    operationId = OPERATION_ID,
                    serverId = SERVER_ID,
                    serverAccessId = ACCESS_ID,
                ),
                platform = DiscoveryPlatform("ubuntu", "24.04"),
                installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
                conflictState = FreshInstallConflictState.PROVEN_CLEAR,
                observedAt = at.minusSeconds(1),
                validUntil = at.plusSeconds(3_600),
            ),
            now = at,
        )
    ) {
        is FreshInstallVerificationResult.Verified -> result.target
        is FreshInstallVerificationResult.Rejected -> throw AssertionError(
            "Phase 8.8 Stop fresh proof rejected: ${result.reason}",
        )
    }

    private fun readStallPort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_STALL_PORT)
            ?: throw AssertionError("Runner did not provide $ARG_STALL_PORT")
        return raw.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw AssertionError("Runner provided invalid stall port")
    }

    private fun sendExactUserStop(operationId: OperationId, generation: Long) {
        val request = ExactOperationHostUserStopRequest(operationId, generation)
        val intent = Intent(context, ExactOperationShortService::class.java)
            .setAction(ExactOperationShortService.ACTION_STOP_EXACT_OPERATION)
            .setData(Uri.fromParts(STOP_INTENT_SCHEME, request.pendingIntentIdentity, null))
            .putExtra(ExactOperationShortService.EXTRA_OPERATION_ID, operationId.value)
            .putExtra(ExactOperationShortService.EXTRA_HOST_GENERATION, generation)
        context.startService(intent)
            ?: throw AssertionError("Android rejected exact user Stop delivery to the running Service")
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
        application.operationRuntimeCoordinator.discardInstallerFreshAuthorization(OPERATION_ID)
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
                        phaseName = "PHASE8_8_STOP_ACCEPTANCE_CLEANUP",
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
        val SERVER_ID = ServerId("phase8-8-stop-server")
        val ACCESS_ID = ServerAccessId("phase8-8-stop-access")
        val OPERATION_ID = OperationId("phase8-8-stop-operation")
        val SECRET_ID = SecretId("phase8-8-stop-secret")

        const val ARG_STALL_PORT = "phase88.stopStallPort"
        const val FIRST_ACCEPTED_SIGNAL_NAME = "phase88-stop-first-accepted.signal"
        const val SECOND_ACCEPTED_SIGNAL_NAME = "phase88-stop-second-accepted.signal"
        const val SAFE_PHASE = "PHASE8_8_SAFE_PRE_DISPATCH"
        const val UNSAFE_PHASE = "PHASE8_8_SYNTHETIC_MUTATION_IN_FLIGHT"
        const val STOP_INTENT_SCHEME = "velum-runtime-stop"
        const val DUMMY_PASSWORD = "phase88-stop-dummy-password"
        const val DUMMY_HOST_PIN = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        const val RUNNER_SIGNAL_TIMEOUT_MILLIS = 20_000L
        const val HOST_STATE_TIMEOUT_MILLIS = 10_000L
        const val SERVICE_RESTART_SETTLE_MILLIS = 300L
        const val DUPLICATE_DELIVERY_SETTLE_MILLIS = 350L
        const val STALE_STOP_SETTLE_MILLIS = 350L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
