package com.velumtegra.xuimobile.integration

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.os.Process
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
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryAction
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionAuthority
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionResult
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapItem
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapResult
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance
import java.io.File
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6K real-device force-stop / USER_REQUESTED recovery acceptance.
 *
 * The host runner first invokes [prepareDurableFixturesAndAwaitExternalForceStop], waits for an exact
 * PID marker, then performs Android `am force-stop` on the target package. The old process must die
 * and remain absent until the runner explicitly starts the second instrumentation invocation.
 *
 * On API 34+ the fresh process must observe the real ApplicationExitInfo USER_REQUESTED evidence
 * through the production [com.velumtegra.xuimobile.core.runtime.android.AndroidApplicationExitInfoAdapter].
 * Both safe READ_ONLY and unsafe MUTATION_IN_FLIGHT durable operations must become non-automatic,
 * read-only reconciliation plans. Automatic admission must be refused; only an explicit-user
 * authority may acquire the exact runtime lease.
 *
 * No SSH connection, credential resolution or remote command exists in this gate.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6KUserRequestedForceStopInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun prepareDurableFixturesAndAwaitExternalForceStop(): Unit = runBlocking {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            "Phase 4.6K requires API 34+ unambiguous REASON_USER_REQUESTED semantics"
        }

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)

        cleanupFixture(database, journal, serverRepository, accessRepository)
        readyMarker().delete()

        val startedAt = Instant.now()
        serverRepository.create(
            Server(
                id = SERVER_ID,
                displayName = "Phase 4.6K force-stop acceptance",
                createdAt = startedAt,
            ),
        ).requireRepositorySuccess("create acceptance Server")
        credentialWriter.createServerAccess(
            ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", 1),
                username = "phase46k",
                auth = SshAuthRef.Password(INTENTIONALLY_UNUSED_SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:phase46k-never-connected"),
            ),
        ).requireRepositorySuccess("create acceptance ServerAccess")

        val readOnly = journal.create(
            OperationSnapshot(
                operationId = READ_ONLY_OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6K_READ_ONLY_BEFORE_FORCE_STOP",
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            ),
        ).requireOperationSuccess("create READ_ONLY acceptance Operation")

        val mutationStartedAt = startedAt.plusNanos(1)
        val mutation = journal.create(
            OperationSnapshot(
                operationId = MUTATION_OPERATION_ID,
                type = OperationType.RECOVERY,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6K_SYNTHETIC_MUTATION_IN_FLIGHT",
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                    recordedAt = mutationStartedAt,
                ),
                startedAt = mutationStartedAt,
                updatedAt = mutationStartedAt,
            ),
        ).requireOperationSuccess("create MUTATION_IN_FLIGHT acceptance Operation")

        // Instantiate the real process-scoped runtime graph before the external force-stop. This
        // performs no recovery execution and opens no SSH connection.
        val runtimeObservation = application.operationRuntimeCoordinator.connectivitySnapshot()

        readyMarker().writeText(
            buildString {
                append("pid=").append(Process.myPid()).append('\n')
                append("readOnlyRevision=").append(readOnly.revision.value).append('\n')
                append("mutationRevision=").append(mutation.revision.value).append('\n')
                append("runtimeGeneration=").append(runtimeObservation.generation).append('\n')
            },
        )

        // PASS for this stage is external Android force-stop, not normal return.
        val deadlineNanos = System.nanoTime() + EXTERNAL_FORCE_STOP_WAIT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            Thread.sleep(100L)
        }
        throw AssertionError("Phase 4.6K runner did not force-stop the prepared target-app process in time")
    }

    @Test
    fun verifyUserRequestedForceStopNeverAuthorizesAutomaticContinuation() = runBlocking {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            "Phase 4.6K requires API 34+ unambiguous REASON_USER_REQUESTED semantics"
        }

        val activityManager = requireNotNull(context.getSystemService(ActivityManager::class.java))
        val latestReason = activityManager
            .getHistoricalProcessExitReasons(context.packageName, 0, 1)
            .firstOrNull()
            ?.reason
            ?: throw AssertionError("Fresh process has no ApplicationExitInfo record for the force-stopped predecessor")
        assertEquals(
            "Android force-stop must be represented by the API 34+ USER_REQUESTED exit reason",
            ApplicationExitInfo.REASON_USER_REQUESTED,
            latestReason,
        )

        val provenance = application.exitInfoAdapter.previousExitProvenance()
        assertEquals(
            "Production exit adapter must normalize real USER_REQUESTED evidence to USER_REQUESTED_STOP",
            RecoveryExitProvenance.USER_REQUESTED_STOP,
            provenance,
        )

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)

        try {
            val readOnlyBefore = journal.get(READ_ONLY_OPERATION_ID)
                .requireOperationSuccess("read persisted READ_ONLY operation after force-stop")
            val mutationBefore = journal.get(MUTATION_OPERATION_ID)
                .requireOperationSuccess("read persisted MUTATION_IN_FLIGHT operation after force-stop")
            val readOnlyHistoryBefore = journal.history(READ_ONLY_OPERATION_ID)
                .requireOperationSuccess("read persisted READ_ONLY history after force-stop")
            val mutationHistoryBefore = journal.history(MUTATION_OPERATION_ID)
                .requireOperationSuccess("read persisted MUTATION_IN_FLIGHT history after force-stop")

            assertEquals(CheckpointSemantics.READ_ONLY, readOnlyBefore.snapshot.checkpoint.semantics)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, mutationBefore.snapshot.checkpoint.semantics)

            val bootstrap = application.operationRuntimeCoordinator.bootstrapRecovery(provenance)
            val success = bootstrap as? RecoveryBootstrapResult.Success
                ?: throw AssertionError(
                    "Production recovery bootstrap failed after real user-requested force-stop: ${bootstrap::class.java.simpleName}",
                )

            val readOnlyPlan = success.requirePlan(READ_ONLY_OPERATION_ID)
            assertEquals(RecoveryAction.RECONCILE_READ_ONLY, readOnlyPlan.action)
            assertFalse(
                "Even a safe READ_ONLY checkpoint may not auto-continue after an explicit force-stop",
                readOnlyPlan.automaticAllowed,
            )
            assertEquals(readOnlyBefore.snapshot.target, readOnlyPlan.target)
            assertEquals(readOnlyBefore.revision, readOnlyPlan.expectedRevision)

            val mutationPlan = success.requirePlan(MUTATION_OPERATION_ID)
            assertEquals(RecoveryAction.RECONCILE_READ_ONLY, mutationPlan.action)
            assertFalse(
                "Unsafe durable truth must remain non-automatic after an explicit force-stop",
                mutationPlan.automaticAllowed,
            )
            assertEquals(mutationBefore.snapshot.target, mutationPlan.target)
            assertEquals(mutationBefore.revision, mutationPlan.expectedRevision)

            assertEquals(
                RecoveryAdmissionResult.RequiresExplicitAuthorization,
                application.operationRuntimeCoordinator.admitRecovery(
                    readOnlyPlan,
                    RecoveryAdmissionAuthority.AUTOMATIC,
                ),
            )
            assertEquals(
                RecoveryAdmissionResult.RequiresExplicitAuthorization,
                application.operationRuntimeCoordinator.admitRecovery(
                    mutationPlan,
                    RecoveryAdmissionAuthority.AUTOMATIC,
                ),
            )

            val readOnlyExplicit = application.operationRuntimeCoordinator.admitRecovery(
                readOnlyPlan,
                RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED,
            ) as? RecoveryAdmissionResult.Admitted
                ?: throw AssertionError("Explicit-user READ_ONLY reconciliation was not admitted")
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                application.operationRuntimeCoordinator.release(readOnlyExplicit.admission),
            )

            val mutationExplicit = application.operationRuntimeCoordinator.admitRecovery(
                mutationPlan,
                RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED,
            ) as? RecoveryAdmissionResult.Admitted
                ?: throw AssertionError("Explicit-user mutation reconciliation was not admitted")
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                application.operationRuntimeCoordinator.release(mutationExplicit.admission),
            )

            assertEquals(
                "Recovery planning/admission must not rewrite READ_ONLY durable truth",
                readOnlyBefore,
                journal.get(READ_ONLY_OPERATION_ID)
                    .requireOperationSuccess("re-read READ_ONLY operation after force-stop recovery planning"),
            )
            assertEquals(
                "Recovery planning/admission must not rewrite MUTATION_IN_FLIGHT durable truth",
                mutationBefore,
                journal.get(MUTATION_OPERATION_ID)
                    .requireOperationSuccess("re-read MUTATION_IN_FLIGHT operation after force-stop recovery planning"),
            )
            assertEquals(
                readOnlyHistoryBefore,
                journal.history(READ_ONLY_OPERATION_ID)
                    .requireOperationSuccess("re-read READ_ONLY history after force-stop recovery planning"),
            )
            assertEquals(
                mutationHistoryBefore,
                journal.history(MUTATION_OPERATION_ID)
                    .requireOperationSuccess("re-read MUTATION_IN_FLIGHT history after force-stop recovery planning"),
            )
        } finally {
            try {
                cleanupFixture(database, journal, serverRepository, accessRepository)
            } finally {
                readyMarker().delete()
                database.close()
            }
        }
    }

    @Test
    fun cleanupAcceptanceFixtures() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        try {
            cleanupFixture(database, journal, serverRepository, accessRepository)
        } finally {
            readyMarker().delete()
            database.close()
        }
    }

    private fun RecoveryBootstrapResult.Success.requirePlan(operationId: OperationId) =
        items.asSequence()
            .filterIsInstance<RecoveryBootstrapItem.Planned>()
            .map { it.plan }
            .singleOrNull { it.operationId == operationId }
            ?: throw AssertionError("Recovery bootstrap did not produce exactly one plan for ${operationId.value}")

    private suspend fun cleanupFixture(
        database: VelumDatabase,
        journal: RoomOperationJournal,
        serverRepository: RoomServerRepository,
        accessRepository: RoomServerAccessRepository,
    ) {
        for (operationId in listOf(READ_ONLY_OPERATION_ID, MUTATION_OPERATION_ID)) {
            val current = when (val result = journal.get(operationId)) {
                is OperationJournalResult.Success -> result.value
                OperationJournalResult.NotFound -> null
                else -> throw AssertionError(
                    "Acceptance cleanup could not read ${operationId.value}: ${result::class.java.simpleName}",
                )
            }
            if (current != null) {
                val terminal = if (
                    current.snapshot.status == OperationStatus.CANCELLED &&
                    current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
                ) {
                    current
                } else {
                    val cleanupAt = laterThan(current.snapshot.updatedAt)
                    journal.advance(
                        operationId = operationId,
                        expectedRevision = current.revision,
                        next = current.snapshot.copy(
                            status = OperationStatus.CANCELLED,
                            checkpoint = OperationCheckpoint(
                                phaseName = "PHASE4_6K_ACCEPTANCE_CLEANUP",
                                semantics = CheckpointSemantics.TERMINAL,
                                recordedAt = cleanupAt,
                            ),
                            updatedAt = cleanupAt,
                        ),
                    ).requireOperationSuccess("terminalize ${operationId.value} for cleanup")
                }

                database.withWriteTransaction {
                    database.operationDao().deleteJournalForOperation(operationId.value)
                    check(
                        database.operationDao().deleteTerminalSnapshotCas(
                            operationId = operationId.value,
                            expectedRevision = terminal.revision.value,
                        ) == 1,
                    ) { "Acceptance cleanup lost exact terminal row ${operationId.value}" }
                }
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
    }

    private fun readyMarker(): File = File(context.filesDir, READY_MARKER_NAME)

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
        val SERVER_ID = ServerId("phase4-6k-force-stop-server")
        val ACCESS_ID = ServerAccessId("phase4-6k-force-stop-access")
        val READ_ONLY_OPERATION_ID = OperationId("phase4-6k-read-only-operation")
        val MUTATION_OPERATION_ID = OperationId("phase4-6k-mutation-in-flight-operation")
        val INTENTIONALLY_UNUSED_SECRET_ID = SecretId("phase4-6k-never-resolved-secret")

        const val READY_MARKER_NAME = "phase46k-force-stop-ready.marker"
        const val EXTERNAL_FORCE_STOP_WAIT_MILLIS = 90_000L
    }
}
