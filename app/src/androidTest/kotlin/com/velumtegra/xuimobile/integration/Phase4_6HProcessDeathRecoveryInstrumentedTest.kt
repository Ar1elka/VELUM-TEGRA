package com.velumtegra.xuimobile.integration

import android.content.Context
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
import com.velumtegra.xuimobile.core.runtime.DurableServerMutationBarrierPolicy
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryAction
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionAuthority
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionResult
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapItem
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapResult
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance
import com.velumtegra.xuimobile.core.runtime.ServerMutationBarrierDecision
import java.io.File
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6H real-device process-death recovery acceptance.
 *
 * The runner invokes [prepareDurableFixturesAndAwaitExternalCrash] first and does not let it finish
 * normally. After both durable fixtures exist and the production process-scoped runtime graph has
 * been instantiated, this method publishes an app-private marker containing its exact Android PID
 * and waits. The host runner then asks Android Activity Manager to crash that exact target-app
 * process. A second instrumentation invocation starts in a new process and calls
 * [verifyProcessDeathRecoveryIsCheckpointConservative].
 *
 * This proves three adjacent Constitution properties against production Room + production
 * ApplicationExitInfo + production OperationRuntimeCoordinator:
 * 1) READ_ONLY survives real process death as exact-owner reconnect policy;
 * 2) MUTATION_IN_FLIGHT survives real process death as read-only reconciliation, never replay;
 * 3) the same durable unsafe checkpoint still closes the server mutation barrier after recreation.
 *
 * No SSH connection or remote command exists in this gate.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6HProcessDeathRecoveryInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun prepareDurableFixturesAndAwaitExternalCrash(): Unit = runBlocking {
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
                displayName = "Phase 4.6H process-death acceptance",
                createdAt = startedAt,
            ),
        ).requireRepositorySuccess("create acceptance Server")
        credentialWriter.createServerAccess(
            ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", 1),
                username = "phase46h",
                auth = SshAuthRef.Password(INTENTIONALLY_UNUSED_SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:phase46h-never-connected"),
            ),
        ).requireRepositorySuccess("create acceptance ServerAccess")

        val readOnly = journal.create(
            OperationSnapshot(
                operationId = READ_ONLY_OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6H_READ_ONLY_BEFORE_PROCESS_DEATH",
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
                    phaseName = "PHASE4_6H_SYNTHETIC_MUTATION_IN_FLIGHT",
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                    recordedAt = mutationStartedAt,
                ),
                startedAt = mutationStartedAt,
                updatedAt = mutationStartedAt,
            ),
        ).requireOperationSuccess("create MUTATION_IN_FLIGHT acceptance Operation")

        // Force construction of the production process-scoped runtime graph before the runner kills
        // this process. Merely constructing it performs no recovery execution and opens no SSH.
        val runtimeObservation = application.operationRuntimeCoordinator.connectivitySnapshot()

        readyMarker().writeText(
            buildString {
                append("pid=").append(Process.myPid()).append('\n')
                append("readOnlyRevision=").append(readOnly.revision.value).append('\n')
                append("mutationRevision=").append(mutation.revision.value).append('\n')
                append("runtimeGeneration=").append(runtimeObservation.generation).append('\n')
            },
        )

        // PASS for this stage is process death, not normal return. If the host runner fails to crash
        // the process, fail boundedly instead of leaving an immortal instrumentation test behind.
        val deadlineNanos = System.nanoTime() + EXTERNAL_CRASH_WAIT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            Thread.sleep(100L)
        }
        throw AssertionError("Phase 4.6H runner did not crash the prepared target-app process in time")
    }

    @Test
    fun verifyProcessDeathRecoveryIsCheckpointConservative() = runBlocking {
        val provenance = application.exitInfoAdapter.previousExitProvenance()
        assertEquals(
            "Fresh process must observe Android's real previous-process crash evidence",
            RecoveryExitProvenance.PROCESS_DEATH,
            provenance,
        )

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)

        try {
            val readOnlyBefore = journal.get(READ_ONLY_OPERATION_ID)
                .requireOperationSuccess("read persisted READ_ONLY operation after process death")
            val mutationBefore = journal.get(MUTATION_OPERATION_ID)
                .requireOperationSuccess("read persisted MUTATION_IN_FLIGHT operation after process death")
            val readOnlyHistoryBefore = journal.history(READ_ONLY_OPERATION_ID)
                .requireOperationSuccess("read persisted READ_ONLY history after process death")
            val mutationHistoryBefore = journal.history(MUTATION_OPERATION_ID)
                .requireOperationSuccess("read persisted MUTATION_IN_FLIGHT history after process death")

            assertEquals(CheckpointSemantics.READ_ONLY, readOnlyBefore.snapshot.checkpoint.semantics)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, mutationBefore.snapshot.checkpoint.semantics)
            assertEquals(OperationStatus.RUNNING, readOnlyBefore.snapshot.status)
            assertEquals(OperationStatus.RUNNING, mutationBefore.snapshot.status)

            val bootstrap = application.operationRuntimeCoordinator.bootstrapRecovery(provenance)
            val success = bootstrap as? RecoveryBootstrapResult.Success
                ?: throw AssertionError(
                    "Production recovery bootstrap failed after real process death: ${bootstrap::class.java.simpleName}",
                )

            val readOnlyPlan = success.requirePlan(READ_ONLY_OPERATION_ID)
            assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, readOnlyPlan.action)
            assertTrue("READ_ONLY process-death recovery may use automatic exact reconnect", readOnlyPlan.automaticAllowed)
            assertEquals(readOnlyBefore.snapshot.target, readOnlyPlan.target)
            assertEquals(readOnlyBefore.revision, readOnlyPlan.expectedRevision)

            val mutationPlan = success.requirePlan(MUTATION_OPERATION_ID)
            assertEquals(
                "MUTATION_IN_FLIGHT after process death must never become command replay",
                RecoveryAction.RECONCILE_READ_ONLY,
                mutationPlan.action,
            )
            assertTrue("Read-only reconciliation may be scheduled automatically after proven process death", mutationPlan.automaticAllowed)
            assertEquals(mutationBefore.snapshot.target, mutationPlan.target)
            assertEquals(mutationBefore.revision, mutationPlan.expectedRevision)

            val readOnlyAdmission = application.operationRuntimeCoordinator.admitRecovery(
                readOnlyPlan,
                RecoveryAdmissionAuthority.AUTOMATIC,
            ) as? RecoveryAdmissionResult.Admitted
                ?: throw AssertionError("READ_ONLY exact recovery plan was not admitted in the fresh process")
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                application.operationRuntimeCoordinator.release(readOnlyAdmission.admission),
            )

            val mutationAdmission = application.operationRuntimeCoordinator.admitRecovery(
                mutationPlan,
                RecoveryAdmissionAuthority.AUTOMATIC,
            ) as? RecoveryAdmissionResult.Admitted
                ?: throw AssertionError("Read-only reconciliation plan was not admitted in the fresh process")
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                application.operationRuntimeCoordinator.release(mutationAdmission.admission),
            )

            val currentNonTerminal = journal.listNonTerminal()
                .requireOperationSuccess("reload durable nonterminal set after process recreation")
            val barrier = DurableServerMutationBarrierPolicy.evaluate(
                serverId = SERVER_ID,
                durableOperations = currentNonTerminal.map { it.snapshot },
            )
            val blocked = barrier as? ServerMutationBarrierDecision.BlockedByUncertainMutation
                ?: throw AssertionError(
                    "Durable MUTATION_IN_FLIGHT evidence must keep the same-server mutation barrier closed after process recreation",
                )
            assertTrue(
                "Recovered durable barrier must name the exact unsafe operation",
                blocked.blockers.any {
                    it.operationId == MUTATION_OPERATION_ID &&
                        it.status == OperationStatus.RUNNING &&
                        it.checkpointSemantics == CheckpointSemantics.MUTATION_IN_FLIGHT
                },
            )

            assertEquals(
                "Recovery planning/admission must not rewrite READ_ONLY durable truth",
                readOnlyBefore,
                journal.get(READ_ONLY_OPERATION_ID)
                    .requireOperationSuccess("re-read READ_ONLY operation after recovery planning"),
            )
            assertEquals(
                "Recovery planning/admission must not rewrite MUTATION_IN_FLIGHT durable truth",
                mutationBefore,
                journal.get(MUTATION_OPERATION_ID)
                    .requireOperationSuccess("re-read MUTATION_IN_FLIGHT operation after recovery planning"),
            )
            assertEquals(
                readOnlyHistoryBefore,
                journal.history(READ_ONLY_OPERATION_ID)
                    .requireOperationSuccess("re-read READ_ONLY history after recovery planning"),
            )
            assertEquals(
                mutationHistoryBefore,
                journal.history(MUTATION_OPERATION_ID)
                    .requireOperationSuccess("re-read MUTATION_IN_FLIGHT history after recovery planning"),
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
                                phaseName = "PHASE4_6H_ACCEPTANCE_CLEANUP",
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
        val SERVER_ID = ServerId("phase4-6h-process-death-server")
        val ACCESS_ID = ServerAccessId("phase4-6h-process-death-access")
        val READ_ONLY_OPERATION_ID = OperationId("phase4-6h-read-only-operation")
        val MUTATION_OPERATION_ID = OperationId("phase4-6h-mutation-in-flight-operation")
        val INTENTIONALLY_UNUSED_SECRET_ID = SecretId("phase4-6h-never-resolved-secret")

        const val READY_MARKER_NAME = "phase46h-process-ready.marker"
        const val EXTERNAL_CRASH_WAIT_MILLIS = 90_000L
    }
}
