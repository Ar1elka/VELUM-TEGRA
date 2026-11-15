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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6N real-device reboot + conservative cold-start recovery acceptance.
 *
 * The host runner invokes [prepareDurableFixturesAndAwaitExternalReboot] in a live target process,
 * waits for the app-private PID marker, then performs a real device reboot. The runner verifies the
 * Linux boot id changed and that the target package does not resurrect before an explicit
 * instrumentation start. Only then does [verifyRebootRecoveryIsConservative] run in the new boot.
 *
 * The production ApplicationExitInfo adapter deliberately does not guess DEVICE_REBOOT. A real
 * reboot may still be reported by a platform build as conservative USER_REQUESTED_STOP evidence;
 * the acceptance contract is therefore policy-based: post-reboot provenance must never become a
 * PROCESS_DEATH/SYSTEM_STOP path that could authorize automatic recovery. API 24-29 still fail
 * closed to UNKNOWN through the canonical adapter regression tests.
 *
 * No Service is started, no credential is resolved, no SSH connection exists and no remote command
 * is available in this gate.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6NRebootConservativeRecoveryInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun prepareDurableFixturesAndAwaitExternalReboot(): Unit = runBlocking {
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
                displayName = "Phase 4.6N reboot acceptance",
                createdAt = startedAt,
            ),
        ).requireRepositorySuccess("create acceptance Server")
        credentialWriter.createServerAccess(
            ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", 1),
                username = "phase46n",
                auth = SshAuthRef.Password(INTENTIONALLY_UNUSED_SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:phase46n-never-connected"),
            ),
        ).requireRepositorySuccess("create acceptance ServerAccess")

        val readOnly = journal.create(
            OperationSnapshot(
                operationId = READ_ONLY_OPERATION_ID,
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6N_READ_ONLY_BEFORE_REBOOT",
                    semantics = CheckpointSemantics.READ_ONLY,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            ),
        ).requireOperationSuccess("create READ_ONLY reboot Operation")

        val mutationStartedAt = startedAt.plusNanos(1)
        val mutation = journal.create(
            OperationSnapshot(
                operationId = MUTATION_OPERATION_ID,
                type = OperationType.RECOVERY,
                target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE4_6N_SYNTHETIC_MUTATION_IN_FLIGHT_BEFORE_REBOOT",
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                    recordedAt = mutationStartedAt,
                ),
                startedAt = mutationStartedAt,
                updatedAt = mutationStartedAt,
            ),
        ).requireOperationSuccess("create MUTATION_IN_FLIGHT reboot Operation")

        // Instantiate the real process-scoped runtime graph, but do not bootstrap recovery or start
        // any Android execution host. Reboot itself must be the next lifecycle boundary.
        val runtimeObservation = application.operationRuntimeCoordinator.connectivitySnapshot()
        readyMarker().writeText(
            buildString {
                append("pid=").append(Process.myPid()).append('\n')
                append("readOnlyRevision=").append(readOnly.revision.value).append('\n')
                append("mutationRevision=").append(mutation.revision.value).append('\n')
                append("runtimeGeneration=").append(runtimeObservation.generation).append('\n')
            },
        )

        val deadlineNanos = System.nanoTime() + EXTERNAL_REBOOT_WAIT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            Thread.sleep(100L)
        }
        throw AssertionError("Phase 4.6N runner did not reboot the prepared device in time")
    }

    @Test
    fun verifyRebootRecoveryIsConservative() = runBlocking {
        val provenance = application.exitInfoAdapter.previousExitProvenance()
        assertTrue(
            "Real reboot evidence must stay on a non-automatic conservative provenance path, but was $provenance",
            provenance in setOf(
                RecoveryExitProvenance.UNKNOWN,
                RecoveryExitProvenance.USER_REQUESTED_STOP,
                RecoveryExitProvenance.DEVICE_REBOOT,
            ),
        )

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)

        try {
            val readOnlyBefore = journal.get(READ_ONLY_OPERATION_ID)
                .requireOperationSuccess("read READ_ONLY operation after reboot")
            val mutationBefore = journal.get(MUTATION_OPERATION_ID)
                .requireOperationSuccess("read MUTATION_IN_FLIGHT operation after reboot")
            val readOnlyHistoryBefore = journal.history(READ_ONLY_OPERATION_ID)
                .requireOperationSuccess("read READ_ONLY history after reboot")
            val mutationHistoryBefore = journal.history(MUTATION_OPERATION_ID)
                .requireOperationSuccess("read MUTATION_IN_FLIGHT history after reboot")

            assertEquals(CheckpointSemantics.READ_ONLY, readOnlyBefore.snapshot.checkpoint.semantics)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, mutationBefore.snapshot.checkpoint.semantics)
            assertEquals(OperationStatus.RUNNING, readOnlyBefore.snapshot.status)
            assertEquals(OperationStatus.RUNNING, mutationBefore.snapshot.status)

            val bootstrap = application.operationRuntimeCoordinator.bootstrapRecovery(provenance)
            val success = bootstrap as? RecoveryBootstrapResult.Success
                ?: throw AssertionError(
                    "Production recovery bootstrap failed after real reboot: ${bootstrap::class.java.simpleName}",
                )

            val readOnlyPlan = success.requirePlan(READ_ONLY_OPERATION_ID)
            val expectedReadOnlyAction = when (provenance) {
                RecoveryExitProvenance.UNKNOWN -> RecoveryAction.RECONNECT_EXACT_OWNER
                RecoveryExitProvenance.USER_REQUESTED_STOP,
                RecoveryExitProvenance.DEVICE_REBOOT,
                -> RecoveryAction.RECONCILE_READ_ONLY
                RecoveryExitProvenance.PROCESS_DEATH,
                RecoveryExitProvenance.SYSTEM_STOP,
                -> throw AssertionError("Unsafe automatic-capable reboot provenance escaped the guard: $provenance")
            }
            assertEquals(expectedReadOnlyAction, readOnlyPlan.action)
            assertFalse(
                "Reboot READ_ONLY recovery must never authorize background automatic continuation",
                readOnlyPlan.automaticAllowed,
            )
            assertEquals(readOnlyBefore.snapshot.target, readOnlyPlan.target)
            assertEquals(readOnlyBefore.revision, readOnlyPlan.expectedRevision)

            val mutationPlan = success.requirePlan(MUTATION_OPERATION_ID)
            assertEquals(
                "MUTATION_IN_FLIGHT after reboot must require read-only reconciliation, never replay",
                RecoveryAction.RECONCILE_READ_ONLY,
                mutationPlan.action,
            )
            assertFalse(
                "Reboot mutation recovery must require an explicit user-allowed entry point",
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

            // The runner started this instrumentation explicitly after boot. Prove that the same
            // exact plans can be admitted only under that explicit-user authority, without doing
            // any transport work, and release both process-local leases immediately.
            val readOnlyAdmission = application.operationRuntimeCoordinator.admitRecovery(
                readOnlyPlan,
                RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED,
            ) as? RecoveryAdmissionResult.Admitted
                ?: throw AssertionError("Explicit READ_ONLY reboot recovery admission was not granted")
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                application.operationRuntimeCoordinator.release(readOnlyAdmission.admission),
            )

            val mutationAdmission = application.operationRuntimeCoordinator.admitRecovery(
                mutationPlan,
                RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED,
            ) as? RecoveryAdmissionResult.Admitted
                ?: throw AssertionError("Explicit read-only reconciliation admission was not granted")
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                application.operationRuntimeCoordinator.release(mutationAdmission.admission),
            )

            val currentNonTerminal = journal.listNonTerminal()
                .requireOperationSuccess("reload durable nonterminal set after reboot")
            val barrier = DurableServerMutationBarrierPolicy.evaluate(
                serverId = SERVER_ID,
                durableOperations = currentNonTerminal.map { it.snapshot },
            )
            val blocked = barrier as? ServerMutationBarrierDecision.BlockedByUncertainMutation
                ?: throw AssertionError(
                    "Durable MUTATION_IN_FLIGHT evidence must keep the server mutation barrier closed after reboot",
                )
            assertTrue(
                "Reboot recovery barrier must name the exact unsafe operation",
                blocked.blockers.any {
                    it.operationId == MUTATION_OPERATION_ID &&
                        it.status == OperationStatus.RUNNING &&
                        it.checkpointSemantics == CheckpointSemantics.MUTATION_IN_FLIGHT
                },
            )

            assertEquals(
                readOnlyBefore,
                journal.get(READ_ONLY_OPERATION_ID)
                    .requireOperationSuccess("re-read READ_ONLY operation after reboot planning/admission"),
            )
            assertEquals(
                mutationBefore,
                journal.get(MUTATION_OPERATION_ID)
                    .requireOperationSuccess("re-read MUTATION operation after reboot planning/admission"),
            )
            assertEquals(
                readOnlyHistoryBefore,
                journal.history(READ_ONLY_OPERATION_ID)
                    .requireOperationSuccess("re-read READ_ONLY history after reboot planning/admission"),
            )
            assertEquals(
                mutationHistoryBefore,
                journal.history(MUTATION_OPERATION_ID)
                    .requireOperationSuccess("re-read MUTATION history after reboot planning/admission"),
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
                                phaseName = "PHASE4_6N_ACCEPTANCE_CLEANUP",
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
        val SERVER_ID = ServerId("phase4-6n-reboot-server")
        val ACCESS_ID = ServerAccessId("phase4-6n-reboot-access")
        val READ_ONLY_OPERATION_ID = OperationId("phase4-6n-read-only-operation")
        val MUTATION_OPERATION_ID = OperationId("phase4-6n-mutation-in-flight-operation")
        val INTENTIONALLY_UNUSED_SECRET_ID = SecretId("phase4-6n-never-resolved-secret")

        const val READY_MARKER_NAME = "phase46n-reboot-ready.marker"
        const val EXTERNAL_REBOOT_WAIT_MILLIS = 180_000L
    }
}
