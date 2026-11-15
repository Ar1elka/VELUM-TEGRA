package com.velumtegra.xuimobile.integration

import android.content.Context
import android.os.Process
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
import com.velumtegra.xuimobile.core.domain.FreshInstallAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.FreshInstallVerificationResult
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
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
import com.velumtegra.xuimobile.core.runtime.DurableServerMutationBarrierPolicy
import com.velumtegra.xuimobile.core.runtime.InstallerPostInstallCoordinatorResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeEntryRegistrationResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimePreparationResult
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
 * Phase 8.8 real-device process/force-stop/reboot acceptance for all Installer recovery boundaries.
 *
 * The same deterministic durable fixture is exercised across three real Android termination modes.
 * No SSH endpoint is reachable and the acceptance SecretId is intentionally never resolved.
 */
@RunWith(AndroidJUnit4::class)
class Phase8_8InstallerLifecycleRecoveryInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun prepareInstallerCheckpointsAndAwaitExternalTermination(): Unit = runBlocking {
        val mode = requiredMode()
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)

        cleanupFixture(database, journal, serverRepository, accessRepository)
        readyMarker().delete()

        val startedAt = Instant.now()
        serverRepository.create(
            Server(SERVER_ID, "Phase 8.8 Installer lifecycle acceptance", startedAt),
        ).requireRepositorySuccess("create Phase 8.8 Server")
        credentialWriter.createServerAccess(
            ServerAccess(
                id = ACCESS_ID,
                serverId = SERVER_ID,
                endpoint = SshEndpoint("127.0.0.1", 1),
                username = "phase88-never-connected",
                auth = SshAuthRef.Password(INTENTIONALLY_UNUSED_SECRET_ID),
                pinnedHostKey = HostKeyFingerprint("SHA256:phase88-never-connected"),
            ),
        ).requireRepositorySuccess("create Phase 8.8 ServerAccess")

        val predispatch = createOperation(
            journal = journal,
            operationId = PREDISPATCH_OPERATION_ID,
            status = OperationStatus.RUNNING,
            semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
            phase = "PHASE8_8_PREDISPATCH",
            at = startedAt,
        )
        val inFlight = createOperation(
            journal = journal,
            operationId = IN_FLIGHT_OPERATION_ID,
            status = OperationStatus.RUNNING,
            semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
            phase = "PHASE8_8_MUTATION_IN_FLIGHT",
            at = startedAt.plusNanos(1),
        )
        val postVerify = createOperation(
            journal = journal,
            operationId = POST_VERIFY_OPERATION_ID,
            status = OperationStatus.RECONCILIATION_REQUIRED,
            semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
            phase = "PHASE8_8_POST_VERIFY_REQUIRED",
            at = startedAt.plusNanos(2),
        )
        val commitVerified = createOperation(
            journal = journal,
            operationId = COMMIT_OPERATION_ID,
            status = OperationStatus.RUNNING,
            semantics = CheckpointSemantics.COMMIT_VERIFIED,
            phase = "PHASE8_8_COMMIT_VERIFIED",
            at = startedAt.plusNanos(3),
        )

        // Prove the pre-dispatch authority exists before termination and reaches the production
        // pre-transport gate. The exact authority remains unconsumed because no SSH/mutation runs.
        val fresh = verifiedFreshTarget(predispatch, startedAt.plusSeconds(1))
        assertEquals(
            InstallerRuntimeEntryRegistrationResult.Registered,
            application.operationRuntimeCoordinator.registerInstallerFreshAuthorization(fresh),
        )
        val prePlan = application.operationRuntimeCoordinator
            .bootstrapRecovery(RecoveryExitProvenance.UNKNOWN)
            .requireSuccess()
            .requirePlan(PREDISPATCH_OPERATION_ID)
        val preAdmission = application.operationRuntimeCoordinator.admitRecovery(
            prePlan,
            RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED,
        ) as? RecoveryAdmissionResult.Admitted
            ?: throw AssertionError("Phase 8.8 pre-termination Installer admission was not granted")
        assertEquals(
            InstallerRuntimePreparationResult.TransportRequired,
            application.operationRuntimeCoordinator.prepareInstallerTransport(preAdmission.admission),
        )
        assertEquals(
            OperationRuntimeReleaseResult.RELEASED,
            application.operationRuntimeCoordinator.release(preAdmission.admission),
        )

        // Force construction of the production graph before the runner terminates this process.
        val runtimeObservation = application.operationRuntimeCoordinator.connectivitySnapshot()
        readyMarker().writeText(
            buildString {
                append("mode=").append(mode).append('\n')
                append("pid=").append(Process.myPid()).append('\n')
                append("predispatchRevision=").append(predispatch.revision.value).append('\n')
                append("inFlightRevision=").append(inFlight.revision.value).append('\n')
                append("postVerifyRevision=").append(postVerify.revision.value).append('\n')
                append("commitRevision=").append(commitVerified.revision.value).append('\n')
                append("runtimeGeneration=").append(runtimeObservation.generation).append('\n')
            },
        )

        val deadline = System.nanoTime() + EXTERNAL_TERMINATION_WAIT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadline) Thread.sleep(100L)
        throw AssertionError("Phase 8.8 runner did not perform external $mode termination in time")
    }

    @Test
    fun verifyInstallerRecoveryIsCheckpointConservative() = runBlocking {
        val mode = requiredMode()
        val provenance = application.exitInfoAdapter.previousExitProvenance()
        when (mode) {
            MODE_PROCESS_DEATH -> assertEquals(RecoveryExitProvenance.PROCESS_DEATH, provenance)
            MODE_FORCE_STOP -> assertEquals(RecoveryExitProvenance.USER_REQUESTED_STOP, provenance)
            MODE_REBOOT -> assertTrue(
                "Reboot provenance must remain conservative and must not masquerade as process/system auto-resume",
                provenance in setOf(
                    RecoveryExitProvenance.DEVICE_REBOOT,
                    RecoveryExitProvenance.USER_REQUESTED_STOP,
                    RecoveryExitProvenance.UNKNOWN,
                ),
            )
            else -> throw AssertionError("Unsupported Phase 8.8 lifecycle mode: $mode")
        }

        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        try {
            val before = OPERATION_IDS.associateWith { operationId ->
                journal.get(operationId).requireOperationSuccess("read ${operationId.value} after $mode")
            }
            assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, before.getValue(PREDISPATCH_OPERATION_ID).snapshot.checkpoint.semantics)
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, before.getValue(IN_FLIGHT_OPERATION_ID).snapshot.checkpoint.semantics)
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, before.getValue(POST_VERIFY_OPERATION_ID).snapshot.checkpoint.semantics)
            assertEquals(CheckpointSemantics.COMMIT_VERIFIED, before.getValue(COMMIT_OPERATION_ID).snapshot.checkpoint.semantics)

            // The process-local authority proved present before termination must be gone now.
            assertFalse(application.operationRuntimeCoordinator.discardInstallerFreshAuthorization(PREDISPATCH_OPERATION_ID))

            val bootstrap = application.operationRuntimeCoordinator.bootstrapRecovery(provenance).requireSuccess()
            val plans = OPERATION_IDS.associateWith { bootstrap.requirePlan(it) }
            val automaticExpected = mode == MODE_PROCESS_DEATH

            if (automaticExpected) {
                assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plans.getValue(PREDISPATCH_OPERATION_ID).action)
                assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, plans.getValue(COMMIT_OPERATION_ID).action)
                assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plans.getValue(IN_FLIGHT_OPERATION_ID).action)
                assertEquals(RecoveryAction.RECONCILE_READ_ONLY, plans.getValue(POST_VERIFY_OPERATION_ID).action)
                plans.values.forEach { assertTrue(it.automaticAllowed) }
            } else {
                plans.values.forEach {
                    assertEquals(RecoveryAction.RECONCILE_READ_ONLY, it.action)
                    assertFalse(it.automaticAllowed)
                    assertEquals(
                        RecoveryAdmissionResult.RequiresExplicitAuthorization,
                        application.operationRuntimeCoordinator.admitRecovery(
                            it,
                            RecoveryAdmissionAuthority.AUTOMATIC,
                        ),
                    )
                }
            }

            val authority = if (automaticExpected) {
                RecoveryAdmissionAuthority.AUTOMATIC
            } else {
                RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED
            }

            val preAdmission = admit(plans.getValue(PREDISPATCH_OPERATION_ID), authority)
            assertEquals(
                "Process-local fresh authority must not survive $mode",
                InstallerRuntimePreparationResult.FreshAuthorizationRequired,
                application.operationRuntimeCoordinator.prepareInstallerTransport(preAdmission),
            )
            release(preAdmission)

            val inFlightAdmission = admit(plans.getValue(IN_FLIGHT_OPERATION_ID), authority)
            assertEquals(
                InstallerRuntimePreparationResult.TransportRequired,
                application.operationRuntimeCoordinator.prepareInstallerTransport(inFlightAdmission),
            )
            release(inFlightAdmission)

            val postVerifyAdmission = admit(plans.getValue(POST_VERIFY_OPERATION_ID), authority)
            assertEquals(
                InstallerRuntimePreparationResult.TransportRequired,
                application.operationRuntimeCoordinator.prepareInstallerTransport(postVerifyAdmission),
            )
            release(postVerifyAdmission)

            val commitAdmission = admit(plans.getValue(COMMIT_OPERATION_ID), authority)
            val commitPreparation = application.operationRuntimeCoordinator.prepareInstallerTransport(commitAdmission)
            val commitCompleted = commitPreparation as? InstallerRuntimePreparationResult.Completed
                ?: throw AssertionError("COMMIT_VERIFIED did not complete locally after $mode: $commitPreparation")
            assertTrue(commitCompleted.result is InstallerPostInstallCoordinatorResult.Succeeded)
            release(commitAdmission)

            assertEquals(
                before.getValue(PREDISPATCH_OPERATION_ID),
                journal.get(PREDISPATCH_OPERATION_ID).requireOperationSuccess("re-read predispatch after $mode"),
            )
            assertEquals(
                before.getValue(IN_FLIGHT_OPERATION_ID),
                journal.get(IN_FLIGHT_OPERATION_ID).requireOperationSuccess("re-read in-flight after $mode"),
            )
            assertEquals(
                before.getValue(POST_VERIFY_OPERATION_ID),
                journal.get(POST_VERIFY_OPERATION_ID).requireOperationSuccess("re-read post-verify after $mode"),
            )
            val committedAfter = journal.get(COMMIT_OPERATION_ID).requireOperationSuccess("re-read commit after $mode")
            assertEquals(OperationStatus.SUCCEEDED, committedAfter.snapshot.status)
            assertEquals(CheckpointSemantics.TERMINAL, committedAfter.snapshot.checkpoint.semantics)

            val nonTerminal = journal.listNonTerminal().requireOperationSuccess("read durable blockers after $mode")
            val barrier = DurableServerMutationBarrierPolicy.evaluate(
                serverId = SERVER_ID,
                durableOperations = nonTerminal.map { it.snapshot },
            ) as? ServerMutationBarrierDecision.BlockedByUncertainMutation
                ?: throw AssertionError("Unsafe Installer checkpoint did not keep same-server mutation barrier closed after $mode")
            assertTrue(barrier.blockers.any { it.operationId == IN_FLIGHT_OPERATION_ID })
            assertTrue(barrier.blockers.any { it.operationId == POST_VERIFY_OPERATION_ID })
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

    private suspend fun createOperation(
        journal: RoomOperationJournal,
        operationId: OperationId,
        status: OperationStatus,
        semantics: CheckpointSemantics,
        phase: String,
        at: Instant,
    ): VersionedOperationSnapshot = journal.create(
        OperationSnapshot(
            operationId = operationId,
            type = OperationType.INSTALL,
            target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID),
            status = status,
            checkpoint = OperationCheckpoint(phase, semantics, at),
            startedAt = at,
            updatedAt = at,
        ),
    ).requireOperationSuccess("create ${operationId.value}")

    private fun verifiedFreshTarget(current: VersionedOperationSnapshot, at: Instant) = when (
        val result = FreshInstallAuthorizationPolicy.verify(
            operation = current.snapshot,
            proof = FreshInstallPreflightProof(
                id = TargetProofId("phase88-lifecycle-proof"),
                scope = FreshInstallScope(
                    operationId = current.snapshot.operationId,
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
        is FreshInstallVerificationResult.Rejected -> throw AssertionError("Phase 8.8 fresh proof rejected: ${result.reason}")
    }

    private suspend fun admit(
        plan: com.velumtegra.xuimobile.core.runtime.ColdStartRecoveryPlan,
        authority: RecoveryAdmissionAuthority,
    ) = (application.operationRuntimeCoordinator.admitRecovery(plan, authority) as? RecoveryAdmissionResult.Admitted)
        ?.admission ?: throw AssertionError("Phase 8.8 exact recovery admission was not granted for ${plan.operationId.value}")

    private fun release(admission: com.velumtegra.xuimobile.core.runtime.RecoveryRuntimeAdmission) {
        assertEquals(OperationRuntimeReleaseResult.RELEASED, application.operationRuntimeCoordinator.release(admission))
    }

    private fun RecoveryBootstrapResult.requireSuccess(): RecoveryBootstrapResult.Success =
        this as? RecoveryBootstrapResult.Success
            ?: throw AssertionError("Phase 8.8 recovery bootstrap failed: ${this::class.java.simpleName}")

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
        application.operationRuntimeCoordinator.discardInstallerFreshAuthorization(PREDISPATCH_OPERATION_ID)
        for (operationId in OPERATION_IDS) {
            val current = when (val result = journal.get(operationId)) {
                is OperationJournalResult.Success -> result.value
                OperationJournalResult.NotFound -> null
                else -> throw AssertionError("Acceptance cleanup could not read ${operationId.value}: ${result::class.java.simpleName}")
            }
            if (current != null) {
                val terminal = if (current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
                    current
                } else {
                    val cleanupAt = laterThan(current.snapshot.updatedAt)
                    journal.advance(
                        operationId = operationId,
                        expectedRevision = current.revision,
                        next = current.snapshot.copy(
                            status = OperationStatus.CANCELLED,
                            checkpoint = OperationCheckpoint(
                                phaseName = "PHASE8_8_LIFECYCLE_ACCEPTANCE_CLEANUP",
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
            else -> throw AssertionError("Acceptance cleanup could not delete exact ServerAccess: ${accessDelete::class.java.simpleName}")
        }
        when (val serverCurrent = serverRepository.get(SERVER_ID)) {
            is RepositoryResult.Success -> when (val deleted = serverRepository.delete(SERVER_ID, serverCurrent.value.revision)) {
                is RepositoryResult.Success -> Unit
                else -> throw AssertionError("Acceptance cleanup could not delete exact Server: ${deleted::class.java.simpleName}")
            }
            RepositoryResult.NotFound -> Unit
            else -> throw AssertionError("Acceptance cleanup could not read exact Server: ${serverCurrent::class.java.simpleName}")
        }
    }

    private fun requiredMode(): String =
        InstrumentationRegistry.getArguments().getString(ARG_MODE)?.trim()?.takeIf { it in MODES }
            ?: throw AssertionError("Runner did not provide a valid $ARG_MODE")

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
        val SERVER_ID = ServerId("phase8-8-lifecycle-server")
        val ACCESS_ID = ServerAccessId("phase8-8-lifecycle-access")
        val PREDISPATCH_OPERATION_ID = OperationId("phase8-8-predispatch")
        val IN_FLIGHT_OPERATION_ID = OperationId("phase8-8-in-flight")
        val POST_VERIFY_OPERATION_ID = OperationId("phase8-8-post-verify")
        val COMMIT_OPERATION_ID = OperationId("phase8-8-commit")
        val OPERATION_IDS = listOf(PREDISPATCH_OPERATION_ID, IN_FLIGHT_OPERATION_ID, POST_VERIFY_OPERATION_ID, COMMIT_OPERATION_ID)
        val INTENTIONALLY_UNUSED_SECRET_ID = SecretId("phase8-8-never-resolved-secret")

        const val ARG_MODE = "phase88.lifecycleMode"
        const val MODE_PROCESS_DEATH = "process-death"
        const val MODE_FORCE_STOP = "force-stop"
        const val MODE_REBOOT = "reboot"
        val MODES = setOf(MODE_PROCESS_DEATH, MODE_FORCE_STOP, MODE_REBOOT)
        const val READY_MARKER_NAME = "phase88-lifecycle-ready.marker"
        const val EXTERNAL_TERMINATION_WAIT_MILLIS = 150_000L
    }
}
