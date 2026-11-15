package com.velumtegra.xuimobile.integration

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.runtime.ColdStartRecoveryPlan
import com.velumtegra.xuimobile.core.runtime.ExactRuntimeSessionCloseResult
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryAction
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionAuthority
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionResult
import com.velumtegra.xuimobile.core.runtime.ServerMutationAcquireResult
import com.velumtegra.xuimobile.core.runtime.ServerMutationLeaseRegistry
import com.velumtegra.xuimobile.core.runtime.ServerMutationReleaseResult
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6L real-device live mutation serialization + stale-session cleanup acceptance.
 *
 * Part 1 races two different mutating OperationIds for the same stable ServerId through the
 * production ServerMutationLeaseRegistry on Android. Exactly one may acquire the live mutation
 * lease. After the winner releases, the loser may become the replacement owner; a stale second
 * release of the old lease must not evict that replacement.
 *
 * Part 2 exercises the production OperationRuntimeCoordinator + ExactSessionRegistry boundary.
 * A replacement SessionId is published for the same exact Operation owner/access. Cleanup carrying
 * the prior SessionId must return StaleOrAlreadyClosed and must leave the replacement live; cleanup
 * carrying the replacement SessionId must then close exactly that session.
 *
 * No network connection, authentication, remote command or feature mutation exists in this gate.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6LMutationSerializationStaleSessionInstrumentedTest {

    @Test
    fun sameServerMutationIsSingleOwnedAndStaleSessionCleanupCannotRemoveReplacement() = runBlocking {
        proveLiveSameServerMutationSerialization()
        proveStaleSessionCleanupCannotRemoveReplacement()
    }

    private fun proveLiveSameServerMutationSerialization() {
        val registry = ServerMutationLeaseRegistry()
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val firstFuture = executor.submit<ServerMutationAcquireResult> {
                ready.countDown()
                check(start.await(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "Timed out waiting for mutation race start" }
                registry.tryAcquire(SERVER_ID, MUTATION_OPERATION_A)
            }
            val secondFuture = executor.submit<ServerMutationAcquireResult> {
                ready.countDown()
                check(start.await(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "Timed out waiting for mutation race start" }
                registry.tryAcquire(SERVER_ID, MUTATION_OPERATION_B)
            }

            assertTrue("Both mutation contenders did not become ready", ready.await(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS))
            start.countDown()

            val results = listOf(
                firstFuture.get(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                secondFuture.get(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS),
            )
            val acquired = results.filterIsInstance<ServerMutationAcquireResult.Acquired>()
            val rejected = results.filterIsInstance<ServerMutationAcquireResult.AlreadyOwned>()
            assertEquals("Exactly one same-server mutation must acquire the live lease", 1, acquired.size)
            assertEquals("Exactly one same-server mutation must be rejected while the lease is owned", 1, rejected.size)

            val winnerLease = acquired.single().lease
            val winnerOperationId = winnerLease.operationId
            val loserOperationId = when (winnerOperationId) {
                MUTATION_OPERATION_A -> MUTATION_OPERATION_B
                MUTATION_OPERATION_B -> MUTATION_OPERATION_A
                else -> throw AssertionError("Unexpected mutation lease owner: $winnerOperationId")
            }

            assertEquals(ServerMutationReleaseResult.RELEASED, registry.release(winnerLease))

            val replacement = registry.tryAcquire(SERVER_ID, loserOperationId)
                as? ServerMutationAcquireResult.Acquired
                ?: throw AssertionError("Former loser could not acquire mutation lease after winner release")
            assertEquals(loserOperationId, replacement.lease.operationId)

            // A stale cleanup from the former owner must not release the replacement lease.
            assertEquals(
                ServerMutationReleaseResult.STALE_OR_ALREADY_RELEASED,
                registry.release(winnerLease),
            )
            assertEquals(
                "Stale release must not make the same Server available while replacement owns it",
                ServerMutationAcquireResult.AlreadyOwned,
                registry.tryAcquire(SERVER_ID, MUTATION_OPERATION_C),
            )
            assertEquals(ServerMutationReleaseResult.RELEASED, registry.release(replacement.lease))
        } finally {
            executor.shutdownNow()
            executor.awaitTermination(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        }
    }

    private suspend fun proveStaleSessionCleanupCannotRemoveReplacement() {
        val startedAt = Instant.now()
        val target = OperationTarget.ServerTarget(SERVER_ID, ACCESS_ID)
        val snapshot = OperationSnapshot(
            operationId = SESSION_OPERATION_ID,
            type = OperationType.QUICK_INSPECT,
            target = target,
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "PHASE4_6L_SESSION_BASE",
                semantics = CheckpointSemantics.READ_ONLY,
                recordedAt = startedAt,
            ),
            startedAt = startedAt,
            updatedAt = startedAt,
        )
        val versioned = VersionedOperationSnapshot(snapshot, SESSION_REVISION)
        val journal = SingleSnapshotJournal(versioned)
        val sessions = ExactSessionRegistry()
        val coordinator = OperationRuntimeCoordinator(
            journal = journal,
            accessRepository = NeverUsedAccessRepository,
            connectionFactory = NeverUsedConnectionFactory,
            sessionRegistry = sessions,
        )

        val plan = ColdStartRecoveryPlan(
            operationId = SESSION_OPERATION_ID,
            target = target,
            expectedRevision = SESSION_REVISION,
            action = RecoveryAction.RECONNECT_EXACT_OWNER,
            automaticAllowed = true,
        )
        val admission = (coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.AUTOMATIC)
            as? RecoveryAdmissionResult.Admitted)?.admission
            ?: throw AssertionError("Exact recovery admission was not granted for session-cleanup fixture")

        try {
            val owner = SessionOwner.Operation(SESSION_OPERATION_ID)
            val oldHandle = WitnessSessionHandle(
                SessionBinding(OLD_SESSION_ID, ACCESS_ID, owner),
            )
            val replacementHandle = WitnessSessionHandle(
                SessionBinding(NEW_SESSION_ID, ACCESS_ID, owner),
            )

            assertEquals(SessionInstallResult.Installed, sessions.install(oldHandle))
            assertEquals(SessionInstallResult.Replaced(OLD_SESSION_ID), sessions.install(replacementHandle))
            assertFalse("Replaced prior session must be closed during exact replacement", oldHandle.isOpen)
            assertEquals(1, oldHandle.closeCount.get())
            assertTrue(replacementHandle.isOpen)

            val staleCleanup = coordinator.closeExactSession(admission, oldHandle.binding)
            assertEquals(ExactRuntimeSessionCloseResult.StaleOrAlreadyClosed, staleCleanup)
            assertSame(
                "Old SessionId cleanup removed the live replacement",
                replacementHandle,
                sessions.find(owner, ACCESS_ID),
            )
            assertTrue(replacementHandle.isOpen)
            assertEquals(0, replacementHandle.closeCount.get())

            val currentCleanup = coordinator.closeExactSession(admission, replacementHandle.binding)
            assertEquals(ExactRuntimeSessionCloseResult.Closed, currentCleanup)
            assertFalse(replacementHandle.isOpen)
            assertEquals(1, replacementHandle.closeCount.get())
            assertEquals(0, sessions.size())
        } finally {
            assertEquals(OperationRuntimeReleaseResult.RELEASED, coordinator.release(admission))
            sessions.close()
        }
    }

    private class WitnessSessionHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        val closeCount = AtomicInteger(0)

        @Volatile
        private var open = true

        override val isOpen: Boolean
            get() = open

        override suspend fun execute(
            command: RemoteCommand,
            config: SshTransportConfig,
        ): SshCommandResult = throw AssertionError("Phase 4.6L must never execute a remote command")

        override fun close() {
            if (open) {
                open = false
                closeCount.incrementAndGet()
            }
        }
    }

    private class SingleSnapshotJournal(
        private val current: VersionedOperationSnapshot,
    ) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.AlreadyExists

        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) {
                OperationJournalResult.Success(current)
            } else {
                OperationJournalResult.NotFound
            }

        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(listOf(current))

        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> =
            throw AssertionError("Phase 4.6L session-cleanup fixture must not mutate OperationJournal")

        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }

    private object NeverUsedAccessRepository : ServerAccessRepository {
        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
            throw AssertionError("Phase 4.6L must not resolve credentials/access during stale-session cleanup")

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> =
            throw AssertionError("Phase 4.6L must not enumerate access records")

        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> =
            throw AssertionError("Phase 4.6L must not delete access records")
    }

    private object NeverUsedConnectionFactory : SshConnectionFactory {
        override suspend fun connect(
            access: ServerAccess,
            owner: SessionOwner,
            config: SshTransportConfig,
        ): SshConnectResult = throw AssertionError("Phase 4.6L must not open a network connection")
    }

    private companion object {
        const val RACE_TIMEOUT_SECONDS = 5L

        val SERVER_ID = ServerId("phase46l-server")
        val ACCESS_ID = ServerAccessId("phase46l-access")
        val MUTATION_OPERATION_A = OperationId("phase46l-mutation-a")
        val MUTATION_OPERATION_B = OperationId("phase46l-mutation-b")
        val MUTATION_OPERATION_C = OperationId("phase46l-mutation-c")
        val SESSION_OPERATION_ID = OperationId("phase46l-session-operation")
        val OLD_SESSION_ID = SessionId("phase46l-old-session")
        val NEW_SESSION_ID = SessionId("phase46l-new-session")
        val SESSION_REVISION = OperationRevision(7)
    }
}
