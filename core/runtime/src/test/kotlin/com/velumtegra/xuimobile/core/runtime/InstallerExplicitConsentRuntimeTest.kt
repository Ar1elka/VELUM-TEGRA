package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.UpdateServerArchitecture
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.CapturedOutput
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.FreshInstallPrerequisiteGap
import com.velumtegra.xuimobile.core.ssh.FreshInstallReadinessFacts
import com.velumtegra.xuimobile.core.ssh.FreshInstallReadinessObservationResult
import com.velumtegra.xuimobile.core.ssh.FreshInstallUncertainty
import com.velumtegra.xuimobile.core.ssh.InstallerReconciliationReason
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionResult
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshCommandResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerExplicitConsentRuntimeTest {
    @Test
    fun `exact consent connects then re-observes readiness on the same session before the only write`() = runSuspend {
        val f = Fixture()
        f.register()
        assertEquals(InstallerRuntimePreparationResult.TransportRequired, f.coordinator.prepareTransport(f.admission))

        val result = f.coordinator.execute(f.admission, f.binding)

        // Detached hand-off: its own result, no immediate post-install wait, legacy synchronous executor unused.
        val launched = result as InstallerRuntimeExecutionResult.DetachedWorkerLaunched
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, launched.durable.snapshot.checkpoint.semantics)
        assertEquals(0, f.postInstallCalls)
        assertEquals(0, f.synchronousCalls)
        assertEquals(listOf("readiness", "mutation"), f.order)
        assertSame(f.handle, f.readinessSessions.single())
        assertEquals(FreshInstallScope(f.operationId, f.serverId, f.accessId), f.readinessScopes.single())
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, f.journal.current.snapshot.checkpoint.semantics)
        // One-shot: gone after use.
        assertFalse(f.coordinator.discardExplicitInstallConsent(f.operationId))
    }

    @Test
    fun `no consent or wrong revision or expired consent never permits transport`() = runSuspend {
        val f = Fixture()
        assertEquals(InstallerRuntimePreparationResult.FreshAuthorizationRequired, f.coordinator.prepareTransport(f.admission))

        f.register(revision = OperationRevision(f.journal.current.revision.value + 1))
        assertTrue(f.coordinator.prepareTransport(f.admission) is InstallerRuntimePreparationResult.ContractViolation)
        assertEquals(InstallerRuntimePreparationResult.FreshAuthorizationRequired, f.coordinator.prepareTransport(f.admission))

        f.register()
        f.now = f.now.plusSeconds(61)
        assertEquals(InstallerRuntimePreparationResult.FreshAuthorizationExpired, f.coordinator.prepareTransport(f.admission))
        assertEquals(InstallerRuntimePreparationResult.FreshAuthorizationRequired, f.coordinator.prepareTransport(f.admission))
        assertEquals(0, f.mutationCalls)
    }

    @Test
    fun `registration rejects long ttl and conflicting duplicate`() = runSuspend {
        val f = Fixture()
        val tooLong = f.consent().copy(validUntil = f.now.plusSeconds(121))
        assertTrue(f.coordinator.registerExplicitInstallConsent(tooLong) is InstallerExplicitConsentRegistrationResult.Rejected)
        assertEquals(InstallerExplicitConsentRegistrationResult.Registered, f.coordinator.registerExplicitInstallConsent(f.consent()))
        assertEquals(InstallerExplicitConsentRegistrationResult.AlreadyRegistered, f.coordinator.registerExplicitInstallConsent(f.consent()))
        assertEquals(
            InstallerExplicitConsentRegistrationResult.Conflict,
            f.coordinator.registerExplicitInstallConsent(f.consent().copy(validUntil = f.now.plusSeconds(30))),
        )
    }

    @Test
    fun `non ready readiness refuses before any write and spends the consent`() = runSuspend {
        listOf(
            FreshInstallReadinessObservationResult.PrerequisitesUnmet(setOf(FreshInstallPrerequisiteGap.NotDirectRoot)),
            FreshInstallReadinessObservationResult.Indeterminate(setOf(FreshInstallUncertainty.SessionChanged), emptySet()),
        ).forEach { observed ->
            val f = Fixture()
            f.readiness = { observed }
            f.register()
            val result = f.coordinator.execute(f.admission, f.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused
            assertEquals(FreshInstallRefusalReason.READINESS_NOT_READY, result.reason)
            assertEquals(observed, result.readiness)
            assertEquals(0, f.mutationCalls)
            assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, f.journal.current.snapshot.checkpoint.semantics)
            assertEquals(InstallerRuntimePreparationResult.FreshAuthorizationRequired, f.coordinator.prepareTransport(f.admission))
            assertEquals(InstallerRuntimeExecutionResult.FreshAuthorizationRequired, f.coordinator.execute(f.admission, f.binding))
        }
    }

    @Test
    fun `ready for a different scope is refused`() = runSuspend {
        val f = Fixture()
        f.readiness = { scope -> f.ready(FreshInstallScope(scope.operationId, ServerId("other"), scope.serverAccessId)) }
        f.register()
        val result = f.coordinator.execute(f.admission, f.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused
        assertEquals(FreshInstallRefusalReason.READINESS_SCOPE_MISMATCH, result.reason)
        assertEquals(0, f.mutationCalls)
    }

    @Test
    fun `ttl elapsing during the read only suspend refuses`() = runSuspend {
        val f = Fixture()
        f.readiness = { scope -> f.now = f.now.plusSeconds(61); f.ready(scope) }
        f.register()
        val result = f.coordinator.execute(f.admission, f.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused
        assertEquals(FreshInstallRefusalReason.CONSENT_EXPIRED, result.reason)
        assertEquals(0, f.mutationCalls)
    }

    @Test
    fun `changed or missing access and pin mismatch refuse`() = runSuspend {
        val changed = Fixture().also { it.currentAccess = it.access.copy(username = "other"); it.register() }
        assertEquals(
            FreshInstallRefusalReason.ACCESS_CHANGED,
            (changed.coordinator.execute(changed.admission, changed.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused).reason,
        )
        val missing = Fixture().also { it.currentAccess = null; it.register() }
        assertEquals(
            FreshInstallRefusalReason.ACCESS_UNAVAILABLE,
            (missing.coordinator.execute(missing.admission, missing.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused).reason,
        )
        val pin = Fixture(sessionPinHex = "00".repeat(32)).also { it.register() }
        assertEquals(
            FreshInstallRefusalReason.SESSION_PIN_UNVERIFIED,
            (pin.coordinator.execute(pin.admission, pin.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused).reason,
        )
        listOf(changed, missing, pin).forEach { assertEquals(0, it.mutationCalls); assertEquals(0, it.readinessScopes.size) }
    }

    @Test
    fun `access changing session closing or journal moving during readiness refuse`() = runSuspend {
        val access = Fixture()
        access.readiness = { scope -> access.currentAccess = access.access.copy(username = "other"); access.ready(scope) }
        access.register()
        assertEquals(
            FreshInstallRefusalReason.ACCESS_CHANGED,
            (access.coordinator.execute(access.admission, access.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused).reason,
        )
        val closing = Fixture()
        closing.readiness = { scope -> closing.handle.close(); closing.ready(scope) }
        closing.register()
        assertEquals(
            FreshInstallRefusalReason.SESSION_CHANGED,
            (closing.coordinator.execute(closing.admission, closing.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused).reason,
        )
        val moving = Fixture()
        moving.readiness = { scope -> moving.journal.bump(); moving.ready(scope) }
        moving.register()
        assertEquals(
            FreshInstallRefusalReason.JOURNAL_CHANGED,
            (moving.coordinator.execute(moving.admission, moving.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused).reason,
        )
        listOf(access, closing, moving).forEach { assertEquals(0, it.mutationCalls) }
    }

    @Test
    fun `session closing during the last access read refuses before dispatch`() = runSuspend {
        val f = Fixture()
        f.readiness = { scope ->
            f.onAccessRead = { f.handle.close() }
            f.ready(scope)
        }
        f.register()
        val result = f.coordinator.execute(f.admission, f.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused
        assertEquals(FreshInstallRefusalReason.SESSION_CHANGED, result.reason)
        assertEquals(0, f.mutationCalls)
    }

    @Test
    fun `lost runtime admission during readiness refuses`() = runSuspend {
        val f = Fixture()
        f.readiness = { scope -> f.runtimeRegistry.release(f.runtimeLease); f.ready(scope) }
        f.register()
        val result = f.coordinator.execute(f.admission, f.binding) as InstallerRuntimeExecutionResult.FreshInstallRefused
        assertEquals(FreshInstallRefusalReason.ADMISSION_LOST, result.reason)
        assertEquals(0, f.mutationCalls)
    }

    @Test
    fun `durable barrier and competing lease block before the consent is consumed`() = runSuspend {
        val f = Fixture()
        f.register()
        val competing = f.serverMutationRegistry.tryAcquire(f.serverId, OperationId("other")) as ServerMutationAcquireResult.Acquired
        assertEquals(InstallerRuntimeExecutionResult.ServerMutationAlreadyOwned, f.coordinator.execute(f.admission, f.binding))
        f.serverMutationRegistry.release(competing.lease)
        assertEquals(0, f.readinessScopes.size)
        assertEquals(InstallerRuntimePreparationResult.TransportRequired, f.coordinator.prepareTransport(f.admission))
    }

    @Test
    fun `consent never survives past the mutation boundary`() = runSuspend {
        val f = Fixture()
        f.register()
        f.journal.setSemantics(CheckpointSemantics.MUTATION_IN_FLIGHT)
        assertEquals(InstallerRuntimePreparationResult.TransportRequired, f.coordinator.prepareTransport(f.admission))
        assertFalse(f.coordinator.discardExplicitInstallConsent(f.operationId))
    }

    @Test
    fun `unknown launch outcome keeps the barrier and is never replayed or awaited`() = runSuspend {
        val f = Fixture()
        f.launchResult = { current ->
            InstallerSshExecutionResult.ReconciliationRequired(
                durable = current,
                reason = InstallerReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
                reconciliationCheckpointRecorded = true,
            )
        }
        f.register()
        val result = f.coordinator.execute(f.admission, f.binding) as InstallerRuntimeExecutionResult.MutationExecution
        assertTrue(result.result is InstallerSshExecutionResult.ReconciliationRequired)
        assertEquals(1, f.mutationCalls)
        assertEquals(0, f.postInstallCalls)
        // Consent is spent: no second launch is possible.
        assertEquals(InstallerRuntimeExecutionResult.FreshAuthorizationRequired, f.coordinator.execute(f.admission, f.binding))
        assertEquals(1, f.mutationCalls)
    }

    private class Fixture(sessionPinHex: String? = null) {
        var now: Instant = Instant.parse("2026-11-06T12:00:00Z")
        val operationId = OperationId("explicit-install")
        val serverId = ServerId("explicit-server")
        val accessId = ServerAccessId("explicit-access")
        private val pin = CanonicalHostKeyFingerprint.fromRawHostKey(byteArrayOf(1, 2, 3))
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.10", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("secret-ref")),
            pinnedHostKey = pin.asModel(),
        )
        var currentAccess: ServerAccess? = access
        var onAccessRead: () -> Unit = {}
        val journal = FakeJournal(
            VersionedOperationSnapshot(
                OperationSnapshot(
                    operationId = operationId,
                    type = OperationType.INSTALL,
                    target = OperationTarget.ServerTarget(serverId, accessId),
                    status = OperationStatus.RUNNING,
                    checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(60)),
                    startedAt = now.minusSeconds(60),
                    updatedAt = now.minusSeconds(60),
                ),
                OperationRevision(3),
            ),
        )
        val runtimeRegistry = OperationRuntimeLeaseRegistry()
        val runtimeLease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
        val admission = RecoveryRuntimeAdmission(
            ColdStartRecoveryPlan(operationId, journal.current.snapshot.target, journal.current.revision, RecoveryAction.RECONNECT_EXACT_OWNER, true),
            runtimeLease,
        )
        val binding = SessionBinding(SessionId("explicit-session"), accessId, SessionOwner.Operation(operationId))
        val handle = VerifiedHandle(binding, sessionPinHex ?: pin.asHexSha256())
        private val sessionRegistry = ExactSessionRegistry().also { it.install(handle) }
        val serverMutationRegistry = ServerMutationLeaseRegistry()
        val order = mutableListOf<String>()
        val readinessSessions = mutableListOf<SshSessionHandle>()
        val readinessScopes = mutableListOf<FreshInstallScope>()
        var mutationCalls = 0
        var synchronousCalls = 0
        var postInstallCalls = 0
        var launchResult: ((VersionedOperationSnapshot) -> InstallerSshExecutionResult)? = null
        var readiness: (FreshInstallScope) -> FreshInstallReadinessObservationResult = { ready(it) }

        fun ready(scope: FreshInstallScope) = FreshInstallReadinessObservationResult.Ready(
            FreshInstallReadinessFacts(
                scope, DiscoveryPlatform("ubuntu", "24.04"), UpdateServerArchitecture.AMD64,
                FreshInstallPrivilegeCapability.DIRECT_ROOT, FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                now,
            ),
        )

        val coordinator = InstallerRuntimeCoordinator(
            journal = journal,
            runtimeRegistry = runtimeRegistry,
            sessionRegistry = sessionRegistry,
            serverMutationRegistry = serverMutationRegistry,
            entryRegistry = InstallerRuntimeEntryRegistry(),
            mutationExecutor = InstallerMutationExecutionPort { _, _, _ ->
                synchronousCalls += 1
                error("explicit consent must not use the synchronous executor")
            },
            detachedLaunch = InstallerDetachedLaunchPort { _, current, _ ->
                mutationCalls += 1
                order += "mutation"
                launchResult?.invoke(current) ?: run {
                    val at = now.plusSeconds(1)
                    val next = current.snapshot.copy(
                        checkpoint = OperationCheckpoint("VERIFYING", CheckpointSemantics.POST_VERIFY_REQUIRED, at),
                        updatedAt = at,
                    )
                    InstallerSshExecutionResult.DetachedWorkerLaunched(
                        (journal.advance(operationId, current.revision, next) as OperationJournalResult.Success).value,
                    )
                }
            },
            postInstall = object : InstallerPostInstallRuntimePort {
                override suspend fun reconcileAndPublish(current: VersionedOperationSnapshot, session: SshSessionHandle): InstallerPostInstallCoordinatorResult {
                    postInstallCalls += 1
                    return InstallerPostInstallCoordinatorResult.AwaitingWorker(current)
                }

                override suspend fun finishCommitted(current: VersionedOperationSnapshot) =
                    InstallerPostInstallCoordinatorResult.Succeeded(current, XuiInstallationId("x"))
            },
            now = { now },
            accessPort = InstallerFreshAccessPort { onAccessRead(); currentAccess },
            readinessPort = InstallerFreshReadinessPort { scope, session ->
                order += "readiness"
                readinessSessions += session
                readinessScopes += scope
                readiness(scope)
            },
        )

        fun consent() = InstallerExplicitInstallConsent(
            operationId, journal.current.revision, access, grantedAt = now, validUntil = now.plusSeconds(60),
        )

        fun register(revision: OperationRevision = journal.current.revision) {
            coordinator.registerExplicitInstallConsent(consent().copy(expectedRevision = revision))
        }
    }

    private class VerifiedHandle(
        override val binding: SessionBinding,
        override val verifiedHostKeySha256: String,
    ) : VerifiedHostKeySshSessionHandle {
        private var closed = false
        override val isOpen: Boolean get() = !closed
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig) = SshCommandResult(
            CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess, CapturedOutput.EMPTY, CapturedOutput.EMPTY,
        )
        override fun close() { closed = true }
    }

    private class FakeJournal(var current: VersionedOperationSnapshot) : OperationJournal {
        fun bump() { current = VersionedOperationSnapshot(current.snapshot, OperationRevision(current.revision.value + 1)) }
        fun setSemantics(s: CheckpointSemantics) {
            current = VersionedOperationSnapshot(
                current.snapshot.copy(checkpoint = OperationCheckpoint("X", s, current.snapshot.updatedAt)), current.revision,
            )
        }
        override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> =
            OperationJournalResult.StorageFailure("not used")
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(listOf(current))
        override suspend fun advance(
            operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }
}

private fun <T> runSuspend(block: suspend () -> T): T {
    var result: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(value: Result<T>) { result = value }
    })
    return result!!.getOrThrow()
}
