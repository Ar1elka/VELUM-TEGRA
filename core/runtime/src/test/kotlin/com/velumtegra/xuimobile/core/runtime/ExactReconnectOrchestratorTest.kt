package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.domain.OperationRevision
import java.time.Duration
import java.util.ArrayDeque
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactReconnectOrchestratorTest {
    @Test
    fun `offline observation waits without access lookup or SSH`() = runSuspend {
        val fixture = Fixture()
        val offline = fixture.connectivity.observe(ConnectivityState.OFFLINE)

        val result = fixture.orchestrator.begin(fixture.admission, offline, RetryBudget(maxAttempts = 3))

        assertEquals(ExactReconnectResult.WaitForNetwork, result)
        assertEquals(0, fixture.repository.getCalls)
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `stale observation cannot start access lookup or SSH`() = runSuspend {
        val fixture = Fixture()
        val stale = fixture.connectivity.observe(ConnectivityState.ONLINE)
        fixture.connectivity.observe(ConnectivityState.UNKNOWN)

        val result = fixture.orchestrator.begin(fixture.admission, stale, RetryBudget(maxAttempts = 3))

        assertEquals(ExactReconnectResult.StaleConnectivityGeneration, result)
        assertEquals(0, fixture.repository.getCalls)
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `exact reconnect resolves persisted access and installs exact operation-owned session`() = runSuspend {
        val fixture = Fixture()
        val observation = fixture.connectivity.observe(ConnectivityState.UNKNOWN)
        val handle = fixture.connectedHandle("session-1")
        fixture.factory.results += SshConnectResult.Connected(handle)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))
            as ExactReconnectResult.Connected

        assertEquals(1, fixture.repository.getCalls)
        assertEquals(fixture.access.id, fixture.repository.requestedIds.single())
        assertEquals(SessionOwner.Operation(fixture.operationId), fixture.factory.owners.single())
        assertEquals(fixture.access, fixture.factory.accesses.single())
        assertEquals(handle.binding, result.binding)
        assertEquals(1, result.attemptNumber)
        assertEquals(SessionInstallResult.Installed, result.installation)
        assertTrue(fixture.sessions.find(SessionOwner.Operation(fixture.operationId), fixture.access.id) === handle)
    }

    @Test
    fun `read only reconciliation plan may establish transport but executes no command`() = runSuspend {
        val fixture = Fixture(action = RecoveryAction.RECONCILE_READ_ONLY)
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)
        val handle = fixture.connectedHandle("session-reconcile")
        fixture.factory.results += SshConnectResult.Connected(handle)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 2))

        assertTrue(result is ExactReconnectResult.Connected)
        assertEquals(0, handle.executeCalls)
    }

    @Test
    fun `missing exact access blocks recovery without SSH fallback`() = runSuspend {
        val fixture = Fixture(repositoryResult = RepositoryResult.NotFound)
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))
            as ExactReconnectResult.RecoveryBlocked

        assertEquals(RecoveryBlockReason.EXACT_ACCESS_MISSING, result.reason)
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `access returned for another server is corruption and never connects`() = runSuspend {
        val fixture = Fixture()
        fixture.repository.result = RepositoryResult.Success(
            fixture.access.copy(serverId = ServerId("different-server")),
        )
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))
            as ExactReconnectResult.PreparationFailed

        assertEquals(ReconnectPreparationFailureKind.ACCESS_CORRUPTION, result.kind)
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `network generation changing during access lookup prevents SSH dispatch`() = runSuspend {
        val fixture = Fixture()
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)
        fixture.repository.onGet = { fixture.connectivity.observe(ConnectivityState.UNKNOWN) }

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))

        assertEquals(ExactReconnectResult.StaleConnectivityGeneration, result)
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `network generation changing during successful connect closes unpublished stale session`() = runSuspend {
        val fixture = Fixture()
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)
        val handle = fixture.connectedHandle("session-stale-connect")
        fixture.factory.onConnect = { fixture.connectivity.observe(ConnectivityState.UNKNOWN) }
        fixture.factory.results += SshConnectResult.Connected(handle)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))

        assertEquals(ExactReconnectResult.StaleConnectivityGeneration, result)
        assertTrue(handle.closed)
        assertEquals(0, fixture.sessions.size())
    }

    @Test
    fun `lost runtime admission during successful connect closes session and publishes nothing`() = runSuspend {
        val fixture = Fixture()
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)
        val handle = fixture.connectedHandle("session-lost-admission")
        fixture.factory.onConnect = { fixture.runtimeRegistry.release(fixture.admission.runtimeLease) }
        fixture.factory.results += SshConnectResult.Connected(handle)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))

        assertEquals(ExactReconnectResult.AdmissionLost, result)
        assertTrue(handle.closed)
        assertEquals(0, fixture.sessions.size())
    }

    @Test
    fun `released admission cannot acquire connectivity permit or SSH`() = runSuspend {
        val fixture = Fixture()
        fixture.runtimeRegistry.release(fixture.admission.runtimeLease)
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))

        assertEquals(ExactReconnectResult.AdmissionLost, result)
        assertEquals(0, fixture.repository.getCalls)
        assertEquals(0, fixture.factory.connectCalls)
    }

    @Test
    fun `transport binding mismatch is closed and rejected`() = runSuspend {
        val fixture = Fixture()
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)
        val handle = FakeHandle(
            SessionBinding(
                sessionId = SessionId("session-wrong-owner"),
                serverAccessId = fixture.access.id,
                owner = SessionOwner.WebPanel(WebPanelAccessId("panel")),
            ),
        )
        fixture.factory.results += SshConnectResult.Connected(handle)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))
            as ExactReconnectResult.PreparationFailed

        assertEquals(ReconnectPreparationFailureKind.TRANSPORT_CONTRACT_VIOLATION, result.kind)
        assertTrue(handle.closed)
        assertEquals(0, fixture.sessions.size())
    }

    @Test
    fun `successful reconnect replaces old exact session and closes it`() = runSuspend {
        val fixture = Fixture()
        val owner = SessionOwner.Operation(fixture.operationId)
        val old = fixture.connectedHandle("session-old")
        assertEquals(SessionInstallResult.Installed, fixture.sessions.install(old))
        val fresh = fixture.connectedHandle("session-new")
        fixture.factory.results += SshConnectResult.Connected(fresh)
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 2))
            as ExactReconnectResult.Connected

        assertEquals(SessionInstallResult.Replaced(SessionId("session-old")), result.installation)
        assertTrue(old.closed)
        assertFalse(fresh.closed)
        assertTrue(fixture.sessions.find(owner, fixture.access.id) === fresh)
        assertFalse(fixture.sessions.remove(owner, fixture.access.id, old.binding.sessionId))
        assertTrue(fixture.sessions.find(owner, fixture.access.id) === fresh)
    }

    @Test
    fun `session id collision rejects newcomer without replacing published handle`() = runSuspend {
        val fixture = Fixture()
        val owner = SessionOwner.Operation(fixture.operationId)
        val old = fixture.connectedHandle("same-session-id")
        fixture.sessions.install(old)
        val colliding = fixture.connectedHandle("same-session-id")
        fixture.factory.results += SshConnectResult.Connected(colliding)
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 2))
            as ExactReconnectResult.PreparationFailed

        assertEquals(ReconnectPreparationFailureKind.SESSION_ID_COLLISION, result.kind)
        assertTrue(colliding.closed)
        assertFalse(old.closed)
        assertTrue(fixture.sessions.find(owner, fixture.access.id) === old)
    }

    @Test
    fun `transient failure returns one shot retry bound to same generation and second attempt can connect`() = runSuspend {
        val fixture = Fixture()
        fixture.factory.results += SshConnectResult.Failed(SshConnectFailure.Unreachable("temporary"))
        fixture.factory.results += SshConnectResult.Connected(fixture.connectedHandle("session-retry"))
        val observation = fixture.connectivity.observe(ConnectivityState.UNKNOWN)

        val first = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))
            as ExactReconnectResult.RetryPermitted
        assertEquals(2, first.permit.nextAttemptNumber)
        assertEquals(observation.generation, first.permit.generation)

        val second = fixture.orchestrator.retry(first.permit) as ExactReconnectResult.Connected
        assertEquals(2, second.attemptNumber)
        assertEquals(2, fixture.factory.connectCalls)

        assertEquals(
            ExactReconnectResult.RetryPermitAlreadyConsumed,
            fixture.orchestrator.retry(first.permit),
        )
        assertEquals(2, fixture.factory.connectCalls)
    }

    @Test
    fun `new connectivity generation invalidates old retry without another access lookup or connect`() = runSuspend {
        val fixture = Fixture()
        fixture.factory.results += SshConnectResult.Failed(SshConnectFailure.Unreachable("temporary"))
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)
        val first = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 3))
            as ExactReconnectResult.RetryPermitted
        val getsAfterFirst = fixture.repository.getCalls
        val connectsAfterFirst = fixture.factory.connectCalls

        fixture.connectivity.observe(ConnectivityState.UNKNOWN)
        val retry = fixture.orchestrator.retry(first.permit)

        assertEquals(ExactReconnectResult.StaleConnectivityGeneration, retry)
        assertEquals(getsAfterFirst, fixture.repository.getCalls)
        assertEquals(connectsAfterFirst, fixture.factory.connectCalls)
    }

    @Test
    fun `attempt limit closes retry sequence after first transient failure when max attempts is one`() = runSuspend {
        val fixture = Fixture()
        fixture.factory.results += SshConnectResult.Failed(SshConnectFailure.Unreachable("temporary"))
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 1))
            as ExactReconnectResult.Failed

        assertEquals(RetryDeniedReason.ATTEMPT_LIMIT_REACHED, result.retryDecision.reason)
    }

    @Test
    fun `deadline closes retry sequence using monotonic elapsed time`() = runSuspend {
        var nowNanos = 0L
        val fixture = Fixture(nanoTime = { nowNanos })
        fixture.factory.onConnect = { nowNanos = Duration.ofSeconds(2).toNanos() }
        fixture.factory.results += SshConnectResult.Failed(SshConnectFailure.Unreachable("slow failure"))
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(
            fixture.admission,
            observation,
            RetryBudget(maxAttempts = 5, maxElapsed = Duration.ofSeconds(1)),
        ) as ExactReconnectResult.Failed

        assertEquals(RetryDeniedReason.DEADLINE_REACHED, result.retryDecision.reason)
    }

    @Test
    fun `host identity mismatch becomes recovery block and never gets retry permit`() = runSuspend {
        val fixture = Fixture()
        val mismatch = SshConnectFailure.HostIdentityMismatch("expected", "presented")
        fixture.factory.results += SshConnectResult.Failed(mismatch)
        val observation = fixture.connectivity.observe(ConnectivityState.ONLINE)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 5))
            as ExactReconnectResult.RecoveryBlocked

        assertEquals(RecoveryBlockReason.HOST_IDENTITY_MISMATCH, result.reason)
        assertEquals(mismatch, result.transportFailure)
    }

    @Test
    fun `secret unavailable is non retryable and never triggers credential fallback`() = runSuspend {
        val fixture = Fixture()
        val failure = SshConnectFailure.SecretUnavailable("configured secret unavailable")
        fixture.factory.results += SshConnectResult.Failed(failure)
        val observation = fixture.connectivity.observe(ConnectivityState.UNKNOWN)

        val result = fixture.orchestrator.begin(fixture.admission, observation, RetryBudget(maxAttempts = 5))
            as ExactReconnectResult.Failed

        assertEquals(RetryDeniedReason.FAILURE_NOT_RETRYABLE, result.retryDecision.reason)
        assertEquals(RetryFailureCategory.CREDENTIAL_UNAVAILABLE, result.retryDecision.failureCategory)
        assertEquals(1, fixture.factory.connectCalls)
        assertEquals(1, fixture.repository.getCalls)
    }

    private class Fixture(
        action: RecoveryAction = RecoveryAction.RECONNECT_EXACT_OWNER,
        repositoryResult: RepositoryResult<ServerAccess>? = null,
        nanoTime: () -> Long = { 0L },
    ) {
        val operationId = OperationId("op-reconnect")
        val serverId = ServerId("server-reconnect")
        val accessId = ServerAccessId("access-reconnect")
        val target = OperationTarget.ServerTarget(serverId, accessId)
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("127.0.0.1", 22),
            username = "velum",
            auth = SshAuthRef.Password(SecretId("secret-reconnect")),
            pinnedHostKey = HostKeyFingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        val runtimeRegistry = OperationRuntimeLeaseRegistry()
        private val lease = (runtimeRegistry.tryAcquire(operationId) as OperationRuntimeAcquireResult.Acquired).lease
        val admission = RecoveryRuntimeAdmission(
            plan = ColdStartRecoveryPlan(
                operationId = operationId,
                target = target,
                expectedRevision = OperationRevision(1),
                action = action,
                automaticAllowed = true,
            ),
            runtimeLease = lease,
        )
        val connectivity = ConnectivityReconnectPermitGate()
        val repository = FakeServerAccessRepository(repositoryResult ?: RepositoryResult.Success(access))
        val factory = FakeConnectionFactory()
        val sessions = ExactSessionRegistry()
        val orchestrator = ExactReconnectOrchestrator(
            runtimeRegistry = runtimeRegistry,
            connectivityGate = connectivity,
            accessRepository = repository,
            connectionFactory = factory,
            sessionRegistry = sessions,
            nanoTime = nanoTime,
        )

        fun connectedHandle(sessionId: String): FakeHandle = FakeHandle(
            SessionBinding(
                sessionId = SessionId(sessionId),
                serverAccessId = access.id,
                owner = SessionOwner.Operation(operationId),
            ),
        )
    }

    private class FakeServerAccessRepository(
        var result: RepositoryResult<ServerAccess>,
    ) : ServerAccessRepository {
        var getCalls = 0
        val requestedIds = mutableListOf<ServerAccessId>()
        var onGet: (() -> Unit)? = null

        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> {
            getCalls += 1
            requestedIds += serverAccessId
            onGet?.invoke()
            return result
        }

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> =
            RepositoryResult.StorageFailure("not used")

        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> =
            RepositoryResult.StorageFailure("not used")
    }

    private class FakeConnectionFactory : SshConnectionFactory {
        val results = ArrayDeque<SshConnectResult>()
        var connectCalls = 0
        val accesses = mutableListOf<ServerAccess>()
        val owners = mutableListOf<SessionOwner>()
        var onConnect: (() -> Unit)? = null

        override suspend fun connect(
            access: ServerAccess,
            owner: SessionOwner,
            config: SshTransportConfig,
        ): SshConnectResult {
            connectCalls += 1
            accesses += access
            owners += owner
            onConnect?.invoke()
            return results.pollFirst()
                ?: SshConnectResult.Failed(SshConnectFailure.Unexpected("no fake result"))
        }
    }

    private class FakeHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        var closed = false
        var executeCalls = 0

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(
            command: com.velumtegra.xuimobile.core.ssh.RemoteCommand,
            config: SshTransportConfig,
        ): com.velumtegra.xuimobile.core.ssh.SshCommandResult {
            executeCalls += 1
            error("Reconnect orchestrator must never execute commands")
        }

        override fun close() {
            closed = true
        }
    }

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(
            object : Continuation<T> {
                override val context = EmptyCoroutineContext
                override fun resumeWith(result: Result<T>) {
                    outcome = result
                }
            },
        )
        return requireNotNull(outcome) { "Test coroutine did not complete synchronously" }.getOrThrow()
    }
}
