package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.ConnectivityReconnectPermitGate
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

class ExactOperationHostRuntimeTransportBridgeTest {
    @Test
    fun beginUsesCurrentConnectivityAndExactRuntimeToken() {
        val observation = observation(ConnectivityState.ONLINE)
        val runtimeToken = FakeRuntimeToken("runtime-exact")
        val budget = RetryBudget(maxAttempts = 3)
        val port = FakeTransportPort(
            observation = observation,
            beginResult = ExactOperationHostTransportPortResult.WaitForNetwork,
        )
        val bridge = ExactOperationHostRuntimeTransportBridge(port)
        val binding = ExactOperationHostRuntimeBinding(
            operationId = OperationId("op-exact"),
            token = runtimeToken,
        )

        val result = runSuspend { bridge.begin(binding, budget) }

        assertSame(ExactOperationHostTransportResult.WaitForNetwork, result)
        assertSame(runtimeToken, port.seenRuntimeToken)
        assertSame(observation, port.seenObservation)
        assertSame(budget, port.seenBudget)
        assertEquals(1, port.beginCalls)
        assertEquals(0, port.retryCalls)
    }

    @Test
    fun retryUsesOnlyOpaqueExactPermitToken() {
        val retryToken = FakeRetryToken("retry-exact")
        val port = FakeTransportPort(
            retryResult = ExactOperationHostTransportPortResult.AdmissionLost,
        )
        val bridge = ExactOperationHostRuntimeTransportBridge(port)
        val permit = ExactOperationHostReconnectRetryPermit(
            operationId = OperationId("op-retry"),
            generation = 7L,
            nextAttemptNumber = 2,
            token = retryToken,
        )

        val result = runSuspend { bridge.retry(permit) }

        assertSame(ExactOperationHostTransportResult.AdmissionLost, result)
        assertSame(retryToken, port.seenRetryToken)
        assertEquals(0, port.beginCalls)
        assertEquals(1, port.retryCalls)
    }

    @Test
    fun retryPermittedResultPreservesExactOperationGenerationAndAttempt() {
        val operationId = OperationId("op-permit")
        val retryToken = FakeRetryToken("retry-token")
        val failure = SshConnectFailure.Unreachable("temporary")
        val port = FakeTransportPort(
            beginResult = ExactOperationHostTransportPortResult.RetryPermitted(
                failure = failure,
                operationId = operationId,
                generation = 11L,
                nextAttemptNumber = 3,
                token = retryToken,
            ),
        )
        val bridge = ExactOperationHostRuntimeTransportBridge(port)

        val result = runSuspend {
            bridge.begin(
                binding = ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime")),
                budget = RetryBudget(maxAttempts = 4),
            )
        }

        assertTrue(result is ExactOperationHostTransportResult.RetryPermitted)
        result as ExactOperationHostTransportResult.RetryPermitted
        assertSame(failure, result.failure)
        assertEquals(operationId, result.permit.operationId)
        assertEquals(11L, result.permit.generation)
        assertEquals(3, result.permit.nextAttemptNumber)
        assertSame(retryToken, result.permit.token)
    }

    @Test
    fun retryPermitForDifferentOperationFailsClosed() {
        val requested = OperationId("op-requested")
        val port = FakeTransportPort(
            beginResult = ExactOperationHostTransportPortResult.RetryPermitted(
                failure = SshConnectFailure.Unreachable("temporary"),
                operationId = OperationId("op-other"),
                generation = 2L,
                nextAttemptNumber = 2,
                token = FakeRetryToken("wrong-owner"),
            ),
        )
        val bridge = ExactOperationHostRuntimeTransportBridge(port)

        val result = runSuspend {
            bridge.begin(
                ExactOperationHostRuntimeBinding(requested, FakeRuntimeToken("runtime")),
                RetryBudget(maxAttempts = 2),
            )
        }

        assertTrue(result is ExactOperationHostTransportResult.ContractViolation)
    }

    @Test
    fun typedRecoveryBlockIsNotCollapsedIntoGenericFailure() {
        val transportFailure = SshConnectFailure.HostIdentityMismatch(
            expectedFingerprint = "SHA256:expected",
            presentedFingerprint = "SHA256:presented",
        )
        val port = FakeTransportPort(
            beginResult = ExactOperationHostTransportPortResult.RecoveryBlocked(
                reason = RecoveryBlockReason.HOST_IDENTITY_MISMATCH,
                transportFailure = transportFailure,
            ),
        )
        val bridge = ExactOperationHostRuntimeTransportBridge(port)

        val result = runSuspend {
            bridge.begin(
                ExactOperationHostRuntimeBinding(
                    OperationId("op-blocked"),
                    FakeRuntimeToken("runtime"),
                ),
                RetryBudget(maxAttempts = 1),
            )
        }

        assertEquals(
            ExactOperationHostTransportResult.RecoveryBlocked(
                reason = RecoveryBlockReason.HOST_IDENTITY_MISMATCH,
                transportFailure = transportFailure,
            ),
            result,
        )
    }

    @Test
    fun blankRuntimeBindingNeverTouchesTransportPort() {
        val port = FakeTransportPort()
        val bridge = ExactOperationHostRuntimeTransportBridge(port)

        val result = runSuspend {
            bridge.begin(
                ExactOperationHostRuntimeBinding(
                    OperationId("   "),
                    FakeRuntimeToken("invalid"),
                ),
                RetryBudget(maxAttempts = 1),
            )
        }

        assertTrue(result is ExactOperationHostTransportResult.ContractViolation)
        assertEquals(0, port.beginCalls)
        assertEquals(0, port.retryCalls)
    }


    @Test
    fun closeSessionUsesExactRuntimeTokenAndSessionBinding() {
        val operationId = OperationId("op-close")
        val runtimeToken = FakeRuntimeToken("runtime-close")
        val session = SessionBinding(
            sessionId = SessionId("session-close"),
            serverAccessId = ServerAccessId("access-close"),
            owner = SessionOwner.Operation(operationId),
        )
        val port = FakeTransportPort(
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val bridge = ExactOperationHostRuntimeTransportBridge(port)

        val result = bridge.closeSession(
            ExactOperationHostRuntimeBinding(operationId, runtimeToken),
            session,
        )

        assertSame(ExactOperationHostSessionCloseResult.Closed, result)
        assertSame(runtimeToken, port.seenCloseRuntimeToken)
        assertSame(session, port.seenCloseBinding)
        assertEquals(1, port.closeCalls)
    }

    @Test
    fun closeSessionForDifferentOperationFailsClosedBeforePort() {
        val port = FakeTransportPort()
        val bridge = ExactOperationHostRuntimeTransportBridge(port)

        val result = bridge.closeSession(
            ExactOperationHostRuntimeBinding(OperationId("op-a"), FakeRuntimeToken("runtime-a")),
            SessionBinding(
                sessionId = SessionId("session-b"),
                serverAccessId = ServerAccessId("access-b"),
                owner = SessionOwner.Operation(OperationId("op-b")),
            ),
        )

        assertTrue(result is ExactOperationHostSessionCloseResult.ContractViolation)
        assertEquals(0, port.closeCalls)
    }

    @Test(expected = IllegalArgumentException::class)
    fun retryPermitCannotRepresentInitialAttempt() {
        ExactOperationHostReconnectRetryPermit(
            operationId = OperationId("op"),
            generation = 1L,
            nextAttemptNumber = 1,
            token = FakeRetryToken("invalid"),
        )
    }

    private fun observation(state: ConnectivityState): ConnectivityObservation =
        ConnectivityReconnectPermitGate(state).snapshot()

    private class FakeTransportPort(
        private val observation: ConnectivityObservation =
            ConnectivityReconnectPermitGate(ConnectivityState.UNKNOWN).snapshot(),
        private val beginResult: ExactOperationHostTransportPortResult =
            ExactOperationHostTransportPortResult.WaitForNetwork,
        private val retryResult: ExactOperationHostTransportPortResult =
            ExactOperationHostTransportPortResult.RetryPermitAlreadyConsumed,
        private val closeResult: ExactOperationHostSessionClosePortResult =
            ExactOperationHostSessionClosePortResult.StaleOrAlreadyClosed,
    ) : ExactOperationHostRuntimeTransportPort {
        var beginCalls = 0
        var retryCalls = 0
        var closeCalls = 0
        var seenRuntimeToken: ExactOperationHostRuntimeToken? = null
        var seenObservation: ConnectivityObservation? = null
        var seenBudget: RetryBudget? = null
        var seenRetryToken: ExactOperationHostReconnectRetryToken? = null
        var seenCloseRuntimeToken: ExactOperationHostRuntimeToken? = null
        var seenCloseBinding: SessionBinding? = null

        override fun connectivitySnapshot(): ConnectivityObservation = observation

        override suspend fun begin(
            runtimeToken: ExactOperationHostRuntimeToken,
            observation: ConnectivityObservation,
            budget: RetryBudget,
        ): ExactOperationHostTransportPortResult {
            beginCalls += 1
            seenRuntimeToken = runtimeToken
            seenObservation = observation
            seenBudget = budget
            return beginResult
        }

        override suspend fun retry(
            retryToken: ExactOperationHostReconnectRetryToken,
        ): ExactOperationHostTransportPortResult {
            retryCalls += 1
            seenRetryToken = retryToken
            return retryResult
        }

        override suspend fun executeDiscovery(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): com.velumtegra.xuimobile.core.runtime.DiscoveryRuntimeExecutionResult =
            com.velumtegra.xuimobile.core.runtime.DiscoveryRuntimeExecutionResult.NotDiscoveryOperation(
                com.velumtegra.xuimobile.core.model.OperationType.QUICK_INSPECT,
            )

        override suspend fun executeManagementQuickInspect(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult =
            com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult.NotQuickInspectOperation(
                com.velumtegra.xuimobile.core.model.OperationType.DEEP_DIAGNOSTIC,
            )

        override suspend fun executeDeepDiagnostic(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult =
            com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult.NotDeepDiagnosticOperation(
                com.velumtegra.xuimobile.core.model.OperationType.INSTALL,
            )

        override fun closeSession(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): ExactOperationHostSessionClosePortResult {
            closeCalls += 1
            seenCloseRuntimeToken = runtimeToken
            seenCloseBinding = binding
            return closeResult
        }
    }

    private data class FakeRuntimeToken(val value: String) : ExactOperationHostRuntimeToken
    private data class FakeRetryToken(val value: String) : ExactOperationHostReconnectRetryToken

    private fun <T> runSuspend(block: suspend () -> T): T {
        var result: Result<T>? = null
        block.startCoroutine(
            object : Continuation<T> {
                override val context = EmptyCoroutineContext
                override fun resumeWith(resumeResult: Result<T>) {
                    result = resumeResult
                }
            },
        )
        return checkNotNull(result).getOrThrow()
    }
}

