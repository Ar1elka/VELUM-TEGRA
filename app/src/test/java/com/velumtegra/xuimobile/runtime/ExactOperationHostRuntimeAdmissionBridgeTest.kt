package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.runtime.ColdStartRecoveryPlan
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryAction
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionAuthority
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapFailure
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapFailureKind
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapItem
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapResult
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactOperationHostRuntimeAdmissionBridgeTest {
    @Test
    fun exactPlannedOperationUsesExplicitUserAdmission() {
        val operationId = OperationId("op-exact")
        val plan = plan(operationId)
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(plan)),
            ),
            admissionResult = ExactOperationHostPortAdmissionResult.Admitted(FakeRuntimeToken("token-exact")),
        )
        val bridge = bridge(port, RecoveryExitProvenance.USER_REQUESTED_STOP)

        val result = runSuspend { bridge.bind(operationId) }

        assertTrue(result is ExactOperationHostRuntimeBindResult.Bound)
        assertEquals(operationId, (result as ExactOperationHostRuntimeBindResult.Bound).binding.operationId)
        assertEquals(RecoveryExitProvenance.USER_REQUESTED_STOP, port.seenExitProvenance)
        assertEquals(RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED, port.seenAuthority)
        assertSame(plan, port.seenPlan)
    }

    @Test
    fun blankOperationIdNeverTouchesRuntime() {
        val port = FakeRuntimePort()
        val result = runSuspend { bridge(port).bind(OperationId("   ")) }

        assertSame(ExactOperationHostRuntimeBindResult.InvalidOperationId, result)
        assertEquals(0, port.bootstrapCalls)
        assertEquals(0, port.admitCalls)
    }

    @Test
    fun missingExactOperationDoesNotAdmitAnotherOperation() {
        val requested = OperationId("op-requested")
        val other = plan(OperationId("op-other"))
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(other)),
            ),
        )

        val result = runSuspend { bridge(port).bind(requested) }

        assertEquals(ExactOperationHostRuntimeBindResult.OperationNotNonTerminal(requested), result)
        assertEquals(0, port.admitCalls)
    }

    @Test
    fun duplicateExactBootstrapItemsFailClosedBeforeAdmission() {
        val operationId = OperationId("op-duplicate")
        val planned = RecoveryBootstrapItem.Planned(plan(operationId))
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(listOf(planned, planned)),
        )

        val result = runSuspend { bridge(port).bind(operationId) }

        assertTrue(result is ExactOperationHostRuntimeBindResult.ContractViolation)
        assertEquals(0, port.admitCalls)
    }

    @Test
    fun unavailableExactDurableEvidenceNeverAttemptsAdmission() {
        val operationId = OperationId("op-unavailable")
        val failure = failure(RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE)
        val unavailable = RecoveryBootstrapItem.Unavailable(
            operationId = operationId,
            target = target(),
            expectedRevision = OperationRevision(7),
            failure = failure,
        )
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(listOf(unavailable)),
        )

        val result = runSuspend { bridge(port).bind(operationId) }

        assertEquals(ExactOperationHostRuntimeBindResult.DurableEvidenceUnavailable(failure), result)
        assertEquals(0, port.admitCalls)
    }

    @Test
    fun bootstrapFailureIsPreservedAndAdmissionIsNotAttempted() {
        val failure = failure(RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION)
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Failed(failure),
        )

        val result = runSuspend { bridge(port).bind(OperationId("op")) }

        assertEquals(ExactOperationHostRuntimeBindResult.BootstrapFailed(failure), result)
        assertEquals(0, port.admitCalls)
    }

    @Test
    fun nonExecutableRecoveryPlanIsSurfacedWithoutReinterpretation() {
        val operationId = OperationId("op-blocked")
        val plan = plan(operationId)
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(plan)),
            ),
            admissionResult = ExactOperationHostPortAdmissionResult.NotExecutable(RecoveryAction.RECOVERY_BLOCKED),
        )

        val result = runSuspend { bridge(port).bind(operationId) }

        assertEquals(
            ExactOperationHostRuntimeBindResult.NotExecutable(RecoveryAction.RECOVERY_BLOCKED),
            result,
        )
    }

    @Test
    fun alreadyOwnedExactRuntimeIsNotDuplicated() {
        val operationId = OperationId("op-owned")
        val plan = plan(operationId)
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(plan)),
            ),
            admissionResult = ExactOperationHostPortAdmissionResult.AlreadyOwned,
        )

        val result = runSuspend { bridge(port).bind(operationId) }

        assertSame(ExactOperationHostRuntimeBindResult.AlreadyOwned, result)
    }

    @Test
    fun stalePlanCarriesExactRevisionEvidence() {
        val operationId = OperationId("op-stale")
        val plan = plan(operationId, revision = 3)
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(plan)),
            ),
            admissionResult = ExactOperationHostPortAdmissionResult.StalePlan(
                operationId = operationId,
                expectedRevision = OperationRevision(3),
                actualRevision = OperationRevision(4),
            ),
        )

        val result = runSuspend { bridge(port).bind(operationId) }

        assertEquals(
            ExactOperationHostRuntimeBindResult.StalePlan(
                operationId = operationId,
                expectedRevision = OperationRevision(3),
                actualRevision = OperationRevision(4),
            ),
            result,
        )
    }

    @Test
    fun unexpectedExplicitAuthorizationResultFailsClosed() {
        val operationId = OperationId("op-contract")
        val plan = plan(operationId)
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(plan)),
            ),
            admissionResult = ExactOperationHostPortAdmissionResult.RequiresExplicitAuthorization,
        )

        val result = runSuspend { bridge(port).bind(operationId) }

        assertTrue(result is ExactOperationHostRuntimeBindResult.ContractViolation)
    }

    @Test
    fun releaseDelegatesTheExactAdmissionToken() {
        val operationId = OperationId("op-release")
        val plan = plan(operationId)
        val token = FakeRuntimeToken("token-release")
        val port = FakeRuntimePort(
            bootstrapResult = RecoveryBootstrapResult.Success(
                listOf(RecoveryBootstrapItem.Planned(plan)),
            ),
            admissionResult = ExactOperationHostPortAdmissionResult.Admitted(token),
            releaseResult = OperationRuntimeReleaseResult.RELEASED,
        )
        val bridge = bridge(port)
        val bound = runSuspend { bridge.bind(operationId) } as ExactOperationHostRuntimeBindResult.Bound

        val released = bridge.release(bound.binding)

        assertEquals(OperationRuntimeReleaseResult.RELEASED, released)
        assertSame(token, port.releasedToken)
    }

    private fun bridge(
        port: FakeRuntimePort,
        provenance: RecoveryExitProvenance = RecoveryExitProvenance.UNKNOWN,
    ) = ExactOperationHostRuntimeAdmissionBridge(
        runtimePort = port,
        previousExitProvenance = { provenance },
    )

    private fun plan(
        operationId: OperationId,
        revision: Long = 1,
    ): ColdStartRecoveryPlan = ColdStartRecoveryPlan(
        operationId = operationId,
        target = target(),
        expectedRevision = OperationRevision(revision),
        action = RecoveryAction.RECONNECT_EXACT_OWNER,
        automaticAllowed = false,
    )

    private fun target(): OperationTarget = OperationTarget.ServerTarget(
        serverId = ServerId("server-1"),
        serverAccessId = ServerAccessId("access-1"),
    )

    private fun failure(kind: RecoveryBootstrapFailureKind) = RecoveryBootstrapFailure(
        kind = kind,
        reason = "test failure",
    )

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        val completed = CountDownLatch(1)
        block.startCoroutine(
            object : Continuation<T> {
                override val context = EmptyCoroutineContext

                override fun resumeWith(result: Result<T>) {
                    outcome = result
                    completed.countDown()
                }
            },
        )
        assertTrue("suspend block did not complete", completed.await(2, TimeUnit.SECONDS))
        return checkNotNull(outcome).getOrThrow()
    }

    private data class FakeRuntimeToken(val value: String) : ExactOperationHostRuntimeToken

    private class FakeRuntimePort(
        var bootstrapResult: RecoveryBootstrapResult = RecoveryBootstrapResult.Success(emptyList()),
        var admissionResult: ExactOperationHostPortAdmissionResult = ExactOperationHostPortAdmissionResult.AlreadyOwned,
        var releaseResult: OperationRuntimeReleaseResult = OperationRuntimeReleaseResult.STALE_OR_ALREADY_RELEASED,
    ) : ExactOperationHostRuntimePort {
        var bootstrapCalls = 0
        var admitCalls = 0
        var seenExitProvenance: RecoveryExitProvenance? = null
        var seenAuthority: RecoveryAdmissionAuthority? = null
        var seenPlan: ColdStartRecoveryPlan? = null
        var releasedToken: ExactOperationHostRuntimeToken? = null

        override suspend fun bootstrap(exitProvenance: RecoveryExitProvenance): RecoveryBootstrapResult {
            bootstrapCalls += 1
            seenExitProvenance = exitProvenance
            return bootstrapResult
        }

        override suspend fun admit(
            plan: ColdStartRecoveryPlan,
            authority: RecoveryAdmissionAuthority,
        ): ExactOperationHostPortAdmissionResult {
            admitCalls += 1
            seenPlan = plan
            seenAuthority = authority
            return admissionResult
        }

        override fun release(token: ExactOperationHostRuntimeToken): OperationRuntimeReleaseResult {
            releasedToken = token
            return releaseResult
        }
    }
}
