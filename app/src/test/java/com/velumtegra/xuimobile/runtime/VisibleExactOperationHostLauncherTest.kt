package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VisibleExactOperationHostLauncherTest {
    @Test
    fun acceptedPlatformRequestIsOnlyStartRequestAccepted() {
        val launcher = launcherReturning(ExactOperationHostPlatformStartResult.ACCEPTED)

        assertEquals(
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED,
            launcher.start(OperationId("operation-1")),
        )
    }

    @Test
    fun currentStateDenialRemainsTypedAndExactOperationIsPreserved() {
        var requested: OperationId? = null
        val launcher = VisibleExactOperationHostLauncher { operationId ->
            requested = operationId
            ExactOperationHostPlatformStartResult.NOT_ALLOWED_FROM_CURRENT_STATE
        }
        val exact = OperationId("operation-visible-start")

        assertEquals(
            ExactOperationHostStartResult.NOT_ALLOWED_FROM_CURRENT_STATE,
            launcher.start(exact),
        )
        assertEquals(exact, requested)
    }

    @Test
    fun securityOrPolicyDenialDoesNotBecomeSuccess() {
        val launcher = launcherReturning(ExactOperationHostPlatformStartResult.SECURITY_OR_POLICY_DENIED)

        assertEquals(
            ExactOperationHostStartResult.SECURITY_OR_POLICY_DENIED,
            launcher.start(OperationId("operation-1")),
        )
    }

    @Test
    fun unavailableServiceDoesNotBecomeSuccess() {
        val launcher = launcherReturning(ExactOperationHostPlatformStartResult.SERVICE_UNAVAILABLE)

        assertEquals(
            ExactOperationHostStartResult.SERVICE_UNAVAILABLE,
            launcher.start(OperationId("operation-1")),
        )
    }

    @Test
    fun blankOperationIdIsRejectedBeforePlatformRequest() {
        var requested: OperationId? = null
        val launcher = VisibleExactOperationHostLauncher { operationId ->
            requested = operationId
            ExactOperationHostPlatformStartResult.ACCEPTED
        }

        assertEquals(
            ExactOperationHostStartResult.INVALID_OPERATION_ID,
            launcher.start(OperationId("   ")),
        )
        assertNull(requested)
    }

    @Test
    fun launcherNeverSubstitutesAnotherOperationId() {
        var requested: OperationId? = null
        val launcher = VisibleExactOperationHostLauncher { operationId ->
            requested = operationId
            ExactOperationHostPlatformStartResult.ACCEPTED
        }
        val exact = OperationId("operation-exact-owner")

        launcher.start(exact)

        assertEquals(exact, requested)
    }

    private fun launcherReturning(
        result: ExactOperationHostPlatformStartResult,
    ): VisibleExactOperationHostLauncher = VisibleExactOperationHostLauncher { result }
}
