package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class ExactOperationHostUserStopGateTest {
    private val first = OperationId("operation-1")
    private val second = OperationId("operation-2")

    @Test
    fun exactOperationAndExactGenerationMayStopCurrentHost() {
        val lease = ExactOperationHostLifecycleLease(first, generation = 7L)
        val request = ExactOperationHostUserStopRequest(first, hostGeneration = 7L)

        assertEquals(
            ExactOperationHostUserStopDisposition.STOP_EXACT_HOST,
            ExactOperationHostUserStopGate.classify(request, first, lease),
        )
    }

    @Test
    fun staleGenerationCannotStopReplacementHostForSameOperation() {
        val replacement = ExactOperationHostLifecycleLease(first, generation = 8L)
        val stale = ExactOperationHostUserStopRequest(first, hostGeneration = 7L)

        assertEquals(
            ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostUserStopGate.classify(stale, first, replacement),
        )
    }

    @Test
    fun differentOperationCannotStopActiveHostEvenWithSameGeneration() {
        val lease = ExactOperationHostLifecycleLease(first, generation = 7L)
        val foreign = ExactOperationHostUserStopRequest(second, hostGeneration = 7L)

        assertEquals(
            ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostUserStopGate.classify(foreign, first, lease),
        )
    }

    @Test
    fun lateStopMayOnlyStopOtherwiseUnboundServiceInstance() {
        val stale = ExactOperationHostUserStopRequest(first, hostGeneration = 7L)

        assertEquals(
            ExactOperationHostUserStopDisposition.STOP_UNBOUND_SERVICE,
            ExactOperationHostUserStopGate.classify(stale, null, null),
        )
    }

    @Test
    fun partialOwnershipStateFailsClosedInsteadOfStopping() {
        val request = ExactOperationHostUserStopRequest(first, hostGeneration = 7L)
        val lease = ExactOperationHostLifecycleLease(first, generation = 7L)

        assertEquals(
            ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostUserStopGate.classify(request, first, null),
        )
        assertEquals(
            ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostUserStopGate.classify(request, null, lease),
        )
    }

    @Test
    fun pendingIntentIdentityChangesAcrossSameOperationReplacementGeneration() {
        val stale = ExactOperationHostUserStopRequest(first, hostGeneration = 7L)
        val replacement = ExactOperationHostUserStopRequest(first, hostGeneration = 8L)

        assertNotEquals(stale.pendingIntentIdentity, replacement.pendingIntentIdentity)
    }

    @Test
    fun pendingIntentIdentityChangesAcrossDifferentOperations() {
        val firstRequest = ExactOperationHostUserStopRequest(first, hostGeneration = 7L)
        val secondRequest = ExactOperationHostUserStopRequest(second, hostGeneration = 7L)

        assertNotEquals(firstRequest.pendingIntentIdentity, secondRequest.pendingIntentIdentity)
    }

    @Test(expected = IllegalArgumentException::class)
    fun nonPositiveGenerationIsRejected() {
        ExactOperationHostUserStopRequest(first, hostGeneration = 0L)
    }
}
