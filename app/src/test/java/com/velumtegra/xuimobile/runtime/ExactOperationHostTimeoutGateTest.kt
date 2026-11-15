package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import org.junit.Assert.assertEquals
import org.junit.Test

class ExactOperationHostTimeoutGateTest {
    private val first = OperationId("operation-1")
    private val second = OperationId("operation-2")

    @Test
    fun exactTimeoutStartIdMayStopCurrentHost() {
        val lease = ExactOperationHostLifecycleLease(first, generation = 4L)

        assertEquals(
            ExactOperationHostTimeoutDisposition.STOP_EXACT_HOST,
            ExactOperationHostTimeoutGate.classify(
                timeoutStartId = 17,
                hostedStartId = 17,
                currentOperationId = first,
                currentLifecycleLease = lease,
            ),
        )
    }

    @Test
    fun staleTimeoutStartIdCannotStopReplacementHostForSameOperation() {
        val replacement = ExactOperationHostLifecycleLease(first, generation = 5L)

        assertEquals(
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostTimeoutGate.classify(
                timeoutStartId = 17,
                hostedStartId = 18,
                currentOperationId = first,
                currentLifecycleLease = replacement,
            ),
        )
    }

    @Test
    fun timeoutCannotStopHostWhenLifecycleOperationDisagrees() {
        val foreignLease = ExactOperationHostLifecycleLease(second, generation = 5L)

        assertEquals(
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostTimeoutGate.classify(
                timeoutStartId = 18,
                hostedStartId = 18,
                currentOperationId = first,
                currentLifecycleLease = foreignLease,
            ),
        )
    }

    @Test
    fun timeoutMayStopOtherwiseUnboundServiceInstance() {
        assertEquals(
            ExactOperationHostTimeoutDisposition.STOP_UNBOUND_SERVICE,
            ExactOperationHostTimeoutGate.classify(
                timeoutStartId = 17,
                hostedStartId = null,
                currentOperationId = null,
                currentLifecycleLease = null,
            ),
        )
    }

    @Test
    fun partialOwnershipStateFailsClosedInsteadOfStopping() {
        val lease = ExactOperationHostLifecycleLease(first, generation = 4L)

        assertEquals(
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostTimeoutGate.classify(17, null, first, lease),
        )
        assertEquals(
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostTimeoutGate.classify(17, 17, null, lease),
        )
        assertEquals(
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST,
            ExactOperationHostTimeoutGate.classify(17, 17, first, null),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun nonPositiveTimeoutStartIdFailsClosed() {
        ExactOperationHostTimeoutGate.classify(0, null, null, null)
    }
}
