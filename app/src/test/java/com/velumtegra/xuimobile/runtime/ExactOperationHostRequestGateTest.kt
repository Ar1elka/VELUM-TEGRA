package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactOperationHostRequestGateTest {
    private val first = OperationId("operation-1")
    private val second = OperationId("operation-2")

    @Test
    fun firstExactOperationBindsHost() {
        val gate = ExactOperationHostRequestGate()

        assertEquals(ExactOperationHostBindResult.BOUND, gate.tryBind(first))
        assertEquals(first, gate.current())
    }

    @Test
    fun duplicateStartForSameOperationIsIdempotent() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertEquals(ExactOperationHostBindResult.ALREADY_BOUND, gate.tryBind(first))
        assertEquals(first, gate.current())
    }

    @Test
    fun differentOperationCannotRebindLiveHost() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertEquals(
            ExactOperationHostBindResult.REJECTED_DIFFERENT_OPERATION,
            gate.tryBind(second),
        )
        assertEquals(first, gate.current())
    }

    @Test
    fun staleCleanupCannotReleaseDifferentOperation() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertFalse(gate.release(second))
        assertEquals(first, gate.current())
    }

    @Test
    fun exactCleanupReleasesHostForFutureOperation() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertTrue(gate.release(first))
        assertNull(gate.current())
        assertEquals(ExactOperationHostBindResult.BOUND, gate.tryBind(second))
        assertEquals(second, gate.current())
    }
    @Test
    fun malformedStartStopsOnlyAnUnboundService() {
        val gate = ExactOperationHostRequestGate()

        assertEquals(
            ExactOperationHostInvalidStartDisposition.STOP_UNBOUND_SERVICE,
            gate.invalidStartDisposition(),
        )
    }

    @Test
    fun malformedStartCannotStopAnAlreadyBoundExactHost() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertEquals(
            ExactOperationHostInvalidStartDisposition.IGNORE_ACTIVE_HOST,
            gate.invalidStartDisposition(),
        )
        assertEquals(first, gate.current())
    }

    @Test
    fun staleCleanupDoesNotMakeMalformedStartAbleToStopReplacementOwner() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertFalse(gate.release(second))
        assertEquals(
            ExactOperationHostInvalidStartDisposition.IGNORE_ACTIVE_HOST,
            gate.invalidStartDisposition(),
        )
        assertEquals(first, gate.current())
    }

    @Test
    fun exactReleaseRestoresUnboundMalformedStartDisposition() {
        val gate = ExactOperationHostRequestGate()
        gate.tryBind(first)

        assertTrue(gate.release(first))
        assertEquals(
            ExactOperationHostInvalidStartDisposition.STOP_UNBOUND_SERVICE,
            gate.invalidStartDisposition(),
        )
    }

}
