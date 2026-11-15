package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactOperationHostLifecycleRegistryTest {
    private val first = OperationId("operation-1")
    private val second = OperationId("operation-2")

    @Test
    fun beginPublishesStartingForExactOperation() {
        val registry = ExactOperationHostLifecycleRegistry()

        val lease = registry.begin(first)

        assertEquals(
            ExactOperationHostLifecycleEvidence(
                operationId = first,
                generation = lease.generation,
                state = ExactOperationHostLifecycleState.STARTING,
            ),
            registry.latest(),
        )
    }

    @Test
    fun foregroundPromotionIsRecordedWithoutChangingExactIdentity() {
        val registry = ExactOperationHostLifecycleRegistry()
        val lease = registry.begin(first)

        assertTrue(registry.markForeground(lease))
        assertEquals(
            ExactOperationHostLifecycleEvidence(
                operationId = first,
                generation = lease.generation,
                state = ExactOperationHostLifecycleState.FOREGROUND_ACTIVE,
            ),
            registry.latest(),
        )
    }

    @Test
    fun timeoutIsTerminalHostEvidenceOnly() {
        val registry = ExactOperationHostLifecycleRegistry()
        val lease = registry.begin(first)
        registry.markForeground(lease)

        assertTrue(registry.finish(lease, ExactOperationHostLifecycleState.TIMED_OUT))
        assertEquals(ExactOperationHostLifecycleState.TIMED_OUT, registry.latest()?.state)
    }

    @Test
    fun staleForegroundCallbackCannotOverwriteReplacementHost() {
        val registry = ExactOperationHostLifecycleRegistry()
        val stale = registry.begin(first)
        val replacement = registry.begin(second)

        assertFalse(registry.markForeground(stale))
        assertEquals(second, registry.latest()?.operationId)
        assertEquals(replacement.generation, registry.latest()?.generation)
        assertEquals(ExactOperationHostLifecycleState.STARTING, registry.latest()?.state)
    }

    @Test
    fun staleDestroyCannotOverwriteReplacementHost() {
        val registry = ExactOperationHostLifecycleRegistry()
        val stale = registry.begin(first)
        val replacement = registry.begin(second)
        registry.markForeground(replacement)

        assertFalse(registry.finish(stale, ExactOperationHostLifecycleState.STOPPED))
        assertEquals(second, registry.latest()?.operationId)
        assertEquals(replacement.generation, registry.latest()?.generation)
        assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, registry.latest()?.state)
    }


    @Test
    fun staleDestroyForSameOperationCannotOverwriteNewGeneration() {
        val registry = ExactOperationHostLifecycleRegistry()
        val stale = registry.begin(first)
        val replacement = registry.begin(first)
        registry.markForeground(replacement)

        assertFalse(registry.finish(stale, ExactOperationHostLifecycleState.STOPPED))
        assertEquals(first, registry.latest()?.operationId)
        assertEquals(replacement.generation, registry.latest()?.generation)
        assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, registry.latest()?.state)
    }

    @Test
    fun explicitUserStopIsTerminalHostEvidenceOnly() {
        val registry = ExactOperationHostLifecycleRegistry()
        val lease = registry.begin(first)
        registry.markForeground(lease)

        assertTrue(registry.finish(lease, ExactOperationHostLifecycleState.USER_STOPPED))
        assertEquals(ExactOperationHostLifecycleState.USER_STOPPED, registry.latest()?.state)
    }

    @Test
    fun staleUserStopCannotOverwriteReplacementGenerationOfSameOperation() {
        val registry = ExactOperationHostLifecycleRegistry()
        val stale = registry.begin(first)
        val replacement = registry.begin(first)
        registry.markForeground(replacement)

        assertFalse(registry.finish(stale, ExactOperationHostLifecycleState.USER_STOPPED))
        assertEquals(first, registry.latest()?.operationId)
        assertEquals(replacement.generation, registry.latest()?.generation)
        assertEquals(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE, registry.latest()?.state)
    }

    @Test(expected = IllegalArgumentException::class)
    fun nonTerminalStateCannotFinishHost() {
        val registry = ExactOperationHostLifecycleRegistry()
        val lease = registry.begin(first)

        registry.finish(lease, ExactOperationHostLifecycleState.FOREGROUND_ACTIVE)
    }
}
