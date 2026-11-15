package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactOperationHostRuntimeBindingRegistryTest {
    @Test
    fun currentAttemptAdoptsAndCancellationReturnsExactBindingForRelease() {
        val registry = ExactOperationHostRuntimeBindingRegistry()
        val operationId = OperationId("op-bound")
        val attempt = registry.begin(operationId)
        val binding = binding(operationId, "token-bound")

        assertTrue(registry.adopt(attempt, binding))
        assertSame(binding, registry.cancel(attempt))
    }

    @Test
    fun cancellationBeforeLateAdmissionMakesLateBindingUnadoptable() {
        val registry = ExactOperationHostRuntimeBindingRegistry()
        val operationId = OperationId("op-late")
        val attempt = registry.begin(operationId)

        assertNull(registry.cancel(attempt))
        assertFalse(registry.adopt(attempt, binding(operationId, "late-token")))
    }

    @Test
    fun oldSameOperationGenerationCannotOverwriteReplacementAttempt() {
        val registry = ExactOperationHostRuntimeBindingRegistry()
        val operationId = OperationId("op-replacement")
        val oldAttempt = registry.begin(operationId)
        assertNull(registry.cancel(oldAttempt))

        val replacementAttempt = registry.begin(operationId)
        val replacement = binding(operationId, "replacement-token")

        assertFalse(registry.adopt(oldAttempt, binding(operationId, "old-token")))
        assertTrue(registry.adopt(replacementAttempt, replacement))
        assertNull(registry.cancel(oldAttempt))
        assertSame(replacement, registry.cancel(replacementAttempt))
    }

    @Test
    fun unboundCompletionClosesGenerationAgainstLateBinding() {
        val registry = ExactOperationHostRuntimeBindingRegistry()
        val operationId = OperationId("op-no-admission")
        val attempt = registry.begin(operationId)

        assertTrue(registry.finishWithoutBinding(attempt))
        assertFalse(registry.adopt(attempt, binding(operationId, "too-late")))
        assertNull(registry.cancel(attempt))
    }

    @Test
    fun staleUnboundCompletionCannotClearReplacementGeneration() {
        val registry = ExactOperationHostRuntimeBindingRegistry()
        val operationId = OperationId("op-finish-race")
        val oldAttempt = registry.begin(operationId)
        assertTrue(registry.finishWithoutBinding(oldAttempt))

        val replacementAttempt = registry.begin(operationId)
        val replacement = binding(operationId, "replacement")

        assertFalse(registry.finishWithoutBinding(oldAttempt))
        assertTrue(registry.adopt(replacementAttempt, replacement))
        assertSame(replacement, registry.cancel(replacementAttempt))
    }

    @Test(expected = IllegalArgumentException::class)
    fun bindingForDifferentOperationCannotBeAdopted() {
        val registry = ExactOperationHostRuntimeBindingRegistry()
        val attempt = registry.begin(OperationId("op-a"))

        registry.adopt(attempt, binding(OperationId("op-b"), "wrong-owner"))
    }

    private fun binding(
        operationId: OperationId,
        tokenValue: String,
    ): ExactOperationHostRuntimeBinding = ExactOperationHostRuntimeBinding(
        operationId = operationId,
        token = FakeRuntimeToken(tokenValue),
    )

    private data class FakeRuntimeToken(val value: String) : ExactOperationHostRuntimeToken
}
