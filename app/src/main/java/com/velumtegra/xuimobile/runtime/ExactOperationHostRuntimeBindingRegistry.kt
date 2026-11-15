package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId

/**
 * Service-local generation gate for one asynchronous runtime-admission attempt.
 *
 * Android may destroy/timeout the host while the suspend admission bridge is still re-reading
 * durable truth. The Service therefore never stores a bare late result. A generation token must
 * still be current before a [ExactOperationHostRuntimeBinding] can be adopted. If the generation
 * was cancelled first, the caller must immediately release the late exact binding through the
 * admission bridge.
 *
 * This registry is ephemeral only. It does not replace the process-scoped OperationRuntime lease
 * registry and does not authorize remote work.
 */
internal class ExactOperationHostRuntimeBindingRegistry {
    private val lock = Any()
    private var nextGeneration = 1L
    private var currentAttempt: ExactOperationHostRuntimeAttempt? = null
    private var currentBinding: ExactOperationHostRuntimeBinding? = null

    fun begin(operationId: OperationId): ExactOperationHostRuntimeAttempt = synchronized(lock) {
        require(operationId.value.isNotBlank()) { "OperationId cannot be blank" }
        check(currentAttempt == null) { "Host runtime admission attempt is already active" }
        check(currentBinding == null) { "Host runtime binding cannot exist without an active attempt" }
        ExactOperationHostRuntimeAttempt(
            operationId = operationId,
            generation = nextGeneration++,
        ).also { currentAttempt = it }
    }

    /**
     * Adopts one exact binding only if the originating attempt is still current.
     * False means the caller owns a stale late result and must release it immediately.
     */
    fun adopt(
        attempt: ExactOperationHostRuntimeAttempt,
        binding: ExactOperationHostRuntimeBinding,
    ): Boolean = synchronized(lock) {
        require(binding.operationId == attempt.operationId) {
            "Runtime binding OperationId differs from the host admission attempt"
        }
        if (currentAttempt != attempt) {
            false
        } else {
            check(currentBinding == null) { "Host runtime attempt already adopted a binding" }
            currentBinding = binding
            true
        }
    }

    /** Completes a current admission attempt that produced no runtime binding. */
    fun finishWithoutBinding(attempt: ExactOperationHostRuntimeAttempt): Boolean = synchronized(lock) {
        if (currentAttempt != attempt) {
            false
        } else {
            check(currentBinding == null) { "Bound runtime cannot finish as an unbound attempt" }
            currentAttempt = null
            true
        }
    }

    /**
     * Cancels one exact generation. If it already adopted a binding, ownership is transferred to
     * the caller for exact-token release. A stale cancellation can never remove a replacement.
     */
    fun cancel(attempt: ExactOperationHostRuntimeAttempt): ExactOperationHostRuntimeBinding? =
        synchronized(lock) {
            if (currentAttempt != attempt) {
                null
            } else {
                currentAttempt = null
                currentBinding.also { currentBinding = null }
            }
        }
}

internal data class ExactOperationHostRuntimeAttempt(
    val operationId: OperationId,
    val generation: Long,
)
