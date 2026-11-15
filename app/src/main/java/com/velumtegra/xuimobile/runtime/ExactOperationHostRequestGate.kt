package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator

/**
 * Process-local binding gate for the single Android short-service host instance.
 *
 * This is not operation execution ownership; [OperationRuntimeCoordinator] still owns that exact
 * lease. The gate only prevents Android duplicate/different start intents from rebinding one
 * Service lifetime from one exact OperationId to another.
 */
internal class ExactOperationHostRequestGate {
    private val lock = Any()
    private var hostedOperationId: OperationId? = null

    fun tryBind(operationId: OperationId): ExactOperationHostBindResult = synchronized(lock) {
        when (hostedOperationId) {
            null -> {
                hostedOperationId = operationId
                ExactOperationHostBindResult.BOUND
            }

            operationId -> ExactOperationHostBindResult.ALREADY_BOUND
            else -> ExactOperationHostBindResult.REJECTED_DIFFERENT_OPERATION
        }
    }

    fun current(): OperationId? = synchronized(lock) { hostedOperationId }

    /**
     * Classifies a malformed/unsupported Android start without changing host ownership.
     *
     * An unbound Service instance should stop promptly because no exact OperationId authorized it.
     * Once an exact host is already bound, however, a malformed/stale start is only noise and must
     * never be allowed to terminate or release that live host.
     */
    fun invalidStartDisposition(): ExactOperationHostInvalidStartDisposition = synchronized(lock) {
        if (hostedOperationId == null) {
            ExactOperationHostInvalidStartDisposition.STOP_UNBOUND_SERVICE
        } else {
            ExactOperationHostInvalidStartDisposition.IGNORE_ACTIVE_HOST
        }
    }

    /** Exact cleanup only; a stale cleanup for another OperationId cannot clear the current host. */
    fun release(operationId: OperationId): Boolean = synchronized(lock) {
        if (hostedOperationId != operationId) {
            false
        } else {
            hostedOperationId = null
            true
        }
    }
}

internal enum class ExactOperationHostBindResult {
    BOUND,
    ALREADY_BOUND,
    REJECTED_DIFFERENT_OPERATION,
}

internal enum class ExactOperationHostInvalidStartDisposition {
    STOP_UNBOUND_SERVICE,
    IGNORE_ACTIVE_HOST,
}
