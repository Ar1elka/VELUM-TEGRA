package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId

/**
 * Exact process-local classifier for the user-visible Stop action of one hosted operation.
 *
 * A stop request is bound to both the exact [OperationId] and the exact host lifecycle generation
 * that created its notification. OperationId alone is insufficient: a stale notification from an
 * older Service generation of the same operation must not be able to stop a replacement host.
 *
 * This gate changes no ownership and writes no durable state. It only tells the Service whether the
 * delivered user action is allowed to tear down the currently hosted runtime.
 */
internal object ExactOperationHostUserStopGate {
    fun classify(
        request: ExactOperationHostUserStopRequest,
        currentOperationId: OperationId?,
        currentLifecycleLease: ExactOperationHostLifecycleLease?,
    ): ExactOperationHostUserStopDisposition {
        if (currentOperationId == null && currentLifecycleLease == null) {
            return ExactOperationHostUserStopDisposition.STOP_UNBOUND_SERVICE
        }

        // Any partial/inconsistent ownership view fails closed. Never stop a possibly live host
        // unless both exact host identities agree with the user action.
        if (currentOperationId == null || currentLifecycleLease == null) {
            return ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST
        }

        return if (
            currentOperationId == request.operationId &&
            currentLifecycleLease.operationId == request.operationId &&
            currentLifecycleLease.generation == request.hostGeneration
        ) {
            ExactOperationHostUserStopDisposition.STOP_EXACT_HOST
        } else {
            ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST
        }
    }
}

internal data class ExactOperationHostUserStopRequest(
    val operationId: OperationId,
    val hostGeneration: Long,
) {
    init {
        require(operationId.value.isNotBlank()) { "OperationId cannot be blank" }
        require(hostGeneration > 0L) { "Host lifecycle generation must be positive" }
    }

    /**
     * Stable process-local PendingIntent identity material for this exact host notification.
     * Length-prefixing keeps arbitrary OperationId text unambiguous before Android URI encoding.
     */
    val pendingIntentIdentity: String
        get() = "${operationId.value.length}:${operationId.value}:$hostGeneration"
}

internal enum class ExactOperationHostUserStopDisposition {
    STOP_UNBOUND_SERVICE,
    STOP_EXACT_HOST,
    IGNORE_ACTIVE_HOST,
}
