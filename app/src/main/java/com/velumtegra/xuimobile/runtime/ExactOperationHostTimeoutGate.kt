package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId

/**
 * Exact classifier for Android shortService timeout callbacks.
 *
 * Android supplies the startId associated with the timed-out foreground-service start. A timeout
 * from an older host lifetime must therefore never tear down a replacement host that is already
 * bound inside the same Service instance. The callback may stop only when its startId still matches
 * the exact start that created the current host and the current OperationId/lifecycle lease agree.
 *
 * This gate is ephemeral host safety only. It changes no runtime ownership and no durable state.
 */
internal object ExactOperationHostTimeoutGate {
    fun classify(
        timeoutStartId: Int,
        hostedStartId: Int?,
        currentOperationId: OperationId?,
        currentLifecycleLease: ExactOperationHostLifecycleLease?,
    ): ExactOperationHostTimeoutDisposition {
        require(timeoutStartId > 0) { "Android timeout startId must be positive" }
        require(hostedStartId == null || hostedStartId > 0) {
            "Hosted Android startId must be positive"
        }

        if (hostedStartId == null && currentOperationId == null && currentLifecycleLease == null) {
            return ExactOperationHostTimeoutDisposition.STOP_UNBOUND_SERVICE
        }

        // Any partial/inconsistent ownership view fails closed. A stale callback may not tear down
        // a host unless all exact host identity evidence agrees with the callback.
        if (hostedStartId == null || currentOperationId == null || currentLifecycleLease == null) {
            return ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST
        }

        return if (
            hostedStartId == timeoutStartId &&
            currentLifecycleLease.operationId == currentOperationId
        ) {
            ExactOperationHostTimeoutDisposition.STOP_EXACT_HOST
        } else {
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST
        }
    }
}

internal enum class ExactOperationHostTimeoutDisposition {
    STOP_UNBOUND_SERVICE,
    STOP_EXACT_HOST,
    IGNORE_ACTIVE_HOST,
}
