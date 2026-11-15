package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-local ownership token for one exact [OperationId].
 *
 * The lease is intentionally ephemeral. Durable operation truth remains in OperationJournal;
 * a process restart must recover from persisted evidence and acquire a new lease.
 */
class OperationRuntimeLease internal constructor(
    val operationId: OperationId,
)

sealed interface OperationRuntimeAcquireResult {
    data class Acquired(val lease: OperationRuntimeLease) : OperationRuntimeAcquireResult
    data object AlreadyOwned : OperationRuntimeAcquireResult
}

enum class OperationRuntimeReleaseResult {
    RELEASED,
    STALE_OR_ALREADY_RELEASED,
}

/**
 * Exact process-local ownership registry used by the future runtime coordinator.
 *
 * It has no implicit current/latest lookup and does not provide durability. A duplicate acquire for
 * the same exact OperationId is rejected rather than starting a second executor.
 */
class OperationRuntimeLeaseRegistry {
    private val leases = ConcurrentHashMap<OperationId, OperationRuntimeLease>()

    fun tryAcquire(operationId: OperationId): OperationRuntimeAcquireResult {
        val candidate = OperationRuntimeLease(operationId)
        val existing = leases.putIfAbsent(operationId, candidate)
        return if (existing == null) {
            OperationRuntimeAcquireResult.Acquired(candidate)
        } else {
            OperationRuntimeAcquireResult.AlreadyOwned
        }
    }

    /** Exact-token liveness check used before later remote work from an already-admitted runtime. */
    fun isCurrent(lease: OperationRuntimeLease): Boolean =
        leases[lease.operationId] === lease

    fun release(lease: OperationRuntimeLease): OperationRuntimeReleaseResult =
        if (leases.remove(lease.operationId, lease)) {
            OperationRuntimeReleaseResult.RELEASED
        } else {
            OperationRuntimeReleaseResult.STALE_OR_ALREADY_RELEASED
        }
}
