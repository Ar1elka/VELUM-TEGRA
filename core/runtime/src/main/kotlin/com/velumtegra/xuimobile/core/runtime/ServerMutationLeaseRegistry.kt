package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerId
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-local ownership token for one mutating Operation on one exact [ServerId].
 *
 * The lease is intentionally ephemeral. It prevents concurrent live-process mutations only;
 * durable unsafe-checkpoint barriers remain derived from OperationJournal evidence.
 */
class ServerMutationLease internal constructor(
    val serverId: ServerId,
    val operationId: OperationId,
)

sealed interface ServerMutationAcquireResult {
    data class Acquired(val lease: ServerMutationLease) : ServerMutationAcquireResult
    data object AlreadyOwned : ServerMutationAcquireResult
}

enum class ServerMutationReleaseResult {
    RELEASED,
    STALE_OR_ALREADY_RELEASED,
}

/**
 * Exact process-local mutation gate keyed only by stable [ServerId].
 *
 * At most one mutating Operation may own a Server at a time. Acquisition is non-blocking: a
 * competing mutation is rejected explicitly rather than queued, retried or allowed to steal the
 * current lease. Read-only work is intentionally outside this registry.
 */
class ServerMutationLeaseRegistry {
    private val leases = ConcurrentHashMap<ServerId, ServerMutationLease>()

    fun tryAcquire(
        serverId: ServerId,
        operationId: OperationId,
    ): ServerMutationAcquireResult {
        val candidate = ServerMutationLease(
            serverId = serverId,
            operationId = operationId,
        )
        val existing = leases.putIfAbsent(serverId, candidate)
        return if (existing == null) {
            ServerMutationAcquireResult.Acquired(candidate)
        } else {
            ServerMutationAcquireResult.AlreadyOwned
        }
    }

    /** True only while this exact lease object still owns its server. */
    fun isCurrent(lease: ServerMutationLease): Boolean = leases[lease.serverId] === lease

    fun release(lease: ServerMutationLease): ServerMutationReleaseResult =
        if (leases.remove(lease.serverId, lease)) {
            ServerMutationReleaseResult.RELEASED
        } else {
            ServerMutationReleaseResult.STALE_OR_ALREADY_RELEASED
        }
}
