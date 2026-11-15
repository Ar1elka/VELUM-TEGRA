package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.OperationId

/**
 * Process-local evidence for the Android execution host lifecycle.
 *
 * This registry is deliberately ephemeral: it never replaces OperationJournal truth and it does
 * not authorize remote work. A generation token prevents late callbacks from an older Service
 * lifetime from overwriting evidence published by a newer host lifetime in the same process.
 */
internal class ExactOperationHostLifecycleRegistry {
    private val lock = Any()
    private var nextGeneration = 1L
    private var currentLease: ExactOperationHostLifecycleLease? = null
    private var latestEvidence: ExactOperationHostLifecycleEvidence? = null

    fun begin(operationId: OperationId): ExactOperationHostLifecycleLease = synchronized(lock) {
        require(operationId.value.isNotBlank()) { "OperationId cannot be blank" }
        val lease = ExactOperationHostLifecycleLease(
            operationId = operationId,
            generation = nextGeneration++,
        )
        currentLease = lease
        latestEvidence = lease.evidence(ExactOperationHostLifecycleState.STARTING)
        lease
    }

    fun markForeground(lease: ExactOperationHostLifecycleLease): Boolean = synchronized(lock) {
        if (currentLease != lease) {
            false
        } else {
            latestEvidence = lease.evidence(ExactOperationHostLifecycleState.FOREGROUND_ACTIVE)
            true
        }
    }

    fun finish(
        lease: ExactOperationHostLifecycleLease,
        terminalState: ExactOperationHostLifecycleState,
    ): Boolean = synchronized(lock) {
        require(terminalState.isTerminal) { "Host finish requires a terminal lifecycle state" }
        if (currentLease != lease) {
            false
        } else {
            latestEvidence = lease.evidence(terminalState)
            currentLease = null
            true
        }
    }

    fun latest(): ExactOperationHostLifecycleEvidence? = synchronized(lock) { latestEvidence }

    private fun ExactOperationHostLifecycleLease.evidence(
        state: ExactOperationHostLifecycleState,
    ): ExactOperationHostLifecycleEvidence = ExactOperationHostLifecycleEvidence(
        operationId = operationId,
        generation = generation,
        state = state,
    )
}

internal data class ExactOperationHostLifecycleLease(
    val operationId: OperationId,
    val generation: Long,
)

internal data class ExactOperationHostLifecycleEvidence(
    val operationId: OperationId,
    val generation: Long,
    val state: ExactOperationHostLifecycleState,
)

internal enum class ExactOperationHostLifecycleState(val isTerminal: Boolean) {
    STARTING(false),
    FOREGROUND_ACTIVE(false),
    STOPPED(true),
    USER_STOPPED(true),
    TIMED_OUT(true),
    START_FAILED(true),
}
