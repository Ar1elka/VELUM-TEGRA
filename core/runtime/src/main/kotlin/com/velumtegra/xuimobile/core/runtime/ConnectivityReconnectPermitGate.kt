package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.OperationId

/**
 * One process-local connectivity observation revision.
 *
 * Generation is ordering evidence only. ONLINE is never endpoint-reachability proof, while UNKNOWN
 * remains eligible for one exact-endpoint attempt because private/LAN/VPN targets may be valid.
 */
class ConnectivityObservation internal constructor(
    val generation: Long,
    val state: ConnectivityState,
)

/**
 * One-shot scheduling evidence for one exact OperationId in one connectivity generation.
 *
 * A permit authorizes only a future exact reconnect attempt. It never authorizes command replay,
 * checkpoint advancement, mutation, or treating the endpoint as reachable.
 */
class ReconnectPermit internal constructor(
    val operationId: OperationId,
    val generation: Long,
    val connectivityState: ConnectivityState,
    internal val observation: ConnectivityObservation,
)

sealed interface ReconnectPermitResult {
    data class Permitted(val permit: ReconnectPermit) : ReconnectPermitResult
    data object WaitForNetwork : ReconnectPermitResult
    data object StaleGeneration : ReconnectPermitResult
    data object AlreadyPermittedForGeneration : ReconnectPermitResult
}

enum class ReconnectPermitStatus {
    CURRENT,
    STALE_GENERATION,
}

/**
 * Process-local connectivity generation and reconnect scheduling gate.
 *
 * Every accepted connectivity observation advances the generation and invalidates scheduling work
 * captured from an older observation. Per generation, one exact OperationId can receive at most one
 * reconnect permit; different operations remain independent. The gate does not queue, retry, open
 * SSH sessions, classify command completion, or provide durable recovery state.
 */
class ConnectivityReconnectPermitGate(
    initialState: ConnectivityState = ConnectivityState.UNKNOWN,
) {
    private val lock = Any()
    private var currentObservation = ConnectivityObservation(
        generation = 0L,
        state = initialState,
    )
    private val permittedOperations = mutableSetOf<OperationId>()

    fun snapshot(): ConnectivityObservation = synchronized(lock) {
        currentObservation
    }

    fun observe(state: ConnectivityState): ConnectivityObservation = synchronized(lock) {
        check(currentObservation.generation != Long.MAX_VALUE) {
            "Connectivity generation exhausted"
        }
        currentObservation = ConnectivityObservation(
            generation = currentObservation.generation + 1L,
            state = state,
        )
        permittedOperations.clear()
        currentObservation
    }

    fun tryPermit(
        operationId: OperationId,
        observation: ConnectivityObservation,
    ): ReconnectPermitResult = synchronized(lock) {
        if (observation !== currentObservation) {
            return@synchronized ReconnectPermitResult.StaleGeneration
        }

        if (observation.state == ConnectivityState.OFFLINE) {
            return@synchronized ReconnectPermitResult.WaitForNetwork
        }

        if (!permittedOperations.add(operationId)) {
            return@synchronized ReconnectPermitResult.AlreadyPermittedForGeneration
        }

        ReconnectPermitResult.Permitted(
            ReconnectPermit(
                operationId = operationId,
                generation = observation.generation,
                connectivityState = observation.state,
                observation = observation,
            ),
        )
    }

    fun status(permit: ReconnectPermit): ReconnectPermitStatus = synchronized(lock) {
        if (permit.observation === currentObservation) {
            ReconnectPermitStatus.CURRENT
        } else {
            ReconnectPermitStatus.STALE_GENERATION
        }
    }
}
