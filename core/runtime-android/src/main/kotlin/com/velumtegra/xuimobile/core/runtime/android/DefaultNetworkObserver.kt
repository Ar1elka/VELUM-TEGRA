package com.velumtegra.xuimobile.core.runtime.android

import android.net.ConnectivityManager
import com.velumtegra.xuimobile.core.model.ConnectivityState

@JvmInline
internal value class DefaultNetworkId(val value: Long)

internal data class DefaultNetworkCapabilities(
    val hasInternetCapability: Boolean,
    val isValidated: Boolean,
)

internal sealed interface DefaultNetworkEvent {
    data class Available(val networkId: DefaultNetworkId) : DefaultNetworkEvent
    data class CapabilitiesChanged(
        val networkId: DefaultNetworkId,
        val capabilities: DefaultNetworkCapabilities,
    ) : DefaultNetworkEvent

    data class BlockedStatusChanged(
        val networkId: DefaultNetworkId,
        val isBlocked: Boolean,
    ) : DefaultNetworkEvent

    data class Lost(val networkId: DefaultNetworkId) : DefaultNetworkEvent
}

internal fun interface DefaultNetworkEventListener {
    fun onEvent(event: DefaultNetworkEvent)
}

internal fun interface DefaultNetworkRegistration {
    fun unregister()
}

internal fun interface DefaultNetworkEventSource {
    fun register(listener: DefaultNetworkEventListener): DefaultNetworkRegistration
}

/**
 * Ordered reducer for one Android default-network callback stream.
 *
 * It consumes callback arguments only. It never performs a synchronous ConnectivityManager
 * capability query, so a callback cannot overwrite newer ordered callback evidence with a raced
 * point-in-time re-query.
 */
internal class DefaultNetworkStateReducer {
    private var currentNetworkId: DefaultNetworkId? = null
    private var currentCapabilities: DefaultNetworkCapabilities? = null
    private var currentBlockedStatus: Boolean? = null

    var currentState: ConnectivityState = ConnectivityState.OFFLINE
        private set

    /**
     * Returns a new observation only when scheduling semantics changed.
     *
     * A new exact default-network identity is meaningful even when the mapped state stays UNKNOWN;
     * repeated capability/status callbacks with the same mapped meaning are coalesced.
     */
    fun reduce(event: DefaultNetworkEvent): ConnectivityState? {
        val previousState = currentState
        var forceObservation = false

        when (event) {
            is DefaultNetworkEvent.Available -> {
                if (currentNetworkId == event.networkId) {
                    return null
                }
                currentNetworkId = event.networkId
                currentCapabilities = null
                currentBlockedStatus = null
                forceObservation = true
            }

            is DefaultNetworkEvent.CapabilitiesChanged -> {
                if (currentNetworkId != event.networkId) {
                    return null
                }
                currentCapabilities = event.capabilities
            }

            is DefaultNetworkEvent.BlockedStatusChanged -> {
                if (currentNetworkId != event.networkId) {
                    return null
                }
                currentBlockedStatus = event.isBlocked
            }

            is DefaultNetworkEvent.Lost -> {
                if (currentNetworkId != event.networkId) {
                    return null
                }
                currentNetworkId = null
                currentCapabilities = null
                currentBlockedStatus = null
            }
        }

        currentState = mapState()
        return if (forceObservation || currentState != previousState) currentState else null
    }

    private fun mapState(): ConnectivityState {
        if (currentNetworkId == null) {
            return ConnectivityState.OFFLINE
        }

        // A blocked default network exists, but it is not usable by this app at this moment.
        if (currentBlockedStatus == true) {
            return ConnectivityState.OFFLINE
        }

        val capabilities = currentCapabilities ?: return ConnectivityState.UNKNOWN
        return if (capabilities.hasInternetCapability && capabilities.isValidated) {
            ConnectivityState.ONLINE
        } else {
            ConnectivityState.UNKNOWN
        }
    }
}

/**
 * Android-facing default-network observer for Phase 4.3.
 *
 * This class only emits conservative connectivity observations. It does not own the Phase 4.4
 * coordinator, reconnect permits, SSH sessions, retry loops, OperationJournal or remote commands.
 * Every registration gets a fresh callback/token, so a late event from an earlier registration is
 * ignored after unregister/re-register.
 */
class AndroidDefaultNetworkObserver internal constructor(
    private val eventSource: DefaultNetworkEventSource,
    private val onConnectivityChanged: (ConnectivityState) -> Unit,
) : AutoCloseable {
    constructor(
        connectivityManager: ConnectivityManager,
        onConnectivityChanged: (ConnectivityState) -> Unit,
    ) : this(
        eventSource = ConnectivityManagerDefaultNetworkEventSource(connectivityManager),
        onConnectivityChanged = onConnectivityChanged,
    )

    private val lock = Any()
    /**
     * Serializes outward state delivery with lifecycle invalidation.
     *
     * Reducer advancement and outward delivery both pass through this gate. That lets unregister
     * invalidate the exact registration before any later old callback can reduce or escape and
     * become a newer connectivity generation in the replacement runtime.
     */
    private val deliveryLock = Any()
    private var activeRegistration: ActiveRegistration? = null

    /**
     * Registers exactly once. A duplicate call is rejected without a second Android callback.
     *
     * OFFLINE is emitted first because, before callback evidence arrives, no usable default network
     * is yet known. Android callback events received during registration are buffered behind that
     * initial conservative observation and then reduced in original order.
     */
    fun register(): Boolean {
        val active: ActiveRegistration
        synchronized(lock) {
            if (activeRegistration != null) {
                return false
            }

            val token = Any()
            val reducer = DefaultNetworkStateReducer()
            active = ActiveRegistration(
                token = token,
                reducer = reducer,
            )
            activeRegistration = active

            val listener = DefaultNetworkEventListener { event ->
                onEvent(token, event)
            }

            try {
                active.registration = eventSource.register(listener)
            } catch (error: Throwable) {
                if (activeRegistration === active) {
                    activeRegistration = null
                }
                throw error
            }
        }

        try {
            deliverIfCurrent(active.token, ConnectivityState.OFFLINE)
        } catch (error: Throwable) {
            unregisterExact(active)
            throw error
        }

        drainBufferedEvents(active.token)
        return true
    }

    /** Unregisters the exact active callback once. Late callbacks from it become stale. */
    fun unregister(): Boolean {
        val active = synchronized(deliveryLock) {
            synchronized(lock) {
                activeRegistration?.also { activeRegistration = null }
            }
        } ?: return false

        active.registration?.unregister()
        return true
    }

    override fun close() {
        unregister()
    }

    private fun unregisterExact(active: ActiveRegistration) {
        val owned = synchronized(deliveryLock) {
            synchronized(lock) {
                if (activeRegistration === active) {
                    activeRegistration = null
                    true
                } else {
                    false
                }
            }
        }
        if (owned) {
            active.registration?.unregister()
        }
    }

    private fun onEvent(
        token: Any,
        event: DefaultNetworkEvent,
    ) {
        synchronized(deliveryLock) {
            val emission = synchronized(lock) {
                val active = activeRegistration
                when {
                    active == null || active.token !== token -> null
                    !active.ready -> {
                        active.pendingEvents += event
                        null
                    }
                    else -> active.reducer.reduce(event)
                }
            }
            emission?.let(onConnectivityChanged)
        }
    }

    /**
     * Marks one exact registration ready and drains events that arrived while Android registration
     * was still being established. The whole drain is serialized with unregister/re-register, so
     * an old buffered result cannot escape after its registration has been invalidated.
     */
    private fun drainBufferedEvents(token: Any) {
        synchronized(deliveryLock) {
            val pending = synchronized(lock) {
                val active = activeRegistration
                if (active == null || active.token !== token) {
                    emptyList()
                } else {
                    active.ready = true
                    active.pendingEvents.toList().also { active.pendingEvents.clear() }
                }
            }

            pending.forEach { event ->
                val emission = synchronized(lock) {
                    val active = activeRegistration
                    if (active == null || active.token !== token) {
                        null
                    } else {
                        active.reducer.reduce(event)
                    }
                }
                emission?.let(onConnectivityChanged)
            }
        }
    }

    /**
     * Delivers only while the exact registration that produced [state] is still current.
     *
     * Holding [deliveryLock] across the callback means a concurrent unregister waits for an
     * already-started delivery to finish. A lifecycle transition that wins the gate first marks
     * the old token stale before any later callback can reduce or deliver another observation.
     * The callback itself may reentrantly call unregister because JVM monitors are reentrant.
     */
    private fun deliverIfCurrent(
        token: Any,
        state: ConnectivityState,
    ) {
        synchronized(deliveryLock) {
            val stillCurrent = synchronized(lock) {
                activeRegistration?.token === token
            }
            if (stillCurrent) {
                onConnectivityChanged(state)
            }
        }
    }

    private class ActiveRegistration(
        val token: Any,
        val reducer: DefaultNetworkStateReducer,
    ) {
        var registration: DefaultNetworkRegistration? = null
        var ready: Boolean = false
        val pendingEvents: MutableList<DefaultNetworkEvent> = mutableListOf()
    }
}
