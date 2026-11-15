package com.velumtegra.xuimobile.core.runtime.android

import com.velumtegra.xuimobile.core.model.ConnectivityState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class DefaultNetworkObserverTest {
    @Test
    fun `available starts UNKNOWN and validated internet becomes ONLINE`() {
        val reducer = DefaultNetworkStateReducer()
        val network = DefaultNetworkId(1L)

        assertEquals(ConnectivityState.UNKNOWN, reducer.reduce(DefaultNetworkEvent.Available(network)))
        assertEquals(
            ConnectivityState.ONLINE,
            reducer.reduce(
                DefaultNetworkEvent.CapabilitiesChanged(
                    network,
                    DefaultNetworkCapabilities(
                        hasInternetCapability = true,
                        isValidated = true,
                    ),
                ),
            ),
        )
    }

    @Test
    fun `unvalidated or non Internet network remains UNKNOWN not OFFLINE`() {
        val reducer = DefaultNetworkStateReducer()
        val network = DefaultNetworkId(1L)
        reducer.reduce(DefaultNetworkEvent.Available(network))

        assertEquals(
            null,
            reducer.reduce(
                DefaultNetworkEvent.CapabilitiesChanged(
                    network,
                    DefaultNetworkCapabilities(
                        hasInternetCapability = true,
                        isValidated = false,
                    ),
                ),
            ),
        )
        assertEquals(ConnectivityState.UNKNOWN, reducer.currentState)

        assertEquals(
            null,
            reducer.reduce(
                DefaultNetworkEvent.CapabilitiesChanged(
                    network,
                    DefaultNetworkCapabilities(
                        hasInternetCapability = false,
                        isValidated = false,
                    ),
                ),
            ),
        )
        assertEquals(ConnectivityState.UNKNOWN, reducer.currentState)
    }

    @Test
    fun `blocked current default network maps to OFFLINE and unblocked restores capabilities state`() {
        val reducer = DefaultNetworkStateReducer()
        val network = DefaultNetworkId(1L)
        reducer.reduce(DefaultNetworkEvent.Available(network))
        reducer.reduce(
            DefaultNetworkEvent.CapabilitiesChanged(
                network,
                DefaultNetworkCapabilities(
                    hasInternetCapability = true,
                    isValidated = true,
                ),
            ),
        )

        assertEquals(
            ConnectivityState.OFFLINE,
            reducer.reduce(DefaultNetworkEvent.BlockedStatusChanged(network, true)),
        )
        assertEquals(
            ConnectivityState.ONLINE,
            reducer.reduce(DefaultNetworkEvent.BlockedStatusChanged(network, false)),
        )
    }

    @Test
    fun `loss of current network becomes OFFLINE`() {
        val reducer = DefaultNetworkStateReducer()
        val network = DefaultNetworkId(1L)
        reducer.reduce(DefaultNetworkEvent.Available(network))

        assertEquals(ConnectivityState.OFFLINE, reducer.reduce(DefaultNetworkEvent.Lost(network)))
    }

    @Test
    fun `stale callbacks from replaced network cannot overwrite newer default network`() {
        val reducer = DefaultNetworkStateReducer()
        val old = DefaultNetworkId(1L)
        val current = DefaultNetworkId(2L)
        reducer.reduce(DefaultNetworkEvent.Available(old))
        reducer.reduce(DefaultNetworkEvent.Available(current))

        assertEquals(null, reducer.reduce(DefaultNetworkEvent.Lost(old)))
        assertEquals(
            null,
            reducer.reduce(
                DefaultNetworkEvent.CapabilitiesChanged(
                    old,
                    DefaultNetworkCapabilities(true, true),
                ),
            ),
        )
        assertEquals(ConnectivityState.UNKNOWN, reducer.currentState)
    }

    @Test
    fun `new exact network emits a new observation even when mapped state stays UNKNOWN`() {
        val reducer = DefaultNetworkStateReducer()

        assertEquals(
            ConnectivityState.UNKNOWN,
            reducer.reduce(DefaultNetworkEvent.Available(DefaultNetworkId(1L))),
        )
        assertEquals(
            ConnectivityState.UNKNOWN,
            reducer.reduce(DefaultNetworkEvent.Available(DefaultNetworkId(2L))),
        )
    }

    @Test
    fun `repeated equivalent capabilities are coalesced`() {
        val reducer = DefaultNetworkStateReducer()
        val network = DefaultNetworkId(1L)
        val capabilities = DefaultNetworkCapabilities(true, true)
        reducer.reduce(DefaultNetworkEvent.Available(network))
        assertEquals(
            ConnectivityState.ONLINE,
            reducer.reduce(DefaultNetworkEvent.CapabilitiesChanged(network, capabilities)),
        )

        assertEquals(
            null,
            reducer.reduce(DefaultNetworkEvent.CapabilitiesChanged(network, capabilities)),
        )
    }

    @Test
    fun `observer registers and unregisters exact source once`() {
        val source = FakeDefaultNetworkEventSource()
        val states = mutableListOf<ConnectivityState>()
        val observer = AndroidDefaultNetworkObserver(source, states::add)

        assertTrue(observer.register())
        assertFalse(observer.register())
        assertEquals(1, source.registerCalls)
        assertEquals(listOf(ConnectivityState.OFFLINE), states)

        assertTrue(observer.unregister())
        assertFalse(observer.unregister())
        assertEquals(1, source.registrations.single().unregisterCalls)
    }

    @Test
    fun `late callback after unregister is ignored`() {
        val source = FakeDefaultNetworkEventSource()
        val states = mutableListOf<ConnectivityState>()
        val observer = AndroidDefaultNetworkObserver(source, states::add)
        observer.register()
        val registration = source.registrations.single()
        observer.unregister()

        registration.emit(DefaultNetworkEvent.Available(DefaultNetworkId(1L)))

        assertEquals(listOf(ConnectivityState.OFFLINE), states)
    }

    @Test
    fun `late callback from old registration cannot affect replacement registration`() {
        val source = FakeDefaultNetworkEventSource()
        val states = mutableListOf<ConnectivityState>()
        val observer = AndroidDefaultNetworkObserver(source, states::add)
        observer.register()
        val oldRegistration = source.registrations.single()
        observer.unregister()
        observer.register()
        val newRegistration = source.registrations.last()

        oldRegistration.emit(DefaultNetworkEvent.Available(DefaultNetworkId(1L)))
        newRegistration.emit(DefaultNetworkEvent.Available(DefaultNetworkId(2L)))

        assertEquals(
            listOf(
                ConnectivityState.OFFLINE,
                ConnectivityState.OFFLINE,
                ConnectivityState.UNKNOWN,
            ),
            states,
        )
    }


    @Test
    fun `events delivered during source registration are buffered behind initial OFFLINE`() {
        val network = DefaultNetworkId(7L)
        val source = object : DefaultNetworkEventSource {
            override fun register(listener: DefaultNetworkEventListener): DefaultNetworkRegistration {
                listener.onEvent(DefaultNetworkEvent.Available(network))
                listener.onEvent(
                    DefaultNetworkEvent.CapabilitiesChanged(
                        network,
                        DefaultNetworkCapabilities(true, true),
                    ),
                )
                return DefaultNetworkRegistration { }
            }
        }
        val states = mutableListOf<ConnectivityState>()
        val observer = AndroidDefaultNetworkObserver(source, states::add)

        assertTrue(observer.register())

        assertEquals(
            listOf(
                ConnectivityState.OFFLINE,
                ConnectivityState.UNKNOWN,
                ConnectivityState.ONLINE,
            ),
            states,
        )
    }

    @Test
    fun `registration failure clears ownership and allows a later exact retry`() {
        var attempts = 0
        val source = object : DefaultNetworkEventSource {
            override fun register(listener: DefaultNetworkEventListener): DefaultNetworkRegistration {
                attempts += 1
                if (attempts == 1) {
                    throw IllegalStateException("registration failed")
                }
                return DefaultNetworkRegistration { }
            }
        }
        val states = mutableListOf<ConnectivityState>()
        val observer = AndroidDefaultNetworkObserver(source, states::add)

        var failed = false
        try {
            observer.register()
        } catch (_: IllegalStateException) {
            failed = true
        }

        assertTrue(failed)
        assertTrue(observer.register())
        assertEquals(2, attempts)
        assertEquals(listOf(ConnectivityState.OFFLINE), states)
    }


    @Test
    fun `unregister waits for an in flight exact delivery before returning`() {
        val source = FakeDefaultNetworkEventSource()
        val states = Collections.synchronizedList(mutableListOf<ConnectivityState>())
        val deliveryStarted = CountDownLatch(1)
        val releaseDelivery = CountDownLatch(1)
        val observer = AndroidDefaultNetworkObserver(source) { state ->
            states += state
            if (state == ConnectivityState.UNKNOWN) {
                deliveryStarted.countDown()
                assertTrue(releaseDelivery.await(2, TimeUnit.SECONDS))
            }
        }
        observer.register()
        val oldRegistration = source.registrations.single()

        val emitter = thread(start = true) {
            oldRegistration.emit(DefaultNetworkEvent.Available(DefaultNetworkId(1L)))
        }
        assertTrue(deliveryStarted.await(2, TimeUnit.SECONDS))

        val unregisterDone = CountDownLatch(1)
        val unregistrar = thread(start = true) {
            observer.unregister()
            unregisterDone.countDown()
        }

        assertFalse(unregisterDone.await(100, TimeUnit.MILLISECONDS))
        releaseDelivery.countDown()
        emitter.join(2_000)
        unregistrar.join(2_000)
        assertTrue(unregisterDone.await(0, TimeUnit.MILLISECONDS))

        assertTrue(observer.register())
        assertEquals(
            listOf(
                ConnectivityState.OFFLINE,
                ConnectivityState.UNKNOWN,
                ConnectivityState.OFFLINE,
            ),
            states.toList(),
        )
    }

    @Test
    fun `reentrant unregister from delivery invalidates exact callback without deadlock`() {
        val source = FakeDefaultNetworkEventSource()
        val states = mutableListOf<ConnectivityState>()
        lateinit var observer: AndroidDefaultNetworkObserver
        observer = AndroidDefaultNetworkObserver(source) { state ->
            states += state
            if (state == ConnectivityState.UNKNOWN) {
                assertTrue(observer.unregister())
            }
        }

        assertTrue(observer.register())
        val oldRegistration = source.registrations.single()
        oldRegistration.emit(DefaultNetworkEvent.Available(DefaultNetworkId(1L)))

        assertFalse(observer.unregister())
        assertEquals(1, oldRegistration.unregisterCalls)
        assertTrue(observer.register())
        oldRegistration.emit(
            DefaultNetworkEvent.CapabilitiesChanged(
                DefaultNetworkId(1L),
                DefaultNetworkCapabilities(true, true),
            ),
        )

        assertEquals(
            listOf(
                ConnectivityState.OFFLINE,
                ConnectivityState.UNKNOWN,
                ConnectivityState.OFFLINE,
            ),
            states,
        )
    }

    private class FakeDefaultNetworkEventSource : DefaultNetworkEventSource {
        var registerCalls: Int = 0
        val registrations = mutableListOf<FakeRegistration>()

        override fun register(listener: DefaultNetworkEventListener): DefaultNetworkRegistration {
            registerCalls += 1
            return FakeRegistration(listener).also(registrations::add)
        }
    }

    private class FakeRegistration(
        private val listener: DefaultNetworkEventListener,
    ) : DefaultNetworkRegistration {
        var unregisterCalls: Int = 0

        override fun unregister() {
            unregisterCalls += 1
        }

        fun emit(event: DefaultNetworkEvent) {
            listener.onEvent(event)
        }
    }
}
