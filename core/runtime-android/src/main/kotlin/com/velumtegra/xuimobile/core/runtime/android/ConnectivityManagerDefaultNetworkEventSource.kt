package com.velumtegra.xuimobile.core.runtime.android

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.util.concurrent.atomic.AtomicBoolean

/** Thin Android bridge. All semantic mapping lives in [DefaultNetworkStateReducer]. */
internal class ConnectivityManagerDefaultNetworkEventSource(
    private val connectivityManager: ConnectivityManager,
) : DefaultNetworkEventSource {
    override fun register(listener: DefaultNetworkEventListener): DefaultNetworkRegistration {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                listener.onEvent(DefaultNetworkEvent.Available(network.id()))
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                listener.onEvent(
                    DefaultNetworkEvent.CapabilitiesChanged(
                        networkId = network.id(),
                        capabilities = DefaultNetworkCapabilities(
                            hasInternetCapability = networkCapabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_INTERNET,
                            ),
                            isValidated = networkCapabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_VALIDATED,
                            ),
                        ),
                    ),
                )
            }

            override fun onBlockedStatusChanged(
                network: Network,
                blocked: Boolean,
            ) {
                listener.onEvent(
                    DefaultNetworkEvent.BlockedStatusChanged(
                        networkId = network.id(),
                        isBlocked = blocked,
                    ),
                )
            }

            override fun onLost(network: Network) {
                listener.onEvent(DefaultNetworkEvent.Lost(network.id()))
            }
        }

        connectivityManager.registerDefaultNetworkCallback(callback)
        val unregistered = AtomicBoolean(false)
        return DefaultNetworkRegistration {
            if (unregistered.compareAndSet(false, true)) {
                connectivityManager.unregisterNetworkCallback(callback)
            }
        }
    }

    private fun Network.id(): DefaultNetworkId = DefaultNetworkId(networkHandle)
}
