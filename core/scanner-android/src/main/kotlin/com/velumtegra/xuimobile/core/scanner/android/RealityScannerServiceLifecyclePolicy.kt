package com.velumtegra.xuimobile.core.scanner.android

internal data class ScannerLifecycleFlags(
    val running: Boolean,
    val userPaused: Boolean,
    val networkLost: Boolean,
) {
    val paused: Boolean
        get() = userPaused || networkLost
}

internal enum class ScannerLifecycleEvent {
    START,
    RESTORE,
    STOP,
    PAUSE,
    RESUME,
    NETWORK_LOST,
    NETWORK_AVAILABLE,
}

/** Pure lifecycle reducer used by the Android Foreground Service and frozen by JVM tests. */
internal object RealityScannerServiceLifecyclePolicy {
    fun reduce(current: ScannerLifecycleFlags, event: ScannerLifecycleEvent): ScannerLifecycleFlags =
        when (event) {
            ScannerLifecycleEvent.START ->
                ScannerLifecycleFlags(
                    running = true,
                    userPaused = false,
                    // Network state is environmental and must survive a fresh START.
                    networkLost = current.networkLost,
                )

            ScannerLifecycleEvent.RESTORE -> current

            ScannerLifecycleEvent.STOP ->
                ScannerLifecycleFlags(
                    running = false,
                    userPaused = false,
                    networkLost = false,
                )

            ScannerLifecycleEvent.PAUSE ->
                if (current.running && !current.networkLost) {
                    current.copy(userPaused = true)
                } else {
                    current
                }

            ScannerLifecycleEvent.RESUME ->
                if (current.running && !current.networkLost) {
                    current.copy(userPaused = false)
                } else {
                    current
                }

            ScannerLifecycleEvent.NETWORK_LOST -> current.copy(networkLost = true)
            ScannerLifecycleEvent.NETWORK_AVAILABLE -> current.copy(networkLost = false)
        }
}
