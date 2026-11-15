package com.velumtegra.xuimobile.core.scanner.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RealityScannerServiceLifecyclePolicyTest {
    @Test
    fun startCreatesFreshRunningSessionWithoutErasingOfflineState() {
        val offline = ScannerLifecycleFlags(running = false, userPaused = true, networkLost = true)
        val started =
            RealityScannerServiceLifecyclePolicy.reduce(
                offline,
                ScannerLifecycleEvent.START,
            )

        assertEquals(
            ScannerLifecycleFlags(running = true, userPaused = false, networkLost = true),
            started,
        )
        assertTrue(started.paused)
    }

    @Test
    fun restoreDoesNotResetExistingSessionFlags() {
        val current = ScannerLifecycleFlags(running = true, userPaused = true, networkLost = false)

        assertEquals(
            current,
            RealityScannerServiceLifecyclePolicy.reduce(current, ScannerLifecycleEvent.RESTORE),
        )
    }

    @Test
    fun pauseAndResumeAreBlockedWhileNetworkIsLost() {
        val offline = ScannerLifecycleFlags(running = true, userPaused = false, networkLost = true)

        assertEquals(
            offline,
            RealityScannerServiceLifecyclePolicy.reduce(offline, ScannerLifecycleEvent.RESUME),
        )
        assertEquals(
            offline,
            RealityScannerServiceLifecyclePolicy.reduce(offline, ScannerLifecycleEvent.PAUSE),
        )
    }

    @Test
    fun networkLossAutoPausesAndAvailabilityAutoResumesWhenUserDidNotPause() {
        val running = ScannerLifecycleFlags(running = true, userPaused = false, networkLost = false)
        val lost =
            RealityScannerServiceLifecyclePolicy.reduce(
                running,
                ScannerLifecycleEvent.NETWORK_LOST,
            )

        assertTrue(lost.paused)
        assertEquals(
            running,
            RealityScannerServiceLifecyclePolicy.reduce(
                lost,
                ScannerLifecycleEvent.NETWORK_AVAILABLE,
            ),
        )
    }

    @Test
    fun networkRecoveryDoesNotEraseExplicitUserPause() {
        val manuallyPaused =
            ScannerLifecycleFlags(running = true, userPaused = true, networkLost = false)
        val lost =
            RealityScannerServiceLifecyclePolicy.reduce(
                manuallyPaused,
                ScannerLifecycleEvent.NETWORK_LOST,
            )
        val recovered =
            RealityScannerServiceLifecyclePolicy.reduce(
                lost,
                ScannerLifecycleEvent.NETWORK_AVAILABLE,
            )

        assertEquals(manuallyPaused, recovered)
        assertTrue(recovered.paused)
    }

    @Test
    fun stopClearsAllLifecycleFlags() {
        val current = ScannerLifecycleFlags(running = true, userPaused = true, networkLost = true)

        assertEquals(
            ScannerLifecycleFlags(running = false, userPaused = false, networkLost = false),
            RealityScannerServiceLifecyclePolicy.reduce(current, ScannerLifecycleEvent.STOP),
        )
    }
}
