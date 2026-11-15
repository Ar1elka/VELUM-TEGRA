package com.velumtegra.xuimobile.scanner

import com.velumtegra.xuimobile.core.scanner.android.ScannerServiceState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScannerUiProjectionTest {
    @Test
    fun activeServiceStateProjectsWithoutChangingOwnershipFlags() {
        val projected =
            ScannerUiProjection.home(
                ScannerServiceState(
                    running = true,
                    paused = true,
                    networkLost = true,
                    total = 0,
                    completed = 17,
                    feasible = 4,
                    input = "1.1.1.1",
                    port = 443,
                    threads = 8,
                    ipv6 = false,
                ),
            )

        assertEquals(true, projected.running)
        assertEquals(true, projected.paused)
        assertEquals(true, projected.networkLost)
        assertEquals(17, projected.completed)
        assertEquals(4, projected.feasible)
    }

    @Test
    fun validatesApprovedPortAndThreadBounds() {
        assertEquals("Укажи IP, домен или CIDR.", ScannerUiProjection.validateStart("", "443", "2"))
        assertEquals("Порт должен быть от 1 до 65535.", ScannerUiProjection.validateStart("1.1.1.1", "0", "2"))
        assertEquals("Количество потоков должно быть от 1 до 32.", ScannerUiProjection.validateStart("1.1.1.1", "443", "33"))
        assertNull(ScannerUiProjection.validateStart("1.1.1.1", "443", "8"))
    }
}
