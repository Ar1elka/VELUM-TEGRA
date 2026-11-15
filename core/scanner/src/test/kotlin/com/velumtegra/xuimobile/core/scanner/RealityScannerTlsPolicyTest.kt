package com.velumtegra.xuimobile.core.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RealityScannerTlsPolicyTest {
    @Test
    fun defaultKeepsTls13OnlyEvenWhenTls12IsSupported() {
        assertEquals(
            listOf("TLSv1.3"),
            RealityScannerTlsPolicy.enabledProtocols(
                supportedProtocols = listOf("TLSv1.2", "TLSv1.3"),
                enableTls12 = false,
            ),
        )
        assertTrue(RealityScannerTlsPolicy.isAcceptedProtocol("TLSv1.3", enableTls12 = false))
        assertFalse(RealityScannerTlsPolicy.isAcceptedProtocol("TLSv1.2", enableTls12 = false))
    }

    @Test
    fun explicitOptInAddsTls12WithoutRemovingTls13Preference() {
        assertEquals(
            listOf("TLSv1.3", "TLSv1.2"),
            RealityScannerTlsPolicy.enabledProtocols(
                supportedProtocols = listOf("TLSv1", "TLSv1.2", "TLSv1.3"),
                enableTls12 = true,
            ),
        )
        assertTrue(RealityScannerTlsPolicy.isAcceptedProtocol("TLSv1.3", enableTls12 = true))
        assertTrue(RealityScannerTlsPolicy.isAcceptedProtocol("TLSv1.2", enableTls12 = true))
    }

    @Test
    fun optInCanUseTls12OnlyRuntimeWhenTls13IsUnavailable() {
        assertEquals(
            listOf("TLSv1.2"),
            RealityScannerTlsPolicy.enabledProtocols(
                supportedProtocols = listOf("TLSv1.2"),
                enableTls12 = true,
            ),
        )
    }

    @Test
    fun unsupportedProtocolsAreNeverEnabled() {
        assertEquals(
            emptyList<String>(),
            RealityScannerTlsPolicy.enabledProtocols(
                supportedProtocols = listOf("TLSv1.1"),
                enableTls12 = false,
            ),
        )
    }
}
