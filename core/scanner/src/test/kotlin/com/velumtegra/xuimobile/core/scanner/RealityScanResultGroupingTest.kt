package com.velumtegra.xuimobile.core.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RealityScanResultGroupingTest {
    @Test
    fun separatesTls13AndTls12WithoutChangingBucketOrder() {
        val first13 = result(id = "13-a", tls = RealityScannerTlsPolicy.TLS_13)
        val first12 = result(id = "12-a", tls = RealityScannerTlsPolicy.TLS_12)
        val second13 = result(id = "13-b", tls = RealityScannerTlsPolicy.TLS_13)
        val second12 = result(id = "12-b", tls = RealityScannerTlsPolicy.TLS_12)

        val groups =
            RealityScanResultGrouping.split(
                listOf(first13, first12, second13, second12),
            )

        assertEquals(listOf(first13, second13), groups.tls13)
        assertEquals(listOf(first12, second12), groups.tls12)
        assertTrue(groups.other.isEmpty())
        assertEquals(4, groups.total)
    }

    @Test
    fun preservesUnexpectedLegacyProtocolsInFallbackBucket() {
        val legacy = result(id = "legacy", tls = "TLSv1.1")
        val blank = result(id = "blank", tls = "")

        val groups = RealityScanResultGrouping.split(listOf(legacy, blank))

        assertEquals(listOf(legacy, blank), groups.other)
        assertEquals(2, groups.total)
    }

    private fun result(id: String, tls: String): RealityScanResult =
        RealityScanResult(
            id = id,
            origin = "1.1.1.1",
            ip = "1.1.1.1",
            port = 443,
            feasible = true,
            tls = tls,
            alpn = "h2",
            certificateDomain = "example.com",
            certificateIssuer = "Example CA",
            certificateSignature = "SHA256withRSA",
            certificatePublicKey = "RSA",
            certificateLength = 1,
            certificateCount = 1,
        )
}
