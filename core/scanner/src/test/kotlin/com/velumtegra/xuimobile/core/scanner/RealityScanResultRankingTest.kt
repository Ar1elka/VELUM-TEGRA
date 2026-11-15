package com.velumtegra.xuimobile.core.scanner

import org.junit.Assert.assertEquals
import org.junit.Test

class RealityScanResultRankingTest {
    @Test
    fun `lowest known latency is first and unknown latency is last`() {
        val slow = result("slow", 41)
        val unknown = result("unknown", null)
        val fast = result("fast", 7)

        assertEquals(
            listOf("fast", "slow", "unknown"),
            RealityScanResultRanking.byBestLatency(listOf(slow, unknown, fast)).map { it.ip },
        )
    }

    @Test
    fun `ties preserve input order deterministically`() {
        val first = result("first", 12)
        val second = result("second", 12)
        val third = result("third", 12)

        assertEquals(
            listOf("first", "second", "third"),
            RealityScanResultRanking.byBestLatency(listOf(first, second, third)).map { it.ip },
        )
    }

    @Test
    fun `negative legacy latency is treated as unknown`() {
        val valid = result("valid", 9)
        val negative = result("negative", -1)
        val missing = result("missing", null)

        assertEquals(
            listOf("valid", "negative", "missing"),
            RealityScanResultRanking.byBestLatency(listOf(negative, valid, missing)).map { it.ip },
        )
    }

    private fun result(ip: String, latencyMs: Long?): RealityScanResult =
        RealityScanResult(
            id = ip,
            origin = ip,
            ip = ip,
            port = 443,
            feasible = true,
            tls = RealityScannerTlsPolicy.TLS_13,
            alpn = "h2",
            certificateDomain = "example.com",
            certificateIssuer = "issuer",
            certificateSignature = "sig",
            certificatePublicKey = "key",
            certificateLength = 1,
            certificateCount = 1,
            latencyMs = latencyMs,
        )
}
