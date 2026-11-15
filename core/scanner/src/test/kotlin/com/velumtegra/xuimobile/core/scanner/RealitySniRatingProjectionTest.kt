package com.velumtegra.xuimobile.core.scanner

import org.junit.Assert.assertEquals
import org.junit.Test

class RealitySniRatingProjectionTest {
    @Test
    fun cleanAndConfirmedWhitelistStayInSeparateBestPingColumns() {
        val cleanSlow = result("clean-slow", 44, RealitySniVerdict.CLEAN)
        val whiteSlow = result("white-slow", 31, RealitySniVerdict.WHITELIST_CONFIRMED)
        val cleanFast = result("clean-fast", 8, RealitySniVerdict.CLEAN)
        val whiteFast = result("white-fast", 6, RealitySniVerdict.WHITELIST_CONFIRMED)

        val rating = RealitySniRatingProjection.project(listOf(cleanSlow, whiteSlow, cleanFast, whiteFast))

        assertEquals(listOf("clean-fast", "clean-slow"), rating.clean.map { it.id })
        assertEquals(listOf("white-fast", "white-slow"), rating.whitelist.map { it.id })
        assertEquals(4, rating.ratedCount)
        assertEquals(emptyList<RealityScanResult>(), rating.remainder)
    }

    @Test
    fun candidateBlockedUnknownAndUnanalyzedNeverEnterTopColumns() {
        val candidate = result("candidate", 1, RealitySniVerdict.WHITELIST_CANDIDATE)
        val blocked = result("blocked", 2, RealitySniVerdict.BLOCKED)
        val unknown = result("unknown", 3, RealitySniVerdict.UNKNOWN)
        val unanalyzed = result("unanalyzed", 4, null)

        val rating = RealitySniRatingProjection.project(listOf(candidate, blocked, unknown, unanalyzed))

        assertEquals(emptyList<RealityScanResult>(), rating.clean)
        assertEquals(emptyList<RealityScanResult>(), rating.whitelist)
        assertEquals(listOf("candidate", "blocked", "unknown", "unanalyzed"), rating.remainder.map { it.id })
    }

    @Test
    fun staleAnalysisForDifferentSniIsKeptOutOfTopColumns() {
        val stale =
            result("stale", 5, RealitySniVerdict.CLEAN).copy(
                selectedSni = "new.example",
                sniAnalysis = analysis("old.example", RealitySniVerdict.CLEAN),
            )

        val rating = RealitySniRatingProjection.project(listOf(stale))

        assertEquals(emptyList<RealityScanResult>(), rating.clean)
        assertEquals(emptyList<RealityScanResult>(), rating.whitelist)
        assertEquals(listOf(stale), rating.remainder)
    }

    private fun result(id: String, latencyMs: Long?, verdict: RealitySniVerdict?): RealityScanResult =
        RealityScanResult(
            id = id,
            origin = "1.1.1.1",
            ip = "1.1.1.1",
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
            sniCandidates = listOf("$id.example"),
            selectedSni = "$id.example",
            sniAnalysis = verdict?.let { analysis("$id.example", it) },
        )

    private fun analysis(sni: String, verdict: RealitySniVerdict): RealitySniAnalysis =
        RealitySniAnalysis(
            sni = sni,
            verdict = verdict,
            source = "test",
            checkedAt = 1L,
        )
}
