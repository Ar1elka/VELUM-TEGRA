package com.velumtegra.xuimobile.core.scanner

import org.junit.Assert.assertEquals
import org.junit.Test

class RealitySniAnalysisPolicyTest {
    @Test
    fun exactWhitelistIsConfirmedWhenNotBlocked() {
        val match = RealitySniAnalysisPolicy.whitelistMatch("ok.ru", listOf("ok.ru"))
        val result = RealitySniAnalysisPolicy.classify("ok.ru", false, emptyList(), match, "test", 1L)

        assertEquals(RealityWhitelistMatch.EXACT, match)
        assertEquals(RealitySniVerdict.WHITELIST_CONFIRMED, result.verdict)
    }

    @Test
    fun parentOnlyMatchRemainsCandidate() {
        val match = RealitySniAnalysisPolicy.whitelistMatch("cdn.example.com", listOf("example.com"))
        val result = RealitySniAnalysisPolicy.classify("cdn.example.com", false, emptyList(), match, "test", 1L)

        assertEquals(RealityWhitelistMatch.PARENT_CANDIDATE, match)
        assertEquals(RealitySniVerdict.WHITELIST_CANDIDATE, result.verdict)
    }

    @Test
    fun explicitWildcardConfirmsSubdomain() {
        val match = RealitySniAnalysisPolicy.whitelistMatch("cdn.example.com", listOf("*.example.com"))
        assertEquals(RealityWhitelistMatch.EXPLICIT_WILDCARD, match)
    }

    @Test
    fun blockedEvidenceWinsOverWhitelistSnapshot() {
        val result =
            RealitySniAnalysisPolicy.classify(
                sni = "blocked.example",
                blocked = true,
                blockReasons = listOf("rkn_domain"),
                whitelistMatch = RealityWhitelistMatch.EXACT,
                source = "test",
                checkedAt = 1L,
            )

        assertEquals(RealitySniVerdict.BLOCKED, result.verdict)
        assertEquals(listOf("rkn_domain", "whitelist: exact"), result.reasons)
    }

    @Test
    fun clearNonWhitelistIsCleanAndMissingEvidenceIsUnknown() {
        assertEquals(
            RealitySniVerdict.CLEAN,
            RealitySniAnalysisPolicy.classify("clean.example", false, emptyList(), RealityWhitelistMatch.NONE, "test", 1L).verdict,
        )
        assertEquals(
            RealitySniVerdict.UNKNOWN,
            RealitySniAnalysisPolicy.classify("unknown.example", null, emptyList(), RealityWhitelistMatch.NONE, "test", 1L).verdict,
        )
    }
}
