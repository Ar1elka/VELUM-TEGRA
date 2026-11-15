package com.velumtegra.xuimobile.core.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RealitySniCandidatePolicyTest {
    @Test
    fun `SAN DNS names are preferred, normalized and deduplicated before CN`() {
        val candidates =
            RealitySniCandidatePolicy.selectableCandidates(
                commonName = "Example.COM.",
                dnsSubjectAltNames = listOf("cdn.EXAMPLE.com", "example.com", "cdn.example.com"),
            )

        assertEquals(listOf("cdn.example.com", "example.com"), candidates)
    }

    @Test
    fun `wildcards and non host values are not exposed as selectable SNI`() {
        val candidates =
            RealitySniCandidatePolicy.selectableCandidates(
                commonName = "*.example.com",
                dnsSubjectAltNames = listOf("*.edge.example.com", "127.0.0.1", "good.example.com"),
            )

        assertEquals(listOf("good.example.com"), candidates)
    }

    @Test
    fun `requested concrete domain wins when certificate candidate contains it`() {
        val candidates = listOf("edge.example.com", "api.example.com")

        assertEquals(
            "api.example.com",
            RealitySniCandidatePolicy.defaultSelection("API.EXAMPLE.COM.", candidates),
        )
    }

    @Test
    fun `first candidate is deterministic fallback and empty input stays unselected`() {
        assertEquals(
            "edge.example.com",
            RealitySniCandidatePolicy.defaultSelection("missing.example.com", listOf("edge.example.com", "api.example.com")),
        )
        assertNull(RealitySniCandidatePolicy.defaultSelection(null, emptyList()))
    }
}
