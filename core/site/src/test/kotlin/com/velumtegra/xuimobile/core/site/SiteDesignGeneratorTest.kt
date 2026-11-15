package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDesignGeneratorTest {
    @Test
    fun `same seed and inputs produce identical design`() {
        val seeds = SiteDesignSeeds.fromRoot(DesignSeed(0x1234ABCD))
        val request = SiteDesignRequest(seeds = seeds, tagline = "Private network tools")

        assertEquals(
            SiteDesignGenerator.generate(request),
            SiteDesignGenerator.generate(request),
        )
    }

    @Test
    fun `manual name is normalized and preserved`() {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(7)),
                siteName = "  Nova    Gate  ",
            ),
        )

        assertEquals("Nova Gate", design.identity.name)
        assertEquals("NG", design.brand.initials)
    }

    @Test
    fun `different root seeds produce different generated identities`() {
        val first = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(1))),
        )
        val second = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = SiteDesignSeeds.fromRoot(DesignSeed(2))),
        )

        assertNotEquals(first, second)
    }

    @Test
    fun `svg brand contains no external asset references`() {
        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(22)),
                siteName = "Astra Node",
            ),
        )

        assertTrue(design.brand.svg.startsWith("<svg"))
        assertTrue("href=" !in design.brand.svg)
        assertTrue("<image" !in design.brand.svg)
        assertTrue("<script" !in design.brand.svg)
    }
}
