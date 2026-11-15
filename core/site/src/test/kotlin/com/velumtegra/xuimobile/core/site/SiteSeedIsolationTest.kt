package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class SiteSeedIsolationTest {
    @Test
    fun `changing only palette seed preserves independent design dimensions`() {
        val originalSeeds = SiteDesignSeeds.fromRoot(DesignSeed(9090))
        val changedSeeds = originalSeeds.copy(palette = DesignSeed(123456789))
        val request = SiteDesignRequest(seeds = originalSeeds, siteName = "Vela Station")
        val changedRequest = SiteDesignRequest(seeds = changedSeeds, siteName = "Vela Station")

        val original = SiteDesignGenerator.generate(request)
        val changed = SiteDesignGenerator.generate(changedRequest)

        assertEquals(original.identity, changed.identity)
        assertEquals(original.background, changed.background)
        assertEquals(original.typography, changed.typography)
        assertEquals(original.componentStyle, changed.componentStyle)
        assertEquals(original.brand.shape, changed.brand.shape)
        assertEquals(original.brand.initials, changed.brand.initials)
        assertNotEquals(original.palette, changed.palette)
        assertNotEquals(original.brand.svg, changed.brand.svg)
    }

    @Test
    fun `changing only background seed changes background without changing brand geometry`() {
        val originalSeeds = SiteDesignSeeds.fromRoot(DesignSeed(31337))
        val changedSeeds = originalSeeds.copy(background = DesignSeed(-99))

        val original = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = originalSeeds, siteName = "Nexora"),
        )
        val changed = SiteDesignGenerator.generate(
            SiteDesignRequest(seeds = changedSeeds, siteName = "Nexora"),
        )

        assertNotEquals(original.background, changed.background)
        assertEquals(original.palette, changed.palette)
        assertEquals(original.brand, changed.brand)
    }
}
