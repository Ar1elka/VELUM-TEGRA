package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertTrue
import org.junit.Test

class SiteThemeGeneratorTest {
    @Test
    fun `generated palettes satisfy contrast policy across broad seed sample`() {
        repeat(1024) { index ->
            ThemeFamily.entries.forEach { family ->
                val palette = SiteThemeGenerator.generate(DesignSeed(index.toLong()), family)

                assertTrue(
                    "primary text contrast failed for seed=$index family=$family",
                    SiteContrastPolicy.passesNormalText(
                        palette.textPrimary,
                        palette.backgroundPrimary,
                    ),
                )
                assertTrue(
                    "surface text contrast failed for seed=$index family=$family",
                    SiteContrastPolicy.passesNormalText(
                        palette.textPrimary,
                        palette.surface,
                    ),
                )
                assertTrue(
                    "accent contrast failed for seed=$index family=$family",
                    SiteContrastPolicy.contrastRatio(
                        palette.accentPrimary,
                        palette.backgroundPrimary,
                    ) >= SiteContrastPolicy.UI_ACCENT_MIN_RATIO,
                )
            }
        }
    }

    @Test
    fun `hex colors are stable uppercase css values`() {
        assertTrue(SiteColor(0, 15, 255).hex == "#000FFF")
    }
}
