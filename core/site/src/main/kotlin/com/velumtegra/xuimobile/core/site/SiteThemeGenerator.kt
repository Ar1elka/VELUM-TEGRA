package com.velumtegra.xuimobile.core.site

import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt

object SiteContrastPolicy {
    const val NORMAL_TEXT_MIN_RATIO: Double = 4.5
    const val LARGE_TEXT_MIN_RATIO: Double = 3.0
    const val UI_ACCENT_MIN_RATIO: Double = 3.0

    fun contrastRatio(first: SiteColor, second: SiteColor): Double {
        val lighter = max(relativeLuminance(first), relativeLuminance(second))
        val darker = min(relativeLuminance(first), relativeLuminance(second))
        return (lighter + 0.05) / (darker + 0.05)
    }

    fun passesNormalText(foreground: SiteColor, background: SiteColor): Boolean =
        contrastRatio(foreground, background) >= NORMAL_TEXT_MIN_RATIO

    private fun relativeLuminance(color: SiteColor): Double {
        fun channel(value: Int): Double {
            val normalized = value / 255.0
            return if (normalized <= 0.04045) {
                normalized / 12.92
            } else {
                ((normalized + 0.055) / 1.055).pow(2.4)
            }
        }

        return 0.2126 * channel(color.red) +
            0.7152 * channel(color.green) +
            0.0722 * channel(color.blue)
    }
}

object SiteThemeGenerator {
    fun generate(seed: DesignSeed, requestedFamily: ThemeFamily? = null): SitePalette {
        val random = DeterministicRandom(seed)
        val family = requestedFamily ?: random.choose(ThemeFamily.entries)
        val hue = familyHue(family, random)
        val secondaryHue = normalizeHue(hue + random.nextInt(28, 78))

        val isLight = family == ThemeFamily.LIGHT_MINIMAL
        val monochrome = family == ThemeFamily.MONOCHROME_ACCENT
        val saturation = when (family) {
            ThemeFamily.MUTED_PROFESSIONAL -> random.nextInt(30, 48)
            ThemeFamily.MONOCHROME_ACCENT -> random.nextInt(8, 18)
            ThemeFamily.WARM_AMBER -> random.nextInt(72, 88)
            else -> random.nextInt(62, 86)
        }

        val backgroundPrimary = if (isLight) {
            hsl(hue, max(8, saturation / 5), random.nextInt(96, 98))
        } else {
            hsl(hue, max(10, saturation / 3), random.nextInt(6, 10))
        }
        val backgroundSecondary = if (isLight) {
            hsl(secondaryHue, max(10, saturation / 4), random.nextInt(92, 95))
        } else {
            hsl(secondaryHue, max(12, saturation / 3), random.nextInt(10, 14))
        }
        val surface = if (isLight) {
            hsl(hue, max(6, saturation / 6), random.nextInt(99, 100))
        } else {
            hsl(hue, max(12, saturation / 3), random.nextInt(13, 17))
        }
        val surfaceElevated = if (isLight) {
            hsl(secondaryHue, max(8, saturation / 5), random.nextInt(96, 98))
        } else {
            hsl(secondaryHue, max(14, saturation / 2), random.nextInt(17, 22))
        }
        val textPrimary = if (isLight) {
            hsl(hue, max(10, saturation / 4), random.nextInt(8, 13))
        } else {
            hsl(hue, max(5, saturation / 8), random.nextInt(94, 98))
        }
        val textSecondary = if (isLight) {
            hsl(hue, max(8, saturation / 5), random.nextInt(28, 36))
        } else {
            hsl(hue, max(6, saturation / 6), random.nextInt(72, 82))
        }

        val accentHue = when (family) {
            ThemeFamily.GRAPHITE_NEON -> normalizeHue(hue + random.nextInt(125, 205))
            ThemeFamily.COOL_BLUE -> random.nextInt(188, 218)
            ThemeFamily.VIOLET_MAGENTA -> random.nextInt(278, 326)
            ThemeFamily.WARM_AMBER -> random.nextInt(24, 44)
            ThemeFamily.MONOCHROME_ACCENT -> random.nextInt(178, 328)
            else -> hue
        }
        val accentSaturation = if (monochrome) random.nextInt(72, 90) else saturation
        val accentPrimary = accessibleAccent(
            hue = accentHue,
            saturation = if (isLight) max(62, accentSaturation) else max(64, accentSaturation),
            initialLightness = if (isLight) random.nextInt(28, 36) else random.nextInt(58, 68),
            background = backgroundPrimary,
            darkenForContrast = isLight,
        )
        val accentSecondary = if (isLight) {
            hsl(secondaryHue, max(56, saturation), random.nextInt(36, 45))
        } else {
            hsl(secondaryHue, max(58, saturation), random.nextInt(56, 66))
        }
        val border = if (isLight) {
            hsl(hue, max(8, saturation / 5), random.nextInt(78, 86))
        } else {
            hsl(hue, max(10, saturation / 4), random.nextInt(28, 36))
        }

        val palette = SitePalette(
            family = family,
            backgroundPrimary = backgroundPrimary,
            backgroundSecondary = backgroundSecondary,
            surface = surface,
            surfaceElevated = surfaceElevated,
            textPrimary = textPrimary,
            textSecondary = textSecondary,
            accentPrimary = accentPrimary,
            accentSecondary = accentSecondary,
            border = border,
        )
        require(SiteContrastPolicy.passesNormalText(textPrimary, backgroundPrimary)) {
            "Generated primary text contrast is below policy"
        }
        require(SiteContrastPolicy.passesNormalText(textPrimary, surface)) {
            "Generated surface text contrast is below policy"
        }
        val accentContrast = SiteContrastPolicy.contrastRatio(accentPrimary, backgroundPrimary)
        require(accentContrast >= SiteContrastPolicy.UI_ACCENT_MIN_RATIO) {
            "Generated accent contrast is below policy: family=$family ratio=$accentContrast accent=${accentPrimary.hex} background=${backgroundPrimary.hex}"
        }
        return palette
    }

    private fun accessibleAccent(
        hue: Int,
        saturation: Int,
        initialLightness: Int,
        background: SiteColor,
        darkenForContrast: Boolean,
    ): SiteColor {
        var lightness = initialLightness
        repeat(24) {
            val candidate = hsl(hue, saturation, lightness)
            if (SiteContrastPolicy.contrastRatio(candidate, background) >= SiteContrastPolicy.UI_ACCENT_MIN_RATIO) {
                return candidate
            }
            lightness = if (darkenForContrast) {
                (lightness - 2).coerceAtLeast(16)
            } else {
                (lightness + 2).coerceAtMost(86)
            }
        }
        error("Unable to derive an accent that satisfies contrast policy")
    }

    private fun familyHue(family: ThemeFamily, random: DeterministicRandom): Int =
        when (family) {
            ThemeFamily.DARK_TECH -> random.nextInt(190, 235)
            ThemeFamily.GRAPHITE_NEON -> random.nextInt(205, 250)
            ThemeFamily.COOL_BLUE -> random.nextInt(190, 220)
            ThemeFamily.VIOLET_MAGENTA -> random.nextInt(270, 325)
            ThemeFamily.WARM_AMBER -> random.nextInt(20, 44)
            ThemeFamily.LIGHT_MINIMAL -> random.nextInt(185, 250)
            ThemeFamily.MUTED_PROFESSIONAL -> random.nextInt(195, 235)
            ThemeFamily.MONOCHROME_ACCENT -> random.nextInt(200, 240)
        }

    internal fun hsl(hue: Int, saturationPercent: Int, lightnessPercent: Int): SiteColor {
        val h = normalizeHue(hue) / 360.0
        val s = saturationPercent.coerceIn(0, 100) / 100.0
        val l = lightnessPercent.coerceIn(0, 100) / 100.0

        if (s == 0.0) {
            val gray = (l * 255.0).roundToInt().coerceIn(0, 255)
            return SiteColor(gray, gray, gray)
        }

        val q = if (l < 0.5) l * (1 + s) else l + s - l * s
        val p = 2 * l - q

        fun hueToRgb(tInput: Double): Double {
            var t = tInput
            if (t < 0) t += 1.0
            if (t > 1) t -= 1.0
            return when {
                t < 1.0 / 6.0 -> p + (q - p) * 6.0 * t
                t < 1.0 / 2.0 -> q
                t < 2.0 / 3.0 -> p + (q - p) * (2.0 / 3.0 - t) * 6.0
                else -> p
            }
        }

        return SiteColor(
            red = (hueToRgb(h + 1.0 / 3.0) * 255.0).roundToInt().coerceIn(0, 255),
            green = (hueToRgb(h) * 255.0).roundToInt().coerceIn(0, 255),
            blue = (hueToRgb(h - 1.0 / 3.0) * 255.0).roundToInt().coerceIn(0, 255),
        )
    }

    private fun normalizeHue(value: Int): Int {
        val mod = value % 360
        return if (mod < 0) mod + 360 else mod
    }
}
