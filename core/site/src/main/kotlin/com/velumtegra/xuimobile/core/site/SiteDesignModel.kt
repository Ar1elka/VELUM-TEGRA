package com.velumtegra.xuimobile.core.site

@JvmInline
value class DesignSeed(val value: Long) {
    fun derive(namespace: String): DesignSeed = DesignSeed(StableSeedHash.derive(value, namespace))
}

data class SiteDesignSeeds(
    val root: DesignSeed,
    val name: DesignSeed,
    val palette: DesignSeed,
    val background: DesignSeed,
    val typography: DesignSeed,
    val components: DesignSeed,
    val logo: DesignSeed,
) {
    companion object {
        fun fromRoot(root: DesignSeed): SiteDesignSeeds =
            SiteDesignSeeds(
                root = root,
                name = root.derive("site-name"),
                palette = root.derive("palette"),
                background = root.derive("background"),
                typography = root.derive("typography"),
                components = root.derive("components"),
                logo = root.derive("logo"),
            )
    }
}

data class SiteDesignRequest(
    val seeds: SiteDesignSeeds,
    val siteName: String? = null,
    val tagline: String? = null,
    val themeFamily: ThemeFamily? = null,
    val backgroundFamily: BackgroundFamily? = null,
    val typographyProfile: TypographyProfile? = null,
    val componentStyle: ComponentStyle? = null,
)

data class SiteDesign(
    val generatorVersion: Int,
    val seeds: SiteDesignSeeds,
    val identity: SiteIdentity,
    val palette: SitePalette,
    val background: BackgroundSpec,
    val typography: TypographyProfile,
    val componentStyle: ComponentStyle,
    val brand: SiteBrandMark,
)

data class SiteIdentity(
    val name: String,
    val tagline: String?,
)

enum class ThemeFamily {
    DARK_TECH,
    GRAPHITE_NEON,
    COOL_BLUE,
    VIOLET_MAGENTA,
    WARM_AMBER,
    LIGHT_MINIMAL,
    MUTED_PROFESSIONAL,
    MONOCHROME_ACCENT,
}

enum class BackgroundFamily {
    PARTICLE_NETWORK,
    GLOW_FIELDS,
    MESH_GRADIENT,
    TECH_GRID,
    GEOMETRY,
    MINIMAL,
    NOISE_TEXTURE,
}

enum class ComponentStyle {
    SOFT_ROUNDED,
    GLASS,
    OUTLINED,
    SOLID,
}

enum class TypographyProfile(val cssStack: String) {
    SYSTEM_MODERN("system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"),
    SYSTEM_COMPACT("Arial, Helvetica, sans-serif"),
    SYSTEM_TECH("ui-monospace, 'Cascadia Code', 'Segoe UI Mono', monospace"),
    SYSTEM_EDITORIAL("ui-serif, Georgia, 'Times New Roman', serif"),
}

data class SitePalette(
    val family: ThemeFamily,
    val backgroundPrimary: SiteColor,
    val backgroundSecondary: SiteColor,
    val surface: SiteColor,
    val surfaceElevated: SiteColor,
    val textPrimary: SiteColor,
    val textSecondary: SiteColor,
    val accentPrimary: SiteColor,
    val accentSecondary: SiteColor,
    val border: SiteColor,
)

data class BackgroundSpec(
    val family: BackgroundFamily,
    val animationEnabled: Boolean,
    val density: Int,
    val angleDegrees: Int,
    val primaryAnchorXPercent: Int,
    val primaryAnchorYPercent: Int,
    val secondaryAnchorXPercent: Int,
    val secondaryAnchorYPercent: Int,
    val reducedMotionFallback: BackgroundFamily = BackgroundFamily.MINIMAL,
)

enum class BrandShape {
    CIRCLE,
    ROUNDED_SQUARE,
    DIAMOND,
    HEXAGON,
    SHIELD,
    MONOGRAM,
}

data class SiteBrandMark(
    val initials: String,
    val shape: BrandShape,
    val svg: String,
)

data class SiteColor(
    val red: Int,
    val green: Int,
    val blue: Int,
) {
    init {
        require(red in 0..255 && green in 0..255 && blue in 0..255) {
            "RGB channels must be inside 0..255"
        }
    }

    val hex: String
        get() = "#%02X%02X%02X".format(red, green, blue)
}
