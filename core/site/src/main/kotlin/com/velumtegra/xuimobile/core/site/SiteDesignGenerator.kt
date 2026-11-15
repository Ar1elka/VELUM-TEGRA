package com.velumtegra.xuimobile.core.site

object SiteDesignGenerator {
    const val GENERATOR_VERSION: Int = 1

    fun generate(request: SiteDesignRequest): SiteDesign {
        val identity = SiteIdentity(
            name = request.siteName?.let(SiteInputPolicy::normalizeName)
                ?: SiteNameGenerator.generate(request.seeds.name),
            tagline = request.tagline?.let(SiteInputPolicy::normalizeTagline),
        )
        val palette = SiteThemeGenerator.generate(
            seed = request.seeds.palette,
            requestedFamily = request.themeFamily,
        )
        val background = SiteBackgroundGenerator.generate(
            seed = request.seeds.background,
            requestedFamily = request.backgroundFamily,
        )
        val typography = request.typographyProfile
            ?: DeterministicRandom(request.seeds.typography).choose(TypographyProfile.entries)
        val componentStyle = request.componentStyle
            ?: DeterministicRandom(request.seeds.components).choose(ComponentStyle.entries)
        val brand = SiteBrandGenerator.generate(identity.name, request.seeds.logo, palette)

        return SiteDesign(
            generatorVersion = GENERATOR_VERSION,
            seeds = request.seeds,
            identity = identity,
            palette = palette,
            background = background,
            typography = typography,
            componentStyle = componentStyle,
            brand = brand,
        )
    }
}

object SiteInputPolicy {
    private const val MAX_NAME_LENGTH = 60
    private const val MAX_TAGLINE_LENGTH = 140

    fun normalizeName(input: String): String {
        val normalized = input.trim().replace(Regex("\\s+"), " ")
        require(normalized.length in 2..MAX_NAME_LENGTH) {
            "Site name must contain 2..$MAX_NAME_LENGTH characters"
        }
        require(normalized.none(Char::isISOControl)) { "Site name contains control characters" }
        require(normalized.any(Char::isLetterOrDigit)) { "Site name must contain a letter or digit" }
        return normalized
    }

    fun normalizeTagline(input: String): String {
        val normalized = input.trim().replace(Regex("\\s+"), " ")
        require(normalized.isNotEmpty()) { "Tagline must not be blank" }
        require(normalized.length <= MAX_TAGLINE_LENGTH) {
            "Tagline must not exceed $MAX_TAGLINE_LENGTH characters"
        }
        require(normalized.none(Char::isISOControl)) { "Tagline contains control characters" }
        return normalized
    }
}

object SiteNameGenerator {
    private val starts = listOf("Ae", "Arc", "Astra", "Evo", "Kai", "Lum", "Nex", "Nova", "Ori", "Sol", "Tera", "Vela", "Vio", "Zen")
    private val middles = listOf("l", "n", "r", "v", "x", "m", "d", "s")
    private val endings = listOf("ara", "era", "ia", "ion", "is", "ora", "os", "um", "yx", "eo")

    fun generate(seed: DesignSeed): String {
        val random = DeterministicRandom(seed)
        val base = buildString {
            append(random.choose(starts))
            if (random.nextInt(3) == 0) append(random.choose(middles))
            append(random.choose(endings))
        }
        return base.replaceFirstChar { it.uppercase() }
    }
}

object SiteBackgroundGenerator {
    fun generate(seed: DesignSeed, requestedFamily: BackgroundFamily? = null): BackgroundSpec {
        val random = DeterministicRandom(seed)
        val family = requestedFamily ?: random.choose(BackgroundFamily.entries)
        val animated = family == BackgroundFamily.PARTICLE_NETWORK || family == BackgroundFamily.MESH_GRADIENT
        val density = when (family) {
            BackgroundFamily.PARTICLE_NETWORK -> random.nextInt(1, 3)
            BackgroundFamily.GEOMETRY -> random.nextInt(1, 4)
            BackgroundFamily.NOISE_TEXTURE -> 1
            BackgroundFamily.MINIMAL -> 1
            else -> random.nextInt(1, 3)
        }
        return BackgroundSpec(
            family = family,
            animationEnabled = animated,
            density = density,
            angleDegrees = random.nextInt(0, 359),
            primaryAnchorXPercent = random.nextInt(10, 42),
            primaryAnchorYPercent = random.nextInt(8, 44),
            secondaryAnchorXPercent = random.nextInt(58, 92),
            secondaryAnchorYPercent = random.nextInt(56, 94),
        )
    }
}

object SiteBrandGenerator {
    fun generate(siteName: String, seed: DesignSeed, palette: SitePalette): SiteBrandMark {
        val random = DeterministicRandom(seed)
        val shape = random.choose(BrandShape.entries)
        val initials = initials(siteName)
        val svg = renderSvg(
            initials = initials,
            shape = shape,
            background = palette.accentPrimary,
            foreground = palette.backgroundPrimary,
        )
        return SiteBrandMark(initials = initials, shape = shape, svg = svg)
    }

    internal fun initials(siteName: String): String {
        val words = siteName.trim().split(Regex("[^\\p{L}\\p{N}]+"))
            .filter(String::isNotBlank)
        val raw = when {
            words.size >= 2 -> "${words[0].first()}${words[1].first()}"
            words.size == 1 -> words[0].take(2)
            else -> "S"
        }
        return raw.uppercase()
    }

    private fun renderSvg(
        initials: String,
        shape: BrandShape,
        background: SiteColor,
        foreground: SiteColor,
    ): String {
        val safeInitials = xmlEscape(initials)
        val shapeMarkup = when (shape) {
            BrandShape.CIRCLE -> "<circle cx=\"64\" cy=\"64\" r=\"54\" fill=\"${background.hex}\"/>"
            BrandShape.ROUNDED_SQUARE -> "<rect x=\"10\" y=\"10\" width=\"108\" height=\"108\" rx=\"28\" fill=\"${background.hex}\"/>"
            BrandShape.DIAMOND -> "<path d=\"M64 6 122 64 64 122 6 64Z\" fill=\"${background.hex}\"/>"
            BrandShape.HEXAGON -> "<path d=\"M32 9H96L123 64 96 119H32L5 64Z\" fill=\"${background.hex}\"/>"
            BrandShape.SHIELD -> "<path d=\"M64 7 111 24V58C111 91 91 111 64 122 37 111 17 91 17 58V24Z\" fill=\"${background.hex}\"/>"
            BrandShape.MONOGRAM -> "<circle cx=\"64\" cy=\"64\" r=\"56\" fill=\"${background.hex}\"/><circle cx=\"64\" cy=\"64\" r=\"44\" fill=\"none\" stroke=\"${foreground.hex}\" stroke-width=\"3\" opacity=\"0.55\"/>"
        }
        return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="$safeInitials">$shapeMarkup<text x="64" y="72" text-anchor="middle" font-family="system-ui,sans-serif" font-size="42" font-weight="700" fill="${foreground.hex}">$safeInitials</text></svg>"""
    }

    private fun xmlEscape(value: String): String =
        buildString(value.length) {
            value.forEach { ch ->
                when (ch) {
                    '&' -> append("&amp;")
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '"' -> append("&quot;")
                    '\'' -> append("&apos;")
                    else -> append(ch)
                }
            }
        }
}
