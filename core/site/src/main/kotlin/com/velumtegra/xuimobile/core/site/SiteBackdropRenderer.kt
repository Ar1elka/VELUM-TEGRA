package com.velumtegra.xuimobile.core.site

import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Deterministic decorative backdrop for the generated site.
 *
 * The backdrop is a self-contained static SVG (no scripts, no external references, no embedded
 * images) derived only from the background seed, the background family and the palette. Motion is
 * added by CSS and is fully disabled under `prefers-reduced-motion`.
 */
internal object SiteBackdropRenderer {
    const val PATH: String = "assets/backdrop.svg"

    private const val WIDTH = 1600
    private const val HEIGHT = 1000

    fun renderSvg(design: SiteDesign): String {
        val random = DeterministicRandom(design.seeds.background.derive("backdrop"))
        val p = design.palette
        val light = p.family == ThemeFamily.LIGHT_MINIMAL
        val body = when (design.background.family) {
            BackgroundFamily.PARTICLE_NETWORK -> particleNetwork(random, p, light, design.background.density)
            BackgroundFamily.GLOW_FIELDS -> starField(random, p, light, 140)
            BackgroundFamily.MESH_GRADIENT -> flowLines(random, p, light)
            BackgroundFamily.TECH_GRID -> circuit(random, p, light)
            BackgroundFamily.GEOMETRY -> geometry(random, p, light, design.background.density)
            BackgroundFamily.MINIMAL -> rings(random, p, light)
            BackgroundFamily.NOISE_TEXTURE -> noise(random, p, light)
        }
        return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $WIDTH $HEIGHT" preserveAspectRatio="xMidYMid slice" aria-hidden="true">$body</svg>
"""
    }

    private fun particleNetwork(random: DeterministicRandom, p: SitePalette, light: Boolean, density: Int): String {
        val count = 46 + density * 14
        val nodes = List(count) { Pair(random.nextInt(0, WIDTH).toDouble(), random.nextInt(0, HEIGHT).toDouble()) }
        val maxDistance = 190.0
        val lineOpacity = if (light) 0.3 else 0.42
        val lines = buildString {
            for (i in nodes.indices) {
                for (j in i + 1 until nodes.size) {
                    val (x1, y1) = nodes[i]
                    val (x2, y2) = nodes[j]
                    val d = sqrt((x1 - x2) * (x1 - x2) + (y1 - y2) * (y1 - y2))
                    if (d < maxDistance) {
                        val o = fmt(lineOpacity * (1.0 - d / maxDistance))
                        append("<line x1=\"${x1.toInt()}\" y1=\"${y1.toInt()}\" x2=\"${x2.toInt()}\" y2=\"${y2.toInt()}\" stroke-opacity=\"$o\"/>")
                    }
                }
            }
        }
        val dots = buildString {
            nodes.forEachIndexed { index, (x, y) ->
                val color = if (index % 3 == 0) p.accentSecondary.hex else p.accentPrimary.hex
                val r = random.nextInt(15, 32) / 10.0
                append("<circle cx=\"${x.toInt()}\" cy=\"${y.toInt()}\" r=\"${fmt(r)}\" fill=\"$color\" fill-opacity=\"${if (light) "0.55" else "0.8"}\"/>")
                if (index % 7 == 0) {
                    append("<circle cx=\"${x.toInt()}\" cy=\"${y.toInt()}\" r=\"${fmt(r * 4)}\" fill=\"$color\" fill-opacity=\"0.10\"/>")
                }
            }
        }
        return "<g stroke=\"${p.accentPrimary.hex}\" stroke-width=\"1\">$lines</g><g>$dots</g>"
    }

    private fun starField(random: DeterministicRandom, p: SitePalette, light: Boolean, count: Int): String {
        val stars = buildString {
            repeat(count) { index ->
                val x = random.nextInt(0, WIDTH)
                val y = random.nextInt(0, HEIGHT)
                val r = random.nextInt(5, 18) / 10.0
                val color = if (index % 4 == 0) p.accentSecondary.hex else if (light) p.textSecondary.hex else p.textPrimary.hex
                val o = random.nextInt(15, if (light) 35 else 70) / 100.0
                append("<circle cx=\"$x\" cy=\"$y\" r=\"${fmt(r)}\" fill=\"$color\" fill-opacity=\"${fmt(o)}\"/>")
            }
        }
        return stars
    }

    private fun flowLines(random: DeterministicRandom, p: SitePalette, light: Boolean): String {
        val baseY = random.nextInt(260, 520)
        val amplitude = random.nextInt(70, 150)
        val phase = random.nextInt(0, 628) / 100.0
        val lines = buildString {
            repeat(18) { index ->
                val offset = baseY + index * 22
                val path = buildString {
                    var x = -40
                    append("M$x ${offset}")
                    while (x <= WIDTH + 40) {
                        x += 40
                        val y = offset + amplitude * sin(x / 260.0 + phase + index * 0.12) * (0.6 + index / 40.0)
                        append(" L$x ${y.toInt()}")
                    }
                }
                val color = if (index % 2 == 0) p.accentPrimary.hex else p.accentSecondary.hex
                val o = (if (light) 0.10 else 0.16) + index * 0.006
                append("<path d=\"$path\" fill=\"none\" stroke=\"$color\" stroke-width=\"1.2\" stroke-opacity=\"${fmt(o)}\"/>")
            }
        }
        return lines
    }

    private fun circuit(random: DeterministicRandom, p: SitePalette, light: Boolean): String {
        val step = 40
        val traces = buildString {
            repeat(26) { index ->
                var x = random.nextInt(0, WIDTH / step) * step
                var y = random.nextInt(0, HEIGHT / step) * step
                val path = StringBuilder("M$x $y")
                repeat(random.nextInt(3, 6)) {
                    if (random.nextInt(2) == 0) x += step * random.nextInt(-5, 5) else y += step * random.nextInt(-4, 4)
                    path.append(" L$x $y")
                }
                val color = if (index % 3 == 0) p.accentSecondary.hex else p.accentPrimary.hex
                append("<path d=\"$path\" fill=\"none\" stroke=\"$color\" stroke-width=\"1.5\" stroke-opacity=\"${if (light) "0.25" else "0.4"}\" stroke-linejoin=\"round\"/>")
                append("<circle cx=\"$x\" cy=\"$y\" r=\"3.5\" fill=\"$color\" fill-opacity=\"${if (light) "0.45" else "0.75"}\"/>")
            }
        }
        return traces
    }

    private fun geometry(random: DeterministicRandom, p: SitePalette, light: Boolean, density: Int): String {
        val shapes = buildString {
            repeat(18 + density * 6) { index ->
                val cx = random.nextInt(0, WIDTH)
                val cy = random.nextInt(0, HEIGHT)
                val size = random.nextInt(24, 110)
                val rotation = random.nextInt(0, 359)
                val sides = random.choose(listOf(3, 4, 6, 0))
                val color = if (index % 2 == 0) p.accentPrimary.hex else p.accentSecondary.hex
                val o = random.nextInt(if (light) 14 else 20, if (light) 30 else 45) / 100.0
                val filled = index % 5 == 0
                val paint = if (filled) {
                    "fill=\"$color\" fill-opacity=\"${fmt(o / 3)}\" stroke=\"none\""
                } else {
                    "fill=\"none\" stroke=\"$color\" stroke-opacity=\"${fmt(o)}\" stroke-width=\"1.5\""
                }
                if (sides == 0) {
                    append("<circle cx=\"$cx\" cy=\"$cy\" r=\"${size / 2}\" $paint/>")
                } else {
                    val points = (0 until sides).joinToString(" ") { k ->
                        val a = 2 * PI * k / sides + rotation * PI / 180
                        "${(cx + size / 2.0 * cos(a)).toInt()},${(cy + size / 2.0 * sin(a)).toInt()}"
                    }
                    append("<polygon points=\"$points\" $paint/>")
                }
            }
        }
        return shapes
    }

    private fun rings(random: DeterministicRandom, p: SitePalette, light: Boolean): String {
        val cx = random.nextInt(1000, 1450)
        val cy = random.nextInt(150, 400)
        return buildString {
            repeat(7) { index ->
                val r = 140 + index * 70
                val o = (if (light) 0.16 else 0.2) - index * 0.018
                append("<circle cx=\"$cx\" cy=\"$cy\" r=\"$r\" fill=\"none\" stroke=\"${p.accentPrimary.hex}\" stroke-opacity=\"${fmt(o)}\" stroke-width=\"1\"/>")
            }
        }
    }

    private fun noise(random: DeterministicRandom, p: SitePalette, light: Boolean): String {
        val seed = random.nextInt(1, 999)
        val o = if (light) "0.07" else "0.11"
        return "<filter id=\"n\"><feTurbulence type=\"fractalNoise\" baseFrequency=\"0.85\" numOctaves=\"3\" seed=\"$seed\" stitchTiles=\"stitch\"/><feColorMatrix type=\"saturate\" values=\"0\"/></filter>" +
            "<rect width=\"100%\" height=\"100%\" filter=\"url(#n)\" opacity=\"$o\"/>" +
            starField(random, p, light, 40)
    }

    private fun fmt(value: Double): String {
        val rounded = Math.round(value * 1000.0) / 1000.0
        return if (rounded == rounded.toLong().toDouble()) rounded.toLong().toString() else rounded.toString()
    }
}
