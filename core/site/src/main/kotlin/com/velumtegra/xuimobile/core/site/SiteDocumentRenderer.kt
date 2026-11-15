package com.velumtegra.xuimobile.core.site

internal object SiteDocumentRenderer {
    fun renderPage(
        design: SiteDesign,
        page: SitePageSpec,
        navigation: List<SitePageSpec>,
    ): String {
        val name = htmlEscape(design.identity.name)
        val title = if (page.kind == SitePageKind.HOME) name else "${htmlEscape(page.heading)} · $name"
        val nav = navigation.joinToString(separator = "") { item ->
            val current = item.kind == page.kind
            val currentAttr = if (current) " aria-current=\"page\"" else ""
            "<a class=\"nav-link${if (current) " is-active" else ""}\" href=\"${item.kind.path}\"$currentAttr>${htmlEscape(item.navLabel)}</a>"
        }
        val sections = page.sections.withIndex().joinToString(separator = "") { (index, section) ->
            "<section class=\"content-card\"><span class=\"card-index\">${"%02d".format(index + 1)}</span>" +
                "<h2>${htmlEscape(section.title)}</h2><p>${htmlEscape(section.body)}</p></section>"
        }
        val eyebrow = if (page.kind == SitePageKind.HOME) "Добро пожаловать" else design.identity.name
        val actions = if (page.kind == SitePageKind.HOME) heroActions(navigation) else ""
        val description = design.identity.tagline?.let(::htmlEscape) ?: htmlEscape(page.lead)
        val footerLinks = navigation.filter { it.kind != SitePageKind.HOME }.joinToString(separator = "") { item ->
            "<a href=\"${item.kind.path}\">${htmlEscape(item.navLabel)}</a>"
        }

        return """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="$description">
  <meta name="theme-color" content="${design.palette.backgroundPrimary.hex}">
  <title>$title</title>
  <link rel="icon" href="assets/brand.svg" type="image/svg+xml">
  <link rel="stylesheet" href="css/site.css">
</head>
<body class="site-body background-${design.background.family.name.lowercase().replace('_', '-')}">
  <div class="background-layer" aria-hidden="true"></div>
  <header class="site-header">
    <a class="brand" href="index.html" aria-label="$name — главная">
      <img src="assets/brand.svg" width="40" height="40" alt="">
      <span>$name</span>
    </a>
    <nav class="site-nav" aria-label="Основная навигация">$nav</nav>
  </header>
  <main class="site-main">
    <section class="hero">
      <p class="eyebrow"><span class="eyebrow-dot"></span>${htmlEscape(eyebrow)}</p>
      <h1>${htmlEscape(page.heading)}</h1>
      <p class="hero-lead">${htmlEscape(page.lead)}</p>$actions
    </section>
    <div class="content-grid">$sections</div>
  </main>
  <footer class="site-footer"><span class="footer-brand">© $name</span><nav class="footer-nav" aria-label="Ссылки в подвале">$footerLinks</nav></footer>
</body>
</html>
"""
    }

    private fun heroActions(navigation: List<SitePageSpec>): String {
        val primary = navigation.firstOrNull { it.kind == SitePageKind.ABOUT }
            ?: navigation.firstOrNull { it.kind != SitePageKind.HOME && it.kind != SitePageKind.CONTACT }
        val secondary = navigation.firstOrNull { it.kind == SitePageKind.CONTACT }
        if (primary == null && secondary == null) return ""
        return buildString {
            append("\n      <div class=\"hero-actions\">")
            primary?.let { append("<a class=\"button button-primary\" href=\"${it.kind.path}\">Подробнее</a>") }
            secondary?.let { append("<a class=\"button button-ghost\" href=\"${it.kind.path}\">${htmlEscape(it.navLabel)}</a>") }
            append("</div>")
        }
    }

    fun renderCss(design: SiteDesign): String {
        val p = design.palette
        val b = design.background
        val light = p.family == ThemeFamily.LIGHT_MINIMAL
        val radius = when (design.componentStyle) {
            ComponentStyle.SOFT_ROUNDED -> "24px"
            ComponentStyle.GLASS -> "20px"
            ComponentStyle.OUTLINED -> "14px"
            ComponentStyle.SOLID -> "10px"
        }
        val surface = when (design.componentStyle) {
            ComponentStyle.GLASS -> "color-mix(in srgb, ${p.surface.hex} 62%, transparent)"
            ComponentStyle.OUTLINED -> "color-mix(in srgb, ${p.surface.hex} 35%, transparent)"
            else -> "color-mix(in srgb, ${p.surface.hex} 88%, transparent)"
        }
        val shadow = when (design.componentStyle) {
            ComponentStyle.OUTLINED -> "none"
            ComponentStyle.SOLID -> if (light) "0 10px 30px rgba(15,23,42,.08)" else "0 14px 32px rgba(0,0,0,.28)"
            else -> if (light) "0 18px 48px rgba(15,23,42,.10)" else "0 20px 60px rgba(0,0,0,.35)"
        }
        val blur = if (design.componentStyle == ComponentStyle.GLASS || design.componentStyle == ComponentStyle.OUTLINED) "blur(16px)" else "blur(8px)"

        return """/* VELUM//TEGRA Site Builder v${SiteBuilder.BUILDER_VERSION}; background=${b.family.name}; component=${design.componentStyle.name} */
:root {
  color-scheme: ${if (light) "light" else "dark"};
  --bg: ${p.backgroundPrimary.hex};
  --bg-secondary: ${p.backgroundSecondary.hex};
  --surface: $surface;
  --surface-elevated: ${p.surfaceElevated.hex};
  --text: ${p.textPrimary.hex};
  --text-muted: ${p.textSecondary.hex};
  --accent: ${p.accentPrimary.hex};
  --accent-secondary: ${p.accentSecondary.hex};
  --border: ${p.border.hex};
  --radius: $radius;
  --shadow: $shadow;
  --font: ${design.typography.cssStack};
}
* { box-sizing: border-box; }
html { min-height: 100%; background: var(--bg); }
body { position: relative; margin: 0; min-height: 100vh; display: flex; flex-direction: column; color: var(--text); background: transparent; font-family: var(--font); line-height: 1.6; -webkit-font-smoothing: antialiased; }
a { color: inherit; }
${backgroundCss(b, p, light)}
.site-header, .site-main, .site-footer { width: min(1120px, calc(100% - 32px)); margin-inline: auto; }
.site-header { position: sticky; top: 12px; z-index: 5; display: flex; align-items: center; justify-content: space-between; gap: 20px; margin-top: 12px; padding: 10px 12px 10px 16px; border: 1px solid color-mix(in srgb, var(--border) 70%, transparent); border-radius: 18px; background: color-mix(in srgb, var(--bg) 62%, transparent); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); }
.brand { display: inline-flex; align-items: center; gap: 12px; font-weight: 750; text-decoration: none; letter-spacing: .01em; }
.brand img { border-radius: 12px; }
.site-nav { display: flex; flex-wrap: wrap; gap: 4px; }
.nav-link { padding: 8px 13px; border: 1px solid transparent; border-radius: 999px; color: var(--text-muted); font-size: .94rem; text-decoration: none; transition: color .2s, background-color .2s, border-color .2s; }
.nav-link:hover, .nav-link:focus-visible { color: var(--text); background: color-mix(in srgb, var(--surface-elevated) 70%, transparent); }
.nav-link.is-active { color: var(--text); border-color: color-mix(in srgb, var(--accent) 45%, transparent); background: color-mix(in srgb, var(--accent) 14%, transparent); }
.site-main { flex: 1; margin-top: 9vh; margin-bottom: 10vh; }
.hero { max-width: 860px; padding: 40px 0 56px; animation: site-rise .8s ease-out both; }
.eyebrow { display: inline-flex; align-items: center; gap: 10px; margin: 0 0 22px; padding: 6px 14px 6px 10px; border: 1px solid color-mix(in srgb, var(--accent) 35%, transparent); border-radius: 999px; background: color-mix(in srgb, var(--accent) 10%, transparent); color: var(--accent); font-size: .8rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.eyebrow-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 22%, transparent); animation: site-pulse 2.4s ease-in-out infinite; }
h1 { margin: 0; font-size: clamp(2.6rem, 7.5vw, 5.8rem); line-height: 1; letter-spacing: -.04em; background: linear-gradient(120deg, var(--text) 30%, var(--accent) 75%, var(--accent-secondary)); -webkit-background-clip: text; background-clip: text; color: transparent; }
.hero-lead { max-width: 680px; margin: 24px 0 0; color: var(--text-muted); font-size: clamp(1.05rem, 2vw, 1.3rem); }
.hero-actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 34px; }
.button { display: inline-flex; align-items: center; justify-content: center; min-height: 46px; padding: 0 22px; border-radius: 999px; font-weight: 650; text-decoration: none; transition: transform .2s, box-shadow .2s, background-color .2s; }
.button:hover { transform: translateY(-2px); }
.button-primary { color: var(--bg); background: linear-gradient(135deg, var(--accent), var(--accent-secondary)); box-shadow: 0 10px 30px color-mix(in srgb, var(--accent) 35%, transparent); }
.button-ghost { border: 1px solid var(--border); background: color-mix(in srgb, var(--surface-elevated) 55%, transparent); }
.content-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 18px; }
.content-card { position: relative; padding: 26px; border: 1px solid color-mix(in srgb, var(--border) 85%, transparent); border-radius: var(--radius); background: var(--surface); box-shadow: var(--shadow); backdrop-filter: $blur; -webkit-backdrop-filter: $blur; overflow: hidden; transition: transform .25s, border-color .25s; animation: site-rise .8s ease-out both; }
.content-card:nth-child(2) { animation-delay: .08s; } .content-card:nth-child(3) { animation-delay: .16s; } .content-card:nth-child(n+4) { animation-delay: .24s; }
.content-card::before { content: ""; position: absolute; inset: 0 0 auto; height: 2px; background: linear-gradient(90deg, var(--accent), var(--accent-secondary), transparent); opacity: .8; }
.content-card:hover { transform: translateY(-3px); border-color: color-mix(in srgb, var(--accent) 45%, transparent); }
.card-index { display: block; margin-bottom: 14px; color: var(--accent); font-size: .8rem; font-weight: 700; letter-spacing: .12em; }
.content-card h2 { margin: 0 0 8px; font-size: 1.12rem; }
.content-card p { margin: 0; color: var(--text-muted); }
.site-footer { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; padding: 24px 0 36px; border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent); color: var(--text-muted); font-size: .88rem; }
.footer-nav { display: flex; flex-wrap: wrap; gap: 18px; }
.footer-nav a { text-decoration: none; } .footer-nav a:hover { color: var(--text); }
@keyframes site-rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
@keyframes site-pulse { 0%, 100% { opacity: 1; } 50% { opacity: .45; } }
@keyframes site-drift { from { transform: translate3d(0, 0, 0) scale(1.05); } to { transform: translate3d(-3%, -2%, 0) scale(1.08); } }
@keyframes site-float { 0% { transform: translate3d(0, 0, 0) scale(1); } 50% { transform: translate3d(4%, 3%, 0) scale(1.08); } 100% { transform: translate3d(-3%, 5%, 0) scale(.96); } }
@keyframes site-mesh { 0% { background-position: 0% 0%, 100% 100%, 50% 0%, 0% 100%; } 100% { background-position: 100% 60%, 0% 30%, 30% 100%, 90% 0%; } }
@media (max-width: 720px) { .site-header { position: static; flex-direction: column; align-items: flex-start; } .site-main { margin-top: 4vh; } .hero { padding-top: 16px; } .site-footer { flex-direction: column; align-items: flex-start; } }
@media (prefers-reduced-motion: reduce) { .background-layer, .background-layer::before, .background-layer::after, .hero, .content-card, .eyebrow-dot { animation: none !important; } .button, .content-card { transition: none !important; } }
"""
    }

    private fun backgroundCss(background: BackgroundSpec, palette: SitePalette, light: Boolean): String {
        val angle = background.angleDegrees
        val a = "${background.primaryAnchorXPercent}% ${background.primaryAnchorYPercent}%"
        val c = "${background.secondaryAnchorXPercent}% ${background.secondaryAnchorYPercent}%"
        val accent = palette.accentPrimary.hex
        val accent2 = palette.accentSecondary.hex
        val glowAlpha = if (light) "22" else "40"
        val glowAlpha2 = if (light) "1C" else "33"
        val base = "linear-gradient(${angle}deg, ${palette.backgroundPrimary.hex}, ${palette.backgroundSecondary.hex})"
        val vignette = if (light) {
            "radial-gradient(ellipse at 50% 0%, transparent 40%, ${palette.backgroundPrimary.hex}AA 100%)"
        } else {
            "radial-gradient(ellipse at 50% 30%, transparent 35%, ${palette.backgroundPrimary.hex}E6 100%)"
        }
        val patternOpacity: String
        val patternAnimation: String
        val glows: String
        val glowAnimation: String
        val extraLayer: String
        when (background.family) {
            BackgroundFamily.PARTICLE_NETWORK -> {
                patternOpacity = "1"
                patternAnimation = "site-drift 60s ease-in-out infinite alternate"
                glows = "radial-gradient(circle at $a, $accent$glowAlpha2 0, transparent 40%), radial-gradient(circle at $c, $accent2$glowAlpha2 0, transparent 42%)"
                glowAnimation = "site-float 30s ease-in-out infinite alternate"
                extraLayer = ""
            }
            BackgroundFamily.GLOW_FIELDS -> {
                patternOpacity = "1"
                patternAnimation = "site-drift 90s linear infinite alternate"
                glows = "radial-gradient(circle at $a, $accent$glowAlpha 0, transparent 36%), radial-gradient(circle at $c, $accent2$glowAlpha 0, transparent 40%), radial-gradient(circle at 50% 110%, $accent$glowAlpha2 0, transparent 45%)"
                glowAnimation = "site-float 22s ease-in-out infinite alternate"
                extraLayer = ""
            }
            BackgroundFamily.MESH_GRADIENT -> {
                patternOpacity = "1"
                patternAnimation = "site-drift 45s ease-in-out infinite alternate"
                glows = "radial-gradient(circle, $accent$glowAlpha 0, transparent 60%), radial-gradient(circle, $accent2$glowAlpha 0, transparent 60%), radial-gradient(circle, $accent$glowAlpha2 0, transparent 55%), radial-gradient(circle, $accent2$glowAlpha2 0, transparent 55%); background-size: 70% 70%, 80% 80%, 60% 60%, 75% 75%; background-repeat: no-repeat"
                glowAnimation = "site-mesh 26s ease-in-out infinite alternate"
                extraLayer = ""
            }
            BackgroundFamily.TECH_GRID -> {
                patternOpacity = "1"
                patternAnimation = "site-drift 70s linear infinite alternate"
                glows = "radial-gradient(circle at $a, $accent$glowAlpha2 0, transparent 38%), radial-gradient(circle at $c, $accent2$glowAlpha2 0, transparent 40%)"
                glowAnimation = "site-float 28s ease-in-out infinite alternate"
                extraLayer = ".background-layer { background-image: linear-gradient(${palette.border.hex}${if (light) "55" else "40"} 1px, transparent 1px), linear-gradient(90deg, ${palette.border.hex}${if (light) "55" else "40"} 1px, transparent 1px), $base; background-size: 40px 40px, 40px 40px, auto; }\n" +
                    ".background-layer::before { -webkit-mask-image: radial-gradient(ellipse at 50% 20%, #000 30%, transparent 80%); mask-image: radial-gradient(ellipse at 50% 20%, #000 30%, transparent 80%); }\n"
            }
            BackgroundFamily.GEOMETRY -> {
                patternOpacity = "1"
                patternAnimation = "site-drift 55s ease-in-out infinite alternate"
                glows = "radial-gradient(circle at $a, $accent$glowAlpha2 0, transparent 40%), radial-gradient(circle at $c, $accent2$glowAlpha2 0, transparent 42%)"
                glowAnimation = "site-float 32s ease-in-out infinite alternate"
                extraLayer = ""
            }
            BackgroundFamily.MINIMAL -> {
                patternOpacity = "1"
                patternAnimation = "none"
                glows = "radial-gradient(ellipse at 70% -10%, $accent$glowAlpha2 0, transparent 55%)"
                glowAnimation = "site-float 40s ease-in-out infinite alternate"
                extraLayer = ""
            }
            BackgroundFamily.NOISE_TEXTURE -> {
                patternOpacity = "1"
                patternAnimation = "none"
                glows = "radial-gradient(circle at $a, $accent$glowAlpha 0, transparent 38%), radial-gradient(circle at $c, $accent2$glowAlpha2 0, transparent 42%)"
                glowAnimation = "site-float 26s ease-in-out infinite alternate"
                extraLayer = ""
            }
        }
        return """.background-layer { position: fixed; inset: 0; z-index: -1; overflow: hidden; pointer-events: none; background: $base; }
.background-layer::after { content: ""; position: absolute; inset: -15%; background: $glows; filter: blur(${if (light) "30px" else "20px"}); animation: $glowAnimation; }
.background-layer::before { content: ""; position: absolute; inset: -6%; z-index: 1; background: url("../${SiteBackdropRenderer.PATH}") center / cover no-repeat, $vignette; opacity: $patternOpacity; animation: $patternAnimation; }
$extraLayer"""
    }

    private fun htmlEscape(value: String): String =
        buildString(value.length) {
            value.forEach { ch ->
                when (ch) {
                    '&' -> append("&amp;")
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '"' -> append("&quot;")
                    '\'' -> append("&#39;")
                    else -> append(ch)
                }
            }
        }
}
