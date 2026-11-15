package com.velumtegra.xuimobile.core.site

object SiteBuilder {
    const val BUILDER_VERSION: Int = 2

    fun build(request: SiteBuildRequest): SiteBundle {
        SiteBuildPolicy.validateDesign(request.design)
        val pages = if (request.pages.isEmpty()) {
            DefaultSiteContent.pages(request.design)
        } else {
            request.pages.map(SitePageInputPolicy::normalize)
        }
        require(pages.isNotEmpty()) { "At least one site page is required" }
        require(pages.map(SitePageSpec::kind).distinct().size == pages.size) {
            "Only one page per SitePageKind is allowed"
        }
        require(pages.any { it.kind == SitePageKind.HOME }) { "Site bundle must contain a HOME page" }

        val orderedPages = pages.sortedBy { it.kind.ordinal }
        val documents = buildList {
            orderedPages.forEach { page ->
                add(
                    SiteDocument(
                        path = page.kind.path,
                        mediaType = "text/html; charset=utf-8",
                        content = SiteDocumentRenderer.renderPage(
                            design = request.design,
                            page = page,
                            navigation = orderedPages,
                        ),
                    ),
                )
            }
            add(
                SiteDocument(
                    path = "css/site.css",
                    mediaType = "text/css; charset=utf-8",
                    content = SiteDocumentRenderer.renderCss(request.design),
                ),
            )
            add(
                SiteDocument(
                    path = SiteBackdropRenderer.PATH,
                    mediaType = "image/svg+xml",
                    content = SiteBackdropRenderer.renderSvg(request.design),
                ),
            )
            add(
                SiteDocument(
                    path = "assets/brand.svg",
                    mediaType = "image/svg+xml",
                    content = request.design.brand.svg,
                ),
            )
        }.sortedBy(SiteDocument::path)

        val totalBytes = documents.sumOf { it.byteSize.toLong() }
        val preview = SiteBuildPreview(
            siteName = request.design.identity.name,
            fileCount = documents.size,
            totalBytes = totalBytes,
            paths = documents.map(SiteDocument::path),
        )
        val manifest = SiteBuildManifest(
            builderVersion = BUILDER_VERSION,
            designGeneratorVersion = request.design.generatorVersion,
            siteName = request.design.identity.name,
            fileCount = documents.size,
            totalBytes = totalBytes,
            treeSha256 = SiteBundleDigest.treeSha256(documents),
        )
        return SiteBundle(
            documents = documents,
            preview = preview,
            manifest = manifest,
        ).also(SiteBuildPolicy::validate)
    }
}

object SitePageInputPolicy {
    private const val MAX_NAV_LABEL = 32
    private const val MAX_HEADING = 96
    private const val MAX_LEAD = 320
    private const val MAX_SECTIONS = 12
    private const val MAX_SECTION_TITLE = 96
    private const val MAX_SECTION_BODY = 2000

    fun normalize(page: SitePageSpec): SitePageSpec =
        page.copy(
            navLabel = normalizeText(page.navLabel, "Navigation label", 1, MAX_NAV_LABEL),
            heading = normalizeText(page.heading, "Page heading", 1, MAX_HEADING),
            lead = normalizeText(page.lead, "Page lead", 1, MAX_LEAD),
            sections = page.sections.also {
                require(it.size <= MAX_SECTIONS) { "Page contains too many sections" }
            }.map { section ->
                section.copy(
                    title = normalizeText(section.title, "Section title", 1, MAX_SECTION_TITLE),
                    body = normalizeText(section.body, "Section body", 1, MAX_SECTION_BODY),
                )
            },
        )

    private fun normalizeText(input: String, label: String, minLength: Int, maxLength: Int): String {
        val normalized = input.trim().replace(Regex("\\s+"), " ")
        require(normalized.length in minLength..maxLength) {
            "$label must contain $minLength..$maxLength characters"
        }
        require(normalized.none(Char::isISOControl)) { "$label contains control characters" }
        return normalized
    }
}

internal object DefaultSiteContent {
    fun pages(design: SiteDesign): List<SitePageSpec> {
        val name = design.identity.name
        val tagline = design.identity.tagline ?: "Сайт скоро откроется. Мы готовим материалы — загляните чуть позже."
        return listOf(
            SitePageSpec(
                kind = SitePageKind.HOME,
                heading = name,
                lead = tagline,
                sections = listOf(
                    SiteContentSection(
                        title = "О проекте",
                        body = "Здесь появится короткий рассказ о том, чем занимается $name.",
                    ),
                    SiteContentSection(
                        title = "Новости",
                        body = "Следите за обновлениями — первые новости будут опубликованы в ближайшее время.",
                    ),
                    SiteContentSection(
                        title = "Связь",
                        body = "Контактные данные будут добавлены на странице «Контакты».",
                    ),
                ),
            ),
            SitePageSpec(
                kind = SitePageKind.ABOUT,
                heading = "О нас",
                lead = "Несколько слов о $name.",
                sections = listOf(
                    SiteContentSection(
                        title = "Кто мы",
                        body = "Этот раздел находится в подготовке.",
                    ),
                    SiteContentSection(
                        title = "Чем занимаемся",
                        body = "Подробное описание появится после запуска сайта.",
                    ),
                ),
            ),
            SitePageSpec(
                kind = SitePageKind.NEWS,
                heading = "Новости",
                lead = "Анонсы и обновления проекта.",
                sections = listOf(
                    SiteContentSection(
                        title = "Пока тихо",
                        body = "Новостей ещё нет. Загляните позже.",
                    ),
                ),
            ),
            SitePageSpec(
                kind = SitePageKind.RESOURCES,
                heading = "Ресурсы",
                lead = "Документация и полезные материалы.",
                sections = listOf(
                    SiteContentSection(
                        title = "В подготовке",
                        body = "Материалы будут опубликованы здесь.",
                    ),
                ),
            ),
            SitePageSpec(
                kind = SitePageKind.DOWNLOADS,
                heading = "Загрузки",
                lead = "Файлы и приложения для скачивания.",
                sections = listOf(
                    SiteContentSection(
                        title = "Скоро",
                        body = "Файлы для загрузки появятся после запуска.",
                    ),
                ),
            ),
            SitePageSpec(
                kind = SitePageKind.CONTACT,
                heading = "Контакты",
                lead = "Как с нами связаться.",
                sections = listOf(
                    SiteContentSection(
                        title = "Контактные данные",
                        body = "Контакты будут добавлены в ближайшее время.",
                    ),
                ),
            ),
        )
    }
}
