package com.velumtegra.xuimobile.core.site

enum class SitePageKind(val path: String, val defaultNavLabel: String) {
    HOME("index.html", "Главная"),
    ABOUT("about.html", "О нас"),
    NEWS("news.html", "Новости"),
    RESOURCES("resources.html", "Ресурсы"),
    DOWNLOADS("downloads.html", "Загрузки"),
    CONTACT("contact.html", "Контакты"),
}

data class SiteContentSection(
    val title: String,
    val body: String,
)

data class SitePageSpec(
    val kind: SitePageKind,
    val navLabel: String = kind.defaultNavLabel,
    val heading: String,
    val lead: String,
    val sections: List<SiteContentSection> = emptyList(),
)

data class SiteBuildRequest(
    val design: SiteDesign,
    val pages: List<SitePageSpec> = emptyList(),
)

data class SiteDocument(
    val path: String,
    val mediaType: String,
    val content: String,
) {
    val byteSize: Int
        get() = content.encodeToByteArray().size

    val sha256: String
        get() = SiteBundleDigest.sha256(content.encodeToByteArray())
}

data class SiteBuildPreview(
    val siteName: String,
    val fileCount: Int,
    val totalBytes: Long,
    val paths: List<String>,
)

data class SiteBuildManifest(
    val builderVersion: Int,
    val designGeneratorVersion: Int,
    val siteName: String,
    val fileCount: Int,
    val totalBytes: Long,
    val treeSha256: String,
)

data class SiteBundle(
    val documents: List<SiteDocument>,
    val preview: SiteBuildPreview,
    val manifest: SiteBuildManifest,
)
