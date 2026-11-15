package com.velumtegra.xuimobile.core.site

import java.security.MessageDigest

/** Deterministic read-only reconstruction of the SiteBundle tree digest from exact remote bytes. */
object SiteRemoteReadOnlyDigest {
    fun treeSha256(
        entries: List<SiteRemoteTransportTreeEntrySpec>,
        contentByRelativePath: Map<String, ByteArray>,
    ): String {
        require(entries.isNotEmpty()) { "Tree digest requires at least one entry" }
        require(entries.map { it.relativePath } == entries.map { it.relativePath }.sorted()) {
            "Tree digest entries must be sorted by relative path"
        }
        require(entries.map { it.relativePath }.distinct().size == entries.size) {
            "Tree digest entries must not contain duplicates"
        }
        val digest = MessageDigest.getInstance("SHA-256")
        entries.forEach { entry ->
            SiteBuildPolicy.validatePath(entry.relativePath)
            require(entry.mediaType.isNotBlank()) { "Tree digest media type must not be blank" }
            val content = requireNotNull(contentByRelativePath[entry.relativePath]) {
                "Tree digest content is missing: ${entry.relativePath}"
            }
            require(content.size <= SiteBuildPolicy.MAX_DOCUMENT_BYTES) { "Tree digest content exceeds document limit" }
            digest.update(entry.relativePath.encodeToByteArray())
            digest.update(0)
            digest.update(entry.mediaType.encodeToByteArray())
            digest.update(0)
            digest.update(content)
            digest.update(0)
        }
        require(contentByRelativePath.keys == entries.map { it.relativePath }.toSet()) {
            "Tree digest contains unexpected content entries"
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }
}
