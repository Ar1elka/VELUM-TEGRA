package com.velumtegra.xuimobile.core.scanner

import java.net.IDN

/** Pure certificate-to-SNI projection used by the mobile Reality Scanner. */
object RealitySniCandidatePolicy {
    fun selectableCandidates(
        commonName: String,
        dnsSubjectAltNames: Iterable<String>,
    ): List<String> =
        buildList {
            dnsSubjectAltNames.forEach { raw -> normalizeSelectable(raw)?.let(::add) }
            normalizeSelectable(commonName)?.let(::add)
        }.distinct()

    fun defaultSelection(
        requestedDomain: String?,
        candidates: List<String>,
    ): String? {
        val requested = requestedDomain?.let(::normalizeSelectable)
        return candidates.firstOrNull { it == requested } ?: candidates.firstOrNull()
    }

    internal fun normalizeSelectable(raw: String): String? {
        val trimmed = raw.trim().trimEnd('.')
        if (trimmed.isBlank() || trimmed.contains('*')) return null

        val ascii = runCatching { IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES) }.getOrNull() ?: return null
        val normalized = ascii.lowercase()
        if (normalized.length !in 1..253 || normalized.contains(':')) return null

        val labels = normalized.split('.')
        if (labels.size < 2) return null
        if (labels.size == 4 && labels.all { it.toIntOrNull() in 0..255 }) return null
        if (labels.any { label ->
                label.isBlank() ||
                    label.length > 63 ||
                    label.startsWith('-') ||
                    label.endsWith('-') ||
                    !label.all { it.isLetterOrDigit() || it == '-' }
            }
        ) {
            return null
        }

        return normalized
    }
}
