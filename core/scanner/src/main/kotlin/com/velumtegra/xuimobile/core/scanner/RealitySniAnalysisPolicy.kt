package com.velumtegra.xuimobile.core.scanner

import java.net.IDN

enum class RealityWhitelistMatch {
    NONE,
    EXACT,
    EXPLICIT_WILDCARD,
    PARENT_CANDIDATE,
}

/** Pure evidence -> verdict projection. Network/source adapters remain outside this module. */
object RealitySniAnalysisPolicy {
    fun classify(
        sni: String,
        blocked: Boolean?,
        blockReasons: List<String>,
        whitelistMatch: RealityWhitelistMatch,
        source: String,
        checkedAt: Long,
    ): RealitySniAnalysis {
        val verdict =
            when {
                blocked == true -> RealitySniVerdict.BLOCKED
                whitelistMatch == RealityWhitelistMatch.EXACT ||
                    whitelistMatch == RealityWhitelistMatch.EXPLICIT_WILDCARD -> RealitySniVerdict.WHITELIST_CONFIRMED
                whitelistMatch == RealityWhitelistMatch.PARENT_CANDIDATE -> RealitySniVerdict.WHITELIST_CANDIDATE
                blocked == false -> RealitySniVerdict.CLEAN
                else -> RealitySniVerdict.UNKNOWN
            }

        val evidence =
            buildList {
                addAll(blockReasons.filter { it.isNotBlank() })
                when (whitelistMatch) {
                    RealityWhitelistMatch.EXACT -> add("whitelist: exact")
                    RealityWhitelistMatch.EXPLICIT_WILDCARD -> add("whitelist: wildcard")
                    RealityWhitelistMatch.PARENT_CANDIDATE -> add("whitelist: parent candidate")
                    RealityWhitelistMatch.NONE -> Unit
                }
            }.distinct()

        return RealitySniAnalysis(
            sni = normalizeDomain(sni) ?: sni.trim().lowercase(),
            verdict = verdict,
            reasons = evidence,
            source = source,
            checkedAt = checkedAt,
        )
    }

    /**
     * Conservative whitelist matching.
     * Exact/explicit wildcard rows are confirmed. A parent-only row is only a candidate because
     * public observations show that parent-domain allowlisting does not always imply every subdomain.
     */
    fun whitelistMatch(
        sni: String,
        whitelistEntries: Iterable<String>,
    ): RealityWhitelistMatch {
        val normalizedSni = normalizeDomain(sni) ?: return RealityWhitelistMatch.NONE
        var parentCandidate = false

        whitelistEntries.forEach { raw ->
            val value = raw.trim().trim('"', '\'').trimEnd('.').lowercase()
            if (value.isBlank() || value.startsWith("#")) return@forEach

            if (value.startsWith("*.")) {
                val base = normalizeDomain(value.removePrefix("*.")) ?: return@forEach
                if (normalizedSni != base && normalizedSni.endsWith(".$base")) {
                    return RealityWhitelistMatch.EXPLICIT_WILDCARD
                }
                return@forEach
            }

            val entry = normalizeDomain(value) ?: return@forEach
            if (normalizedSni == entry) return RealityWhitelistMatch.EXACT
            if (normalizedSni.endsWith(".$entry")) parentCandidate = true
        }

        return if (parentCandidate) RealityWhitelistMatch.PARENT_CANDIDATE else RealityWhitelistMatch.NONE
    }

    private fun normalizeDomain(raw: String): String? {
        val trimmed = raw.trim().trimEnd('.')
        if (trimmed.isBlank() || trimmed.contains('*') || trimmed.contains(':')) return null
        val ascii = runCatching { IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES) }.getOrNull() ?: return null
        val normalized = ascii.lowercase()
        if (normalized.length !in 1..253) return null
        val labels = normalized.split('.')
        if (labels.size < 2) return null
        if (labels.any { it.isBlank() || it.length > 63 }) return null
        return normalized
    }
}
