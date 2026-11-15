package com.velumtegra.xuimobile.core.scanner.android

import android.content.Context
import com.velumtegra.xuimobile.core.scanner.RealitySniAnalysis
import com.velumtegra.xuimobile.core.scanner.RealitySniAnalysisPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * Fail-soft public-source SNI analyzer.
 *
 * The adapter is intentionally isolated from the scanner engine. It currently consumes the
 * Cheburcheck-compatible public check endpoint plus the published whitelist CSV, so the UI/model
 * contract can later be pointed at a self-hosted compatible source without changing scan ownership.
 */
class CheburcheckSniAnalyzer(
    context: Context,
    private val baseUrl: String = "https://cheburcheck.ru",
) {
    companion object {
        private const val PREFS = "velum_reality_sni_analyzer"
        private const val KEY_WHITELIST = "whitelist_csv"
        private const val KEY_WHITELIST_AT = "whitelist_fetched_at"
        private const val CACHE_TTL_MS = 6L * 60L * 60L * 1000L
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val READ_TIMEOUT_MS = 7_000
        private const val MAX_TEXT_BYTES = 2_000_000
    }

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    suspend fun analyze(sni: String): RealitySniAnalysis =
        withContext(Dispatchers.IO) {
            val now = System.currentTimeMillis()
            runCatching {
                val blockEvidence = queryBlockEvidence(sni)
                val whitelist = loadWhitelistIndex(now)
                val whitelistMatch = RealitySniAnalysisPolicy.whitelistMatch(sni, whitelist.relevantTo(sni))

                RealitySniAnalysisPolicy.classify(
                    sni = sni,
                    blocked = blockEvidence?.blocked,
                    blockReasons = blockEvidence?.reasons.orEmpty(),
                    whitelistMatch = whitelistMatch,
                    source = buildSource(blockEvidence != null, !whitelist.isEmpty),
                    checkedAt = now,
                )
            }.getOrElse { error ->
                RealitySniAnalysisPolicy.classify(
                    sni = sni,
                    blocked = null,
                    blockReasons = listOf("analyzer: ${error.javaClass.simpleName}"),
                    whitelistMatch = com.velumtegra.xuimobile.core.scanner.RealityWhitelistMatch.NONE,
                    source = "unavailable",
                    checkedAt = now,
                )
            }
        }

    private data class BlockEvidence(
        val blocked: Boolean?,
        val reasons: List<String>,
    )

    private fun queryBlockEvidence(sni: String): BlockEvidence? =
        runCatching {
            val encoded = URLEncoder.encode(sni, StandardCharsets.UTF_8.name())
            val body = readUrl("$baseUrl/api/v1/check?target=$encoded") ?: return null
            val root = JSONObject(body)
            val payload = root.optJSONObject("result") ?: root
            val status = payload.optString("status").trim().lowercase()
            val blocked =
                when {
                    status == "blocked" || status == "block" -> true
                    status == "clear" || status == "clean" || status == "ok" -> false
                    payload.has("blocked") && !payload.isNull("blocked") -> payload.optBoolean("blocked")
                    else -> null
                }
            BlockEvidence(blocked = blocked, reasons = extractReasons(payload))
        }.getOrNull()

    private fun extractReasons(payload: JSONObject): List<String> {
        val reasons = payload.optJSONArray("reasons") ?: return emptyList()
        return buildList {
            for (index in 0 until reasons.length()) {
                when (val value = reasons.opt(index)) {
                    is String -> value.takeIf { it.isNotBlank() }?.let(::add)
                    is JSONObject -> {
                        val label =
                            value.optString("reason")
                                .ifBlank { value.optString("type") }
                                .ifBlank { value.optString("name") }
                        if (label.isNotBlank()) add(label)
                    }
                }
            }
        }.distinct()
    }

    /**
     * The whitelist can hold a very large number of rows and the policy normalizes every row it is given.
     * Parsing the CSV and walking all rows for each SNI made a batch check crawl, so the list is parsed once
     * per download and only rows that can match the SNI (itself or a parent domain) reach the policy.
     */
    private class WhitelistIndex(entries: List<String>) {
        private val byKey = HashMap<String, MutableList<String>>()
        private val unindexed = mutableListOf<String>() // non-ASCII rows: the policy applies IDN rules itself

        val isEmpty: Boolean = entries.isEmpty()

        init {
            entries.forEach { raw ->
                val cleaned = raw.trim().trim('"', '\'').trimEnd('.').lowercase()
                if (cleaned.all { it.code < 128 }) {
                    byKey.getOrPut(cleaned.removePrefix("*.")) { mutableListOf() } += raw
                } else {
                    unindexed += raw
                }
            }
        }

        fun relevantTo(sni: String): List<String> {
            val host = sni.trim().trimEnd('.').lowercase()
            if (!host.all { it.code < 128 }) return byKey.values.flatten() + unindexed
            val labels = host.split('.')
            return buildList {
                for (start in labels.indices) byKey[labels.drop(start).joinToString(".")]?.let(::addAll)
                addAll(unindexed)
            }
        }
    }

    @Volatile
    private var whitelistIndex: Pair<Long, WhitelistIndex>? = null

    private fun loadWhitelistIndex(now: Long): WhitelistIndex {
        val cachedAt = prefs.getLong(KEY_WHITELIST_AT, 0L)
        val fresh = prefs.contains(KEY_WHITELIST) && now - cachedAt in 0 until CACHE_TTL_MS
        whitelistIndex?.takeIf { fresh && it.first == cachedAt }?.let { return it.second }

        if (!fresh) {
            val downloaded = runCatching { readUrl("$baseUrl/whitelist/domains.csv") }.getOrNull()
            if (!downloaded.isNullOrBlank()) {
                prefs.edit().putString(KEY_WHITELIST, downloaded).putLong(KEY_WHITELIST_AT, now).apply()
                return WhitelistIndex(parseWhitelist(downloaded)).also { whitelistIndex = now to it }
            }
        }

        // Fresh cache, or the download failed and an older copy is the best evidence available.
        val index = WhitelistIndex(parseWhitelist(prefs.getString(KEY_WHITELIST, null).orEmpty()))
        if (fresh) whitelistIndex = cachedAt to index
        return index
    }

    private fun parseWhitelist(text: String): List<String> =
        text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && !it.startsWith('#') }
            .map { line -> line.substringBefore(',').substringBefore(';').trim().trim('"', '\'') }
            .filterNot { it.equals("domain", ignoreCase = true) || it.equals("domains", ignoreCase = true) }
            .distinct()
            .toList()

    private fun readUrl(url: String): String? {
        val connection =
            (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                setRequestProperty("Accept", "application/json,text/csv,text/plain,*/*")
                setRequestProperty("User-Agent", "VELUM-TEGRA-Next-RealityScanner/1")
                instanceFollowRedirects = true
            }
        return try {
            if (connection.responseCode !in 200..299) return null
            connection.inputStream.buffered().use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8 * 1024)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_TEXT_BYTES) return null
                    output.write(buffer, 0, read)
                }
                output.toString(Charsets.UTF_8.name())
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun buildSource(
        apiAvailable: Boolean,
        whitelistAvailable: Boolean,
    ): String =
        when {
            apiAvailable && whitelistAvailable -> "cheburcheck:check+whitelist"
            apiAvailable -> "cheburcheck:check"
            whitelistAvailable -> "cheburcheck:whitelist"
            else -> "unavailable"
        }
}
