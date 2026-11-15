package com.velumtegra.xuimobile.core.scanner.android

import android.content.Context
import com.velumtegra.xuimobile.core.scanner.RealityScanResult
import com.velumtegra.xuimobile.core.scanner.RealitySniAnalysis
import com.velumtegra.xuimobile.core.scanner.RealitySniVerdict
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

data class RealityScanSession(
    val id: String = UUID.randomUUID().toString(),
    val createdAt: Long,
    val results: List<RealityScanResult>,
)

/** SharedPreferences-backed scanner result store kept separate from frozen Room v1. */
object RealityScanSessionStore {
    private const val PREFS = "velum_reality_scanner"
    private const val KEY_CURRENT = "current_results"
    private const val KEY_HISTORY = "history"
    private const val KEY_FAVORITES = "favorites"
    private const val MAX_HISTORY = 50

    private val lock = Any()
    private val revision = AtomicLong(0)

    /** The scanner service and UI share one process, so the live list need not be re-parsed on every read. */
    @Volatile
    private var currentCache: List<RealityScanResult>? = null

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Changes on every write; lets the UI skip re-reading current results, history and favorites. */
    fun revision(): Long = revision.get()

    fun loadCurrent(context: Context): List<RealityScanResult> =
        currentCache ?: synchronized(lock) {
            currentCache ?: readResultList(context, KEY_CURRENT).also { currentCache = it }
        }

    fun saveCurrent(context: Context, results: List<RealityScanResult>) {
        synchronized(lock) {
            writeResultList(context, KEY_CURRENT, results)
        }
    }

    /**
     * Adds a result unless the same target is already listed; returns whether it was added.
     * The origin is part of the identity: several scanned domains may share one IP behind a CDN.
     */
    fun appendCurrentDistinct(context: Context, result: RealityScanResult): Boolean =
        synchronized(lock) {
            val current = loadCurrent(context)
            if (current.any { it.ip == result.ip && it.port == result.port && it.origin == result.origin }) {
                false
            } else {
                writeResultList(context, KEY_CURRENT, current + result)
                true
            }
        }

    fun updateResultEverywhere(context: Context, updated: RealityScanResult) {
        synchronized(lock) {
            val current = loadCurrent(context)
            if (current.any { it.id == updated.id }) {
                writeResultList(context, KEY_CURRENT, current.map { if (it.id == updated.id) updated else it })
            }

            val favorites = loadFavorites(context)
            if (favorites.any { it.id == updated.id }) {
                writeResultList(context, KEY_FAVORITES, favorites.map { if (it.id == updated.id) updated else it })
            }

            val history = loadHistory(context)
            var historyChanged = false
            val updatedHistory =
                history.map { session ->
                    if (session.results.none { it.id == updated.id }) {
                        session
                    } else {
                        historyChanged = true
                        session.copy(results = session.results.map { if (it.id == updated.id) updated else it })
                    }
                }
            if (historyChanged) saveHistory(context, updatedHistory)
        }
    }

    fun clearCurrent(context: Context) {
        synchronized(lock) {
            prefs(context).edit().remove(KEY_CURRENT).apply()
            currentCache = emptyList()
            revision.incrementAndGet()
        }
    }

    fun loadHistory(context: Context): List<RealityScanSession> =
        runCatching {
            val array = JSONArray(prefs(context).getString(KEY_HISTORY, "[]") ?: "[]")
            buildList {
                for (index in 0 until array.length()) {
                    val obj = array.getJSONObject(index)
                    add(
                        RealityScanSession(
                            id = obj.optString("id").ifBlank { UUID.randomUUID().toString() },
                            createdAt = obj.optLong("createdAt"),
                            results = jsonToList(obj.optJSONArray("results")),
                        ),
                    )
                }
            }
        }.getOrDefault(emptyList())

    fun saveHistory(context: Context, sessions: List<RealityScanSession>) {
        synchronized(lock) {
            val array = JSONArray()
            sessions.take(MAX_HISTORY).forEach { session ->
                array.put(
                    JSONObject()
                        .put("id", session.id)
                        .put("createdAt", session.createdAt)
                        .put("results", listToJson(session.results)),
                )
            }
            prefs(context).edit().putString(KEY_HISTORY, array.toString()).apply()
            revision.incrementAndGet()
        }
    }

    fun archiveCurrent(context: Context) {
        synchronized(lock) {
            val current = loadCurrent(context)
            if (current.isEmpty()) return
            val history = loadHistory(context)
            saveHistory(
                context,
                listOf(
                    RealityScanSession(
                        createdAt = System.currentTimeMillis(),
                        results = current,
                    ),
                ) + history,
            )
        }
    }

    fun loadFavorites(context: Context): List<RealityScanResult> =
        readResultList(context, KEY_FAVORITES)

    fun saveFavorites(context: Context, results: List<RealityScanResult>) {
        synchronized(lock) {
            writeResultList(context, KEY_FAVORITES, results)
        }
    }

    private fun readResultList(context: Context, key: String): List<RealityScanResult> =
        runCatching {
            jsonToList(JSONArray(prefs(context).getString(key, "[]") ?: "[]"))
        }.getOrDefault(emptyList())

    private fun writeResultList(context: Context, key: String, results: List<RealityScanResult>) {
        prefs(context).edit().putString(key, listToJson(results).toString()).apply()
        if (key == KEY_CURRENT) currentCache = results
        revision.incrementAndGet()
    }

    private fun listToJson(results: List<RealityScanResult>): JSONArray =
        JSONArray().apply {
            results.forEach { put(toJson(it)) }
        }

    private fun jsonToList(array: JSONArray?): List<RealityScanResult> {
        if (array == null) return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                add(fromJson(array.getJSONObject(index)))
            }
        }
    }

    private fun toJson(result: RealityScanResult): JSONObject =
        JSONObject()
            .put("id", result.id)
            .put("origin", result.origin)
            .put("ip", result.ip)
            .put("port", result.port)
            .put("feasible", result.feasible)
            .put("tls", result.tls)
            .put("alpn", result.alpn)
            .put("certificateDomain", result.certificateDomain)
            .put("certificateIssuer", result.certificateIssuer)
            .put("certificateSignature", result.certificateSignature)
            .put("certificatePublicKey", result.certificatePublicKey)
            .put("certificateLength", result.certificateLength)
            .put("certificateCount", result.certificateCount)
            .put("cipherSuite", result.cipherSuite)
            .put("curve", result.curve ?: "")
            .put("geo", result.geo)
            .put("latencyMs", result.latencyMs ?: JSONObject.NULL)
            .put("sniCandidates", JSONArray(result.sniCandidates))
            .put("selectedSni", result.selectedSni ?: "")
            .put(
                "sniAnalysis",
                result.sniAnalysis?.let { analysis ->
                    JSONObject()
                        .put("sni", analysis.sni)
                        .put("verdict", analysis.verdict.name)
                        .put("reasons", JSONArray(analysis.reasons))
                        .put("source", analysis.source)
                        .put("checkedAt", analysis.checkedAt)
                } ?: JSONObject.NULL,
            )
            .put("error", result.error ?: "")
            .put("timestamp", result.timestamp)

    private fun fromJson(obj: JSONObject): RealityScanResult =
        RealityScanResult(
            id = obj.optString("id").ifBlank { UUID.randomUUID().toString() },
            origin = obj.optString("origin"),
            ip = obj.optString("ip"),
            port = obj.optInt("port"),
            feasible = obj.optBoolean("feasible"),
            tls = obj.optString("tls"),
            alpn = obj.optString("alpn"),
            certificateDomain = obj.optString("certificateDomain"),
            certificateIssuer = obj.optString("certificateIssuer"),
            certificateSignature = obj.optString("certificateSignature"),
            certificatePublicKey = obj.optString("certificatePublicKey"),
            certificateLength = obj.optInt("certificateLength"),
            certificateCount = obj.optInt("certificateCount"),
            cipherSuite = obj.optString("cipherSuite"),
            curve = obj.optString("curve").ifBlank { null },
            geo = obj.optString("geo", "N/A"),
            latencyMs =
                if (obj.has("latencyMs") && !obj.isNull("latencyMs")) {
                    obj.optLong("latencyMs").takeIf { it >= 0L }
                } else {
                    null
                },
            sniCandidates =
                buildList {
                    val values = obj.optJSONArray("sniCandidates")
                    if (values != null) {
                        for (index in 0 until values.length()) {
                            values.optString(index).takeIf { it.isNotBlank() }?.let(::add)
                        }
                    }
                },
            selectedSni = obj.optString("selectedSni").ifBlank { null },
            sniAnalysis =
                obj.optJSONObject("sniAnalysis")?.let { analysis ->
                    val verdict =
                        runCatching { RealitySniVerdict.valueOf(analysis.optString("verdict")) }
                            .getOrDefault(RealitySniVerdict.UNKNOWN)
                    RealitySniAnalysis(
                        sni = analysis.optString("sni"),
                        verdict = verdict,
                        reasons =
                            buildList {
                                val values = analysis.optJSONArray("reasons")
                                if (values != null) {
                                    for (index in 0 until values.length()) {
                                        values.optString(index).takeIf { it.isNotBlank() }?.let(::add)
                                    }
                                }
                            },
                        source = analysis.optString("source"),
                        checkedAt = analysis.optLong("checkedAt"),
                    )
                },
            error = obj.optString("error").ifBlank { null },
            timestamp = obj.optLong("timestamp"),
        )
}
