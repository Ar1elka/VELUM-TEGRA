package com.velumtegra.xuimobile.core.webpanel

/** Aggregate bytes across clientStats for one inbound, never a client-level record. */
data class WebPanelClientTrafficOverview(
    val inboundId: Int,
    val trackedClients: Int?,
    val uploadBytes: Long?,
    val downloadBytes: Long?,
)

enum class WebPanelClientTrafficFailure {
    SESSION_CLOSED, AUTH_REQUIRED, HTTP_FAILURE, NETWORK_FAILURE,
    TLS_FAILURE, RESPONSE_TOO_LARGE, PROTOCOL_INCOMPATIBLE, CANCELLED,
}

sealed interface WebPanelClientTrafficResult {
    data class Success(val items: List<WebPanelClientTrafficOverview>) : WebPanelClientTrafficResult
    data class Failed(val reason: WebPanelClientTrafficFailure) : WebPanelClientTrafficResult
}

interface WebPanelClientTrafficSession : WebPanelAuthenticatedSession {
    suspend fun readClientTrafficOnce(): WebPanelClientTrafficResult
}

/**
 * Parse the authenticated GET /panel/api/inbounds/list response; never expose fields of
 * clientStats, even in error cases. Missing clientStats means unknown, NOT zero.
 * Each direction becomes unknown when any record has no counter for that direction.
 * Malformed, negative, overflowing, or oversized counters fail the entire response.
 * Counters reflect the server's current recorded period, not live speed or unique users.
 */
internal object WebPanelClientTrafficParser {
    fun parse(json: String): List<WebPanelClientTrafficOverview>? {
        val root = BoundedJson.parseObject(json)?.fields ?: return null
        if ((root["success"] as? BoundedJson.Value.Bool)?.value != true) return null
        val inbounds = (root["obj"] as? BoundedJson.Value.Arr)?.values ?: return null
        if (inbounds.size > 512) return null
        val seenIds = HashSet<Int>()
        var allStats = 0
        return inbounds.map { inbound ->
            val fields = (inbound as? BoundedJson.Value.Obj)?.fields ?: return null
            val id = (fields["id"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it > 0 && seenIds.add(it) } ?: return null
            val rawStats = fields["clientStats"]
            val stats = when (rawStats) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Arr -> rawStats.values
                else -> return null
            }
            if (stats == null) {
                WebPanelClientTrafficOverview(id, null, null, null)
            } else {
                allStats += stats.size
                if (allStats > 8192) return null
                var upTotal = 0L
                var downTotal = 0L
                var missingUp = false
                var missingDown = false
                for (stat in stats) {
                    val record = (stat as? BoundedJson.Value.Obj)?.fields ?: return null
                    val upValue = record["up"]
                    val downValue = record["down"]
                    val up = asNonnegativeBytes(upValue)
                    val down = asNonnegativeBytes(downValue)
                    if (upValue != null && upValue != BoundedJson.Value.Null && up == null) return null
                    if (downValue != null && downValue != BoundedJson.Value.Null && down == null) return null
                    if (up == null) missingUp = true
                    else {
                        if (Long.MAX_VALUE - upTotal < up) return null
                        upTotal += up
                    }
                    if (down == null) missingDown = true
                    else {
                        if (Long.MAX_VALUE - downTotal < down) return null
                        downTotal += down
                    }
                }
                WebPanelClientTrafficOverview(
                    inboundId = id,
                    trackedClients = stats.size,
                    uploadBytes = upTotal.takeUnless { missingUp },
                    downloadBytes = downTotal.takeUnless { missingDown },
                )
            }
        }
    }

    private fun asNonnegativeBytes(value: BoundedJson.Value?): Long? =
        (value as? BoundedJson.Value.Num)?.value?.toLongOrNull()?.takeIf { it >= 0L }
}
