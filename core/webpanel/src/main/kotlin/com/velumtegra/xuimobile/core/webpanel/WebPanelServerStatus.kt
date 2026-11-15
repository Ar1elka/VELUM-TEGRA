package com.velumtegra.xuimobile.core.webpanel

/** One ephemeral, redacted projection of /panel/api/server/status. No raw JSON, IPs or secrets. */
data class WebPanelServerStatusSnapshot(
    val cpuPercent: Double?,
    val memoryUsedBytes: Long?,
    val memoryTotalBytes: Long?,
    val networkUploadedBytes: Long?,
    val networkDownloadedBytes: Long?,
    val xrayState: String?,
)

enum class WebPanelServerStatusFailure {
    SESSION_CLOSED, AUTH_REQUIRED, HTTP_FAILURE, NETWORK_FAILURE,
    TLS_FAILURE, RESPONSE_TOO_LARGE, PROTOCOL_INCOMPATIBLE, CANCELLED,
}

sealed interface WebPanelServerStatusResult {
    data class Success(val snapshot: WebPanelServerStatusSnapshot) : WebPanelServerStatusResult
    data class Failed(val reason: WebPanelServerStatusFailure) : WebPanelServerStatusResult
}

interface WebPanelServerStatusSession : WebPanelAuthenticatedSession {
    suspend fun readServerStatusOnce(): WebPanelServerStatusResult
}

/** Parse only a small allowlist from the documented 3x-ui status envelope. */
internal object WebPanelServerStatusParser {
    fun parse(json: String): WebPanelServerStatusSnapshot? {
        val fields = BoundedJson.parseObject(json)?.fields ?: return null
        if ((fields["success"] as? BoundedJson.Value.Bool)?.value != true) return null
        val obj = (fields["obj"] as? BoundedJson.Value.Obj)?.fields ?: return null

        val cpu = when (val value = obj["cpu"]) {
            null -> null
            is BoundedJson.Value.Num -> value.value.toDoubleOrNull()?.takeIf { it.isFinite() && it in 0.0..100.0 }
                ?: return null
            else -> return null
        }
        val mem = parsePair(obj["mem"], "current", "total", ordered = true)
        if (obj.containsKey("mem") && mem == null) return null
        val net = parsePair(obj["netIO"], "up", "down", ordered = false)
        if (obj.containsKey("netIO") && net == null) return null
        val xray = when (val value = obj["xray"]) {
            null -> null
            is BoundedJson.Value.Obj -> when (val state = value.fields["state"]) {
                null -> null
                is BoundedJson.Value.Str -> state.value.takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,32}")) }
                    ?: return null
                else -> return null
            }
            else -> return null
        }
        if (cpu == null && mem == null && net == null && xray == null) return null
        return WebPanelServerStatusSnapshot(cpu, mem?.first, mem?.second, net?.first, net?.second, xray)
    }

    private fun parsePair(
        value: BoundedJson.Value?, first: String, second: String, ordered: Boolean,
    ): Pair<Long, Long>? {
        val obj = (value as? BoundedJson.Value.Obj)?.fields ?: return null
        val a = (obj[first] as? BoundedJson.Value.Num)?.value?.toLongOrNull() ?: return null
        val b = (obj[second] as? BoundedJson.Value.Num)?.value?.toLongOrNull() ?: return null
        if (a < 0 || b < 0 || (ordered && (b == 0L || a > b))) return null
        return a to b
    }
}
