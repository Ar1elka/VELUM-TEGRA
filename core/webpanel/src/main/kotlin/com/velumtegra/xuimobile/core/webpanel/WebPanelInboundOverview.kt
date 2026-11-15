package com.velumtegra.xuimobile.core.webpanel

/** Sanitized public projection: no client identifiers, settings, UUIDs, keys or configuration. */
data class WebPanelInboundOverview(
    val id: Int,
    val port: Int,
    val protocol: String,
    val remark: String,
    val enabled: Boolean,
)

enum class WebPanelInboundReadFailure {
    SESSION_CLOSED, AUTH_REQUIRED, HTTP_FAILURE, NETWORK_FAILURE,
    TLS_FAILURE, RESPONSE_TOO_LARGE, PROTOCOL_INCOMPATIBLE, CANCELLED,
}

sealed interface WebPanelInboundReadResult {
    data class Success(val inbounds: List<WebPanelInboundOverview>) : WebPanelInboundReadResult
    data class Failed(val reason: WebPanelInboundReadFailure) : WebPanelInboundReadResult
}

/** Only implemented by an authenticated, still-open, process-local session. */
interface WebPanelInboundReadSession : WebPanelAuthenticatedSession {
    suspend fun readInboundsOnce(): WebPanelInboundReadResult
}

/** Parse the known GET /panel/api/inbounds/list envelope without exposing payload secrets. */
internal object WebPanelInboundOverviewParser {
    fun parse(json: String): List<WebPanelInboundOverview>? {
        val obj = BoundedJson.parseObject(json) ?: return null
        if ((obj.fields["success"] as? BoundedJson.Value.Bool)?.value != true) return null
        val inbounds = (obj.fields["obj"] as? BoundedJson.Value.Arr)?.values ?: return null
        if (inbounds.size > 512) return null
        return inbounds.map { item ->
            val fields = (item as? BoundedJson.Value.Obj)?.fields ?: return null
            val id = (fields["id"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it > 0 } ?: return null
            val port = (fields["port"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it in 1..65535 } ?: return null
            val proto = (fields["protocol"] as? BoundedJson.Value.Str)?.value
                ?.takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,32}")) } ?: return null
            val remark = (fields["remark"] as? BoundedJson.Value.Str)?.value ?: ""
            if (remark.length > 160 || remark.any { it.isISOControl() }) return null
            val enable = (fields["enable"] as? BoundedJson.Value.Bool)?.value ?: return null
            WebPanelInboundOverview(id, port, proto, remark, enable)
        }
    }
}
