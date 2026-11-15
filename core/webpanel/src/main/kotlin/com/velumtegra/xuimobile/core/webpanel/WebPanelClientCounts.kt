package com.velumtegra.xuimobile.core.webpanel

/** Only aggregate numbers are returned; no client identifiers, UUIDs, emails, keys or settings. */
data class WebPanelClientCountOverview(
    val inboundId: Int,
    val inboundName: String,
    val clientCount: Int?,
    val enabledCount: Int?,
    val disabledCount: Int?,
)

enum class WebPanelClientCountFailure {
    SESSION_CLOSED, AUTH_REQUIRED, HTTP_FAILURE, NETWORK_FAILURE,
    TLS_FAILURE, RESPONSE_TOO_LARGE, PROTOCOL_INCOMPATIBLE, CANCELLED,
}

sealed interface WebPanelClientCountResult {
    data class Success(val items: List<WebPanelClientCountOverview>) : WebPanelClientCountResult
    data class Failed(val reason: WebPanelClientCountFailure) : WebPanelClientCountResult
}

interface WebPanelClientCountSession : WebPanelAuthenticatedSession {
    suspend fun readClientCountsOnce(): WebPanelClientCountResult
}

/**
 * GET /panel/api/inbounds/list only. Supports both modern nested settings and legacy JSON strings.
 * An inbound with no clients field has unknown count (not zero); malformed data fails closed.
 * Counts represent inbound assignments, not globally unique identities.
 */
internal object WebPanelClientCountParser {
    fun parse(json: String): List<WebPanelClientCountOverview>? {
        val envelope = BoundedJson.parseObject(json)?.fields ?: return null
        if ((envelope["success"] as? BoundedJson.Value.Bool)?.value != true) return null
        val entries = (envelope["obj"] as? BoundedJson.Value.Arr)?.values ?: return null
        if (entries.size > 512) return null
        var totalAssignments = 0
        return entries.map { entry ->
            val fields = (entry as? BoundedJson.Value.Obj)?.fields ?: return null
            val id = (fields["id"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it > 0 } ?: return null
            val remark = (fields["remark"] as? BoundedJson.Value.Str)?.value ?: ""
            if (remark.length > 120 || remark.any { it.isISOControl() }) return null
            val settings = when (val raw = fields["settings"]) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Obj -> raw.fields
                is BoundedJson.Value.Str -> {
                    if (raw.value.length > 64 * 1024) return null
                    BoundedJson.parseObject(raw.value)?.fields ?: return null
                }
                else -> return null
            }
            val clientsValue = settings?.get("clients")
            val clients = when (clientsValue) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Arr -> clientsValue.values
                else -> return null
            }
            if (clients == null) {
                WebPanelClientCountOverview(id, remark, null, null, null)
            } else {
                totalAssignments += clients.size
                if (totalAssignments > 8192) return null
                var enabled = 0
                var disabled = 0
                var unknown = 0
                for (client in clients) {
                    val attrs = (client as? BoundedJson.Value.Obj)?.fields ?: return null
                    when (val flag = attrs["enable"]) {
                        is BoundedJson.Value.Bool -> if (flag.value) enabled++ else disabled++
                        null, BoundedJson.Value.Null -> unknown++
                        else -> return null
                    }
                }
                WebPanelClientCountOverview(id, remark, clients.size,
                    enabled.takeIf { unknown == 0 }, disabled.takeIf { unknown == 0 })
            }
        }
    }
}
