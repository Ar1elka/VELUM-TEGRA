package com.velumtegra.xuimobile.core.webpanel

/** Only nonsecret fields survive this projection. Inbound remarks and raw listen IPs are omitted. */
data class WebPanelInboundDetails(
    val inboundId: Int,
    val port: Int,
    val protocol: String,
    val enabled: Boolean,
    val listenScope: WebPanelInboundListenScope,
    val clientAssignments: Int?,
)

enum class WebPanelInboundListenScope { ALL_INTERFACES, LOOPBACK, SPECIFIC_INTERFACE, UNKNOWN }

enum class WebPanelInboundDetailsFailure {
    SESSION_CLOSED, AUTH_REQUIRED, HTTP_FAILURE, NETWORK_FAILURE,
    TLS_FAILURE, RESPONSE_TOO_LARGE, PROTOCOL_INCOMPATIBLE, CANCELLED,
}

sealed interface WebPanelInboundDetailsResult {
    data class Success(val items: List<WebPanelInboundDetails>) : WebPanelInboundDetailsResult
    data class Failed(val reason: WebPanelInboundDetailsFailure) : WebPanelInboundDetailsResult
}

interface WebPanelInboundDetailsSession : WebPanelAuthenticatedSession {
    suspend fun readInboundDetailsOnce(): WebPanelInboundDetailsResult
}

/** A bounded, aggregate-only reading of GET /panel/api/inbounds/list, not a config editor. */
internal object WebPanelInboundDetailsParser {
    private val supported = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http", "dokodemo-door", "wireguard")

    fun parse(json: String): List<WebPanelInboundDetails>? {
        val root = BoundedJson.parseObject(json)?.fields ?: return null
        if ((root["success"] as? BoundedJson.Value.Bool)?.value != true) return null
        val inbounds = (root["obj"] as? BoundedJson.Value.Arr)?.values ?: return null
        if (inbounds.size > 512) return null
        val seen = HashSet<Int>()
        var totalAssignments = 0
        return inbounds.map { item ->
            val f = (item as? BoundedJson.Value.Obj)?.fields ?: return null
            val id = (f["id"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it > 0 && seen.add(it) } ?: return null
            val port = (f["port"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it in 1..65535 } ?: return null
            val rawProto = (f["protocol"] as? BoundedJson.Value.Str)?.value ?: return null
            if (!rawProto.matches(Regex("[A-Za-z0-9_-]{1,32}"))) return null
            val protocol = rawProto.lowercase().let { if (it in supported) it else "other" }
            val enabled = (f["enable"] as? BoundedJson.Value.Bool)?.value ?: return null
            val scope = when (val listen = f["listen"]) {
                null, BoundedJson.Value.Null -> WebPanelInboundListenScope.UNKNOWN
                is BoundedJson.Value.Str -> {
                    val raw = listen.value
                    if (raw.length > 128 || raw.any { it.isISOControl() }) return null
                    when (raw.trim().lowercase()) {
                        "", "0.0.0.0", "::", "[::]", "*" -> WebPanelInboundListenScope.ALL_INTERFACES
                        "127.0.0.1", "::1", "[::1]", "localhost" -> WebPanelInboundListenScope.LOOPBACK
                        else -> WebPanelInboundListenScope.SPECIFIC_INTERFACE
                    }
                }
                else -> return null
            }
            val settings = when (val s = f["settings"]) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Obj -> s.fields
                is BoundedJson.Value.Str -> {
                    if (s.value.length > 64 * 1024) return null
                    BoundedJson.parseObject(s.value)?.fields ?: return null
                }
                else -> return null
            }
            val clients = when (val value = settings?.get("clients")) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Arr -> value.values
                else -> return null
            }
            val assignments = if (clients == null) null else {
                totalAssignments += clients.size
                if (totalAssignments > 8192) return null
                if (clients.any { it !is BoundedJson.Value.Obj }) return null
                clients.size
            }
            WebPanelInboundDetails(id, port, protocol, enabled, scope, assignments)
        }
    }
}
