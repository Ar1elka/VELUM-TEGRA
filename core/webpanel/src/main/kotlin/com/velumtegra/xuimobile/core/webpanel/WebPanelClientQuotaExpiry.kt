package com.velumtegra.xuimobile.core.webpanel

/** Aggregate-only client quota/expiry categories per inbound. No client identifiers are returned. */
data class WebPanelClientQuotaExpiryOverview(
    val inboundId: Int,
    val assignments: Int?,
    val limitedQuota: Int?,
    val unlimitedQuota: Int?,
    val unknownQuota: Int?,
    val noExpiry: Int?,
    val expired: Int?,
    val expiringWithinSevenDays: Int?,
    val laterExpiry: Int?,
    val specialExpiry: Int?,
    val unknownExpiry: Int?,
)

enum class WebPanelClientQuotaExpiryFailure {
    SESSION_CLOSED, AUTH_REQUIRED, HTTP_FAILURE, NETWORK_FAILURE,
    TLS_FAILURE, RESPONSE_TOO_LARGE, PROTOCOL_INCOMPATIBLE, CANCELLED,
}

sealed interface WebPanelClientQuotaExpiryResult {
    data class Success(val items: List<WebPanelClientQuotaExpiryOverview>) : WebPanelClientQuotaExpiryResult
    data class Failed(val reason: WebPanelClientQuotaExpiryFailure) : WebPanelClientQuotaExpiryResult
}

interface WebPanelClientQuotaExpirySession : WebPanelAuthenticatedSession {
    suspend fun readClientQuotaExpiryOnce(): WebPanelClientQuotaExpiryResult
}

/**
 * GET /panel/api/inbounds/list: settings.clients can be an object or encoded JSON string.
 * `totalGB` is bytes (despite its name): zero means no quota; positive means a limit.
 * `expiryTime` is milliseconds since epoch when positive, zero means no expiry;
 * negative means a special/deferred server expiry mode and is NOT considered expired.
 * Missing values are unknown, not zero. Invalid quota values fail closed.
 * The timestamp is sampled once when the response is parsed; no client metadata survives.
 */
internal object WebPanelClientQuotaExpiryParser {
    private const val SEVEN_DAYS_MS = 7L * 24 * 60 * 60 * 1000

    fun parse(json: String, nowEpochMillis: Long = System.currentTimeMillis()): List<WebPanelClientQuotaExpiryOverview>? {
        if (nowEpochMillis <= 0L) return null
        val root = BoundedJson.parseObject(json)?.fields ?: return null
        if ((root["success"] as? BoundedJson.Value.Bool)?.value != true) return null
        val inbounds = (root["obj"] as? BoundedJson.Value.Arr)?.values ?: return null
        if (inbounds.size > 512) return null
        val seenIds = HashSet<Int>()
        var assignmentsTotal = 0
        val expiryCutoff = if (nowEpochMillis > Long.MAX_VALUE - SEVEN_DAYS_MS) Long.MAX_VALUE
            else nowEpochMillis + SEVEN_DAYS_MS
        return inbounds.map { inbound ->
            val fields = (inbound as? BoundedJson.Value.Obj)?.fields ?: return null
            val id = (fields["id"] as? BoundedJson.Value.Num)?.value?.toIntOrNull()
                ?.takeIf { it > 0 && seenIds.add(it) } ?: return null
            val settings = when (val value = fields["settings"]) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Obj -> value.fields
                is BoundedJson.Value.Str -> {
                    if (value.value.length > 64 * 1024) return null
                    BoundedJson.parseObject(value.value)?.fields ?: return null
                }
                else -> return null
            }
            val clients = when (val value = settings?.get("clients")) {
                null, BoundedJson.Value.Null -> null
                is BoundedJson.Value.Arr -> value.values
                else -> return null
            }
            if (clients == null) {
                WebPanelClientQuotaExpiryOverview(id, null, null, null, null, null, null, null, null, null, null)
            } else {
                assignmentsTotal += clients.size
                if (assignmentsTotal > 8192) return null
                var limited = 0
                var unlimited = 0
                var unknownQuota = 0
                var permanent = 0
                var expired = 0
                var soon = 0
                var later = 0
                var special = 0
                var unknownExpiry = 0
                for (client in clients) {
                    val attrs = (client as? BoundedJson.Value.Obj)?.fields ?: return null
                    val quotaValue = attrs["totalGB"]
                    if (quotaValue == null || quotaValue == BoundedJson.Value.Null) {
                        unknownQuota++
                    } else {
                        val quota = (quotaValue as? BoundedJson.Value.Num)?.value?.toLongOrNull() ?: return null
                        if (quota < 0) return null
                        if (quota == 0L) unlimited++ else limited++
                    }
                    val expiryValue = attrs["expiryTime"]
                    if (expiryValue == null || expiryValue == BoundedJson.Value.Null) {
                        unknownExpiry++
                    } else {
                        val expiry = (expiryValue as? BoundedJson.Value.Num)?.value?.toLongOrNull() ?: return null
                        when {
                            expiry == 0L -> permanent++
                            expiry < 0L -> special++
                            expiry <= nowEpochMillis -> expired++
                            expiry <= expiryCutoff -> soon++
                            else -> later++
                        }
                    }
                }
                WebPanelClientQuotaExpiryOverview(id, clients.size, limited, unlimited, unknownQuota,
                    permanent, expired, soon, later, special, unknownExpiry)
            }
        }
    }
}
