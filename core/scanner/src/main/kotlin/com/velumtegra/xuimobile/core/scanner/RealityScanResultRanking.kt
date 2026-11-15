package com.velumtegra.xuimobile.core.scanner

/** Pure, deterministic best-latency ordering for Scanner result surfaces. */
object RealityScanResultRanking {
    /**
     * Known non-negative latency sorts first (lowest = best). Unknown/legacy latency sorts last.
     * Equal latency preserves the incoming order explicitly rather than relying on sort implementation details.
     */
    fun byBestLatency(results: List<RealityScanResult>): List<RealityScanResult> =
        results
            .withIndex()
            .sortedWith(
                compareBy<IndexedValue<RealityScanResult>>(
                    { entry -> entry.value.latencyMs?.takeIf { it >= 0L } ?: Long.MAX_VALUE },
                    { entry -> entry.index },
                ),
            )
            .map { it.value }
}
