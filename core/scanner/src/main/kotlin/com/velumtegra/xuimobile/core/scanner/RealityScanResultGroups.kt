package com.velumtegra.xuimobile.core.scanner

/** Stable TLS buckets for the Scanner result surface. */
data class RealityScanResultGroups(
    val tls13: List<RealityScanResult>,
    val tls12: List<RealityScanResult>,
    val other: List<RealityScanResult>,
) {
    val total: Int
        get() = tls13.size + tls12.size + other.size
}

/**
 * Pure result partition used by the UI while the service keeps ownership of scan/runtime state.
 * Original ordering inside each protocol bucket is preserved.
 */
object RealityScanResultGrouping {
    fun split(results: List<RealityScanResult>): RealityScanResultGroups {
        val tls13 = mutableListOf<RealityScanResult>()
        val tls12 = mutableListOf<RealityScanResult>()
        val other = mutableListOf<RealityScanResult>()

        results.forEach { result ->
            when (result.tls) {
                RealityScannerTlsPolicy.TLS_13 -> tls13 += result
                RealityScannerTlsPolicy.TLS_12 -> tls12 += result
                else -> other += result
            }
        }

        return RealityScanResultGroups(
            tls13 = tls13,
            tls12 = tls12,
            other = other,
        )
    }
}
