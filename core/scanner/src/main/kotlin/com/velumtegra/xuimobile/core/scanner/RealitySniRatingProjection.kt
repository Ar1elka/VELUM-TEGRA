package com.velumtegra.xuimobile.core.scanner

/** Two independent top-rating columns plus the complete remainder bucket. */
data class RealitySniRatingColumns(
    val clean: List<RealityScanResult>,
    val whitelist: List<RealityScanResult>,
    val remainder: List<RealityScanResult>,
) {
    val ratedCount: Int
        get() = clean.size + whitelist.size
}

/**
 * Pure SNI rating projection.
 *
 * Only a verdict that belongs to the result's currently selected SNI may enter a top column.
 * CLEAN and WHITELIST_CONFIRMED are intentionally separate populations. Candidate, blocked,
 * unknown, unanalyzed or stale evidence stays visible in [RealitySniRatingColumns.remainder].
 * Each top column is ranked independently by the established best-latency policy.
 */
object RealitySniRatingProjection {
    fun project(results: List<RealityScanResult>): RealitySniRatingColumns {
        val clean = mutableListOf<RealityScanResult>()
        val whitelist = mutableListOf<RealityScanResult>()
        val remainder = mutableListOf<RealityScanResult>()

        results.forEach { result ->
            val selected = result.selectedSni?.trim()?.takeIf { it.isNotEmpty() }
            val analysis = result.sniAnalysis
            val appliesToSelected =
                selected != null &&
                    analysis != null &&
                    analysis.sni.trim().equals(selected, ignoreCase = true)

            if (!appliesToSelected) {
                remainder += result
                return@forEach
            }

            when (analysis!!.verdict) {
                RealitySniVerdict.CLEAN -> clean += result
                RealitySniVerdict.WHITELIST_CONFIRMED -> whitelist += result
                RealitySniVerdict.WHITELIST_CANDIDATE,
                RealitySniVerdict.BLOCKED,
                RealitySniVerdict.UNKNOWN,
                -> remainder += result
            }
        }

        return RealitySniRatingColumns(
            clean = RealityScanResultRanking.byBestLatency(clean),
            whitelist = RealityScanResultRanking.byBestLatency(whitelist),
            remainder = remainder,
        )
    }
}
