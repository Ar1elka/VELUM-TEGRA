package com.velumtegra.xuimobile.core.scanner

/** Classification used by the SNI analyzer and later two-column rating projection. */
enum class RealitySniVerdict {
    CLEAN,
    WHITELIST_CONFIRMED,
    WHITELIST_CANDIDATE,
    BLOCKED,
    UNKNOWN,
}

/** Persisted analyzer result for the currently selected SNI of one scan result. */
data class RealitySniAnalysis(
    val sni: String,
    val verdict: RealitySniVerdict,
    val reasons: List<String> = emptyList(),
    val source: String = "",
    val checkedAt: Long,
)
