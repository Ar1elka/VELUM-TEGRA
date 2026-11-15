package com.velumtegra.xuimobile.core.scanner

/** Progress contract preserved from the approved Scanner runtime. Infinite mode reports total=0. */
data class RealityScanProgress(
    val total: Int,
    val completed: Int,
    val feasible: Int,
) {
    val percent: Int
        get() = if (total <= 0) 0 else ((completed * 100L) / total).toInt().coerceIn(0, 100)
}
