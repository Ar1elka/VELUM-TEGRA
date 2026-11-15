package com.velumtegra.xuimobile.core.scanner

/**
 * Scanner target contract carried from the approved legacy Reality Scanner runtime.
 *
 * The contract intentionally contains only target identity. Port selection, TLS, GeoIP, scheduling,
 * persistence and Android lifecycle remain outside this pure scanner module.
 */
data class RealityScanTarget(
    val origin: String,
    val host: String,
    val isDomain: Boolean,
)
