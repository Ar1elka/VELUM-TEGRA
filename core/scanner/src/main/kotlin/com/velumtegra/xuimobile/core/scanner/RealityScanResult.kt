package com.velumtegra.xuimobile.core.scanner

import java.util.UUID

/** Immutable result contract produced by the migrated Reality Scanner engine. */
data class RealityScanResult(
    val id: String = UUID.randomUUID().toString(),
    val origin: String,
    val ip: String,
    val port: Int,
    val feasible: Boolean,
    val tls: String,
    val alpn: String,
    val certificateDomain: String,
    val certificateIssuer: String,
    val certificateSignature: String,
    val certificatePublicKey: String,
    val certificateLength: Int,
    val certificateCount: Int,
    val cipherSuite: String = "",
    val curve: String? = null,
    val geo: String = "N/A",
    /** TCP connect latency to the scanned target/port in milliseconds; null for legacy/failed rows. */
    val latencyMs: Long? = null,
    /** Concrete DNS names learned from the peer certificate and safe to use as selectable SNI values. */
    val sniCandidates: List<String> = emptyList(),
    /** User/default-selected SNI for later VLESS-Reality use; null when no concrete candidate exists. */
    val selectedSni: String? = null,
    /** Last analyzer verdict for selectedSni; null means this SNI has not been analyzed yet. */
    val sniAnalysis: RealitySniAnalysis? = null,
    val error: String? = null,
    val timestamp: Long = System.currentTimeMillis(),
)
