package com.velumtegra.xuimobile.core.scanner

/**
 * Protocol policy for Reality Scanner handshakes.
 *
 * TLS 1.3 remains the default and preferred protocol. TLS 1.2 is added only when the user
 * explicitly opts in. This slice enables capability only; protocol-separated result surfaces are
 * intentionally deferred.
 */
object RealityScannerTlsPolicy {
    const val TLS_13 = "TLSv1.3"
    const val TLS_12 = "TLSv1.2"

    fun enabledProtocols(
        supportedProtocols: Collection<String>,
        enableTls12: Boolean,
    ): List<String> {
        val supported = supportedProtocols.toSet()
        return buildList {
            if (TLS_13 in supported) add(TLS_13)
            if (enableTls12 && TLS_12 in supported) add(TLS_12)
        }
    }

    fun isAcceptedProtocol(protocol: String, enableTls12: Boolean): Boolean =
        protocol == TLS_13 || (enableTls12 && protocol == TLS_12)
}
