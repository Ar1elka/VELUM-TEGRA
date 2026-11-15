package com.velumtegra.xuimobile.core.scanner

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Production seam for the approved single-IP infinite-mode target path.
 *
 * The legacy scanner engine consumed a Sequence<RealityScanTarget>. This adapter preserves that
 * contract while delegating address ordering to [NearbyIpTargetGenerator], so the cumulative
 * lower/upper stepping bug cannot be reintroduced when the Android engine is migrated.
 */
object NearbyIpInfiniteTargetProducer {
    fun sequence(seed: InetAddress, enableIpv6: Boolean): Sequence<RealityScanTarget> {
        require(seed is Inet4Address || enableIpv6) {
            "IPv6 target generation requires enableIpv6=true."
        }

        return NearbyIpTargetGenerator.sequence(seed).map { address ->
            val host = requireNotNull(address.hostAddress) {
                "Generated IP address has no textual host representation."
            }
            RealityScanTarget(
                origin = host,
                host = host,
                isDomain = false,
            )
        }
    }
}
