package com.velumtegra.xuimobile.core.scanner

import java.math.BigInteger
import java.net.InetAddress

/**
 * Generates exact nearest-neighbour IP targets around one already-parsed seed address.
 *
 * The ordering is intentionally symmetric and distance-based:
 * seed, seed-1, seed+1, seed-2, seed+2, ...
 *
 * This class performs no DNS lookup, socket I/O, port iteration or scan scheduling. Callers must
 * parse/authorize the input before constructing a sequence and own lifecycle/backpressure outside
 * this pure target generator.
 */
object NearbyIpTargetGenerator {
    fun sequence(seed: InetAddress): Sequence<InetAddress> {
        val byteCount = seed.address.size
        require(byteCount == IPV4_BYTES || byteCount == IPV6_BYTES) {
            "Only IPv4 and IPv6 addresses are supported."
        }

        val seedValue = BigInteger(1, seed.address)
        val maxValue = BigInteger.ONE.shiftLeft(byteCount * BITS_PER_BYTE).subtract(BigInteger.ONE)

        val maxDistance = maxOf(seedValue, maxValue.subtract(seedValue))

        return sequence {
            yield(seedValue.toInetAddress(byteCount))

            var distance = BigInteger.ONE
            while (distance <= maxDistance) {
                val lower = seedValue.subtract(distance)
                if (lower.signum() >= 0) {
                    yield(lower.toInetAddress(byteCount))
                }

                val upper = seedValue.add(distance)
                if (upper <= maxValue) {
                    yield(upper.toInetAddress(byteCount))
                }

                distance = distance.add(BigInteger.ONE)
            }
        }
    }

    private fun BigInteger.toInetAddress(byteCount: Int): InetAddress {
        val unsigned = toByteArray().let { raw ->
            when {
                raw.size == byteCount -> raw
                raw.size == byteCount + 1 && raw.first() == 0.toByte() -> raw.copyOfRange(1, raw.size)
                raw.size < byteCount -> ByteArray(byteCount - raw.size) + raw
                else -> error("IP value does not fit in $byteCount bytes.")
            }
        }
        return InetAddress.getByAddress(unsigned)
    }

    private const val IPV4_BYTES = 4
    private const val IPV6_BYTES = 16
    private const val BITS_PER_BYTE = 8
}
