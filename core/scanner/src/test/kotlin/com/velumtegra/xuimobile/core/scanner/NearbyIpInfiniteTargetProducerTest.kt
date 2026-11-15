package com.velumtegra.xuimobile.core.scanner

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class NearbyIpInfiniteTargetProducerTest {
    @Test
    fun `runtime target seam preserves exact nearest-ip ordering`() {
        val targets = NearbyIpInfiniteTargetProducer
            .sequence(InetAddress.getByName("192.0.2.139"), enableIpv6 = false)
            .take(7)
            .toList()

        assertEquals(
            listOf(
                "192.0.2.139",
                "192.0.2.138",
                "192.0.2.140",
                "192.0.2.137",
                "192.0.2.141",
                "192.0.2.136",
                "192.0.2.142",
            ),
            targets.map { it.host },
        )
        assertEquals(targets.map { it.host }, targets.map { it.origin })
        assertFalse(targets.any { it.isDomain })
    }

    @Test
    fun `runtime target seam cannot regress to cumulative minus one minus three minus six ordering`() {
        val hosts = NearbyIpInfiniteTargetProducer
            .sequence(InetAddress.getByName("10.0.0.10"), enableIpv6 = false)
            .take(7)
            .map { it.host }
            .toList()

        assertEquals(
            listOf(
                "10.0.0.10",
                "10.0.0.9",
                "10.0.0.11",
                "10.0.0.8",
                "10.0.0.12",
                "10.0.0.7",
                "10.0.0.13",
            ),
            hosts,
        )
    }

    @Test
    fun `ipv6 remains explicitly gated by runtime option`() {
        val ipv6 = InetAddress.getByName("2001:db8::2")

        assertThrows(IllegalArgumentException::class.java) {
            NearbyIpInfiniteTargetProducer.sequence(ipv6, enableIpv6 = false).first()
        }

        val enabled = NearbyIpInfiniteTargetProducer.sequence(ipv6, enableIpv6 = true)
            .take(3)
            .map { it.addressText() }
            .toList()

        assertEquals(
            listOf(
                "20010db8000000000000000000000002",
                "20010db8000000000000000000000001",
                "20010db8000000000000000000000003",
            ),
            enabled,
        )
    }

    private fun RealityScanTarget.addressText(): String =
        InetAddress.getByName(host).address.joinToString(separator = "") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
}
