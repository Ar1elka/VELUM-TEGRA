package com.velumtegra.xuimobile.core.scanner

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test

class NearbyIpTargetGeneratorTest {
    @Test
    fun `ipv4 infinite ordering is exact seed minus plus distance`() {
        val hosts = firstHosts("192.0.2.139", count = 9)

        assertEquals(
            listOf(
                "192.0.2.139",
                "192.0.2.138",
                "192.0.2.140",
                "192.0.2.137",
                "192.0.2.141",
                "192.0.2.136",
                "192.0.2.142",
                "192.0.2.135",
                "192.0.2.143",
            ),
            hosts,
        )
    }

    @Test
    fun `regression does not accumulate previous lower and upper anchors`() {
        val hosts = firstHosts("10.0.0.10", count = 7)

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
    fun `lower ipv4 boundary keeps scanning valid upper neighbours`() {
        assertEquals(
            listOf(
                "0.0.0.1",
                "0.0.0.0",
                "0.0.0.2",
                "0.0.0.3",
                "0.0.0.4",
            ),
            firstHosts("0.0.0.1", count = 5),
        )
    }

    @Test
    fun `upper ipv4 boundary keeps scanning valid lower neighbours`() {
        assertEquals(
            listOf(
                "255.255.255.254",
                "255.255.255.253",
                "255.255.255.255",
                "255.255.255.252",
                "255.255.255.251",
            ),
            firstHosts("255.255.255.254", count = 5),
        )
    }

    @Test
    fun `ipv6 uses the same symmetric nearest ordering`() {
        val hosts = NearbyIpTargetGenerator.sequence(InetAddress.getByName("2001:db8::2"))
            .take(5)
            .map { it.address.toHex() }
            .toList()

        assertEquals(
            listOf(
                "20010db8000000000000000000000002",
                "20010db8000000000000000000000001",
                "20010db8000000000000000000000003",
                "20010db8000000000000000000000000",
                "20010db8000000000000000000000004",
            ),
            hosts,
        )
    }

    private fun firstHosts(seed: String, count: Int): List<String> =
        NearbyIpTargetGenerator.sequence(InetAddress.getByName(seed))
            .take(count)
            .map { it.hostAddress }
            .toList()

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xff)
    }
}
