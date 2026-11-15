package com.velumtegra.xuimobile.core.ssh

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDnsFakeIpTest {
    private fun ip(value: String) = InetAddress.getByName(value)

    @Test fun `vpn fake-ip answer is re-checked through public dns`() {
        val probe = SiteExternalReachabilityProbe(
            resolver = { host -> if (host == "site.test.org") listOf(ip("198.18.0.183")) else listOf(ip(host)) },
            publicResolver = { host -> if (host == "site.test.org") listOf("192.0.2.189") else null },
        )
        val check = probe.checkDns("site.test.org", "192.0.2.189")
        assertTrue(check.pointsToServer)
        assertNull(check.failureMessage)
    }

    @Test fun `unavailable public dns gives an explicit vpn message instead of a wrong a-record hint`() {
        val probe = SiteExternalReachabilityProbe(
            resolver = { host -> if (host == "site.test.org") listOf(ip("198.18.0.183")) else listOf(ip(host)) },
            publicResolver = { null },
        )
        val check = probe.checkDns("site.test.org", "192.0.2.189")
        assertFalse(check.pointsToServer)
        assertTrue(check.failureMessage!!.contains("VPN"))
    }

    @Test fun `real addresses never consult public dns`() {
        var asked = false
        val probe = SiteExternalReachabilityProbe(
            resolver = { host -> if (host == "site.test.org") listOf(ip("10.1.2.3")) else listOf(ip(host)) },
            publicResolver = { asked = true; null },
        )
        val check = probe.checkDns("site.test.org", "192.0.2.189")
        assertFalse(asked)
        assertTrue(check.failureMessage!!.contains("Исправьте A-запись"))
    }

    @Test fun `fake-ip range is exactly 198_18_0_0 slash 15`() {
        assertTrue(SiteExternalReachabilityProbe.isVpnFakeIp("198.18.0.1"))
        assertTrue(SiteExternalReachabilityProbe.isVpnFakeIp("198.19.255.254"))
        assertFalse(SiteExternalReachabilityProbe.isVpnFakeIp("198.20.0.1"))
        assertFalse(SiteExternalReachabilityProbe.isVpnFakeIp("192.0.2.189"))
    }

    @Test fun `doh json answers are parsed`() {
        val json = """{"Status":0,"Answer":[{"name":"a.b.org","type":5,"TTL":60,"data":"c.b.org."},""" +
            """{"name":"c.b.org","type":1,"TTL":60,"data":"192.0.2.189"}]}"""
        assertEquals(listOf("192.0.2.189"), DnsOverHttpsResolver.parse(json))
        assertNull(DnsOverHttpsResolver.parse("""{"Status":3}"""))
    }
}
