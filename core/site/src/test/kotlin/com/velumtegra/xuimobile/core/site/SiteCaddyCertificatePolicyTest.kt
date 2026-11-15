package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteCaddyCertificatePolicyTest {
    private val sha = "c".repeat(64)
    private val caddyPair = SiteCaddyTlsFilePair("/etc/caddy/certs/fullchain.pem", "/etc/caddy/certs/privkey.pem")
    private val rootPair = SiteCaddyTlsFilePair("/root/cert/site.example.com/fullchain.pem", "/root/cert/site.example.com/privkey.pem")

    private fun candidate(
        pair: SiteCaddyTlsFilePair,
        readable: Boolean? = true,
        notExpired: Boolean? = true,
        names: List<String> = listOf("site.example.com"),
    ) = SiteCaddyCertificateCandidate(pair, "caddy", readable, readable, notExpired, names, sha)

    @Test
    fun `readable caddy pair wins over unreadable root pair`() {
        val selection = SiteCaddyCertificatePolicy.select(
            "Site.Example.com",
            listOf(candidate(rootPair, readable = false), candidate(caddyPair)),
        )
        assertEquals(caddyPair, (selection as SiteCaddyCertificateSelection.Selected).candidate.pair)
    }

    @Test
    fun `root pair alone is blocked with a concrete reason`() {
        val blocked = SiteCaddyCertificatePolicy.select("site.example.com", listOf(candidate(rootPair, readable = false)))
            as SiteCaddyCertificateSelection.Blocked
        assertTrue(blocked.message.contains("caddy не может прочитать"))
        assertTrue(blocked.message.contains(rootPair.certificatePath))
    }

    @Test
    fun `no caddy certificates, wrong san, expired and unknown checks are blocked`() {
        assertTrue(SiteCaddyCertificatePolicy.select("site.example.com", emptyList()) is SiteCaddyCertificateSelection.Blocked)
        val wrong = SiteCaddyCertificatePolicy.select("site.example.com", listOf(candidate(caddyPair, names = listOf("vpn.example.com"))))
        assertTrue((wrong as SiteCaddyCertificateSelection.Blocked).message.contains("не покрывает"))
        val expired = SiteCaddyCertificatePolicy.select("site.example.com", listOf(candidate(caddyPair, notExpired = false)))
        assertTrue((expired as SiteCaddyCertificateSelection.Blocked).message.contains("истёк"))
        val unknown = SiteCaddyCertificatePolicy.select("site.example.com", listOf(candidate(caddyPair, readable = null)))
        assertTrue((unknown as SiteCaddyCertificateSelection.Blocked).message.contains("runuser"))
    }

    @Test
    fun `wildcard covers exactly one label`() {
        assertTrue(SiteCaddyCertificatePolicy.covers(listOf("*.example.com"), "site.example.com"))
        assertFalse(SiteCaddyCertificatePolicy.covers(listOf("*.example.com"), "a.b.example.com"))
        assertFalse(SiteCaddyCertificatePolicy.covers(listOf("*.example.com"), "example.com"))
        assertTrue(SiteCaddyCertificatePolicy.covers(listOf("SITE.example.com"), "site.example.com"))
    }

    @Test
    fun `planner refuses certificate files caddy does not already load`() {
        val caddy = SiteCaddyObservation(
            "/usr/bin/caddy", SiteServiceState.ACTIVE, "/etc/caddy/Caddyfile", "b".repeat(64), "caddyfile",
            emptyList(), true, "caddy", listOf(caddyPair),
        )
        fun plan(pair: SiteCaddyTlsFilePair) = SiteCaddyServingPlanner.prepare(
            "198.51.100.10", "site.example.com", 8443, "/var/www/velum-site",
            SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE, caddy, sha, setOf(443),
            SiteCaddyCertificatePolicy.reference("198.51.100.10", candidate(pair)),
        )
        val ok = plan(caddyPair)
        assertEquals("caddy", ok.serviceUser)
        assertEquals(caddyPair.certificatePath, ok.tlsCertificatePath)
        assertTrue(ok.siteBlockUtf8.contains("\ttls /etc/caddy/certs/fullchain.pem /etc/caddy/certs/privkey.pem\n"))
        val error = runCatching { plan(rootPair) }.exceptionOrNull()
        assertTrue(error is IllegalArgumentException)
    }
}
