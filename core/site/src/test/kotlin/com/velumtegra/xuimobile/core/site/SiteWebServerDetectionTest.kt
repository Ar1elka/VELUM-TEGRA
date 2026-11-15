package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServerDetectionTest {
    private val sha = "b".repeat(64)

    private fun inventory(
        caddyState: SiteServiceState = SiteServiceState.ACTIVE,
        caddyBin: String? = "/usr/bin/caddy",
        nginxState: SiteServiceState = SiteServiceState.INACTIVE,
        nginxBin: String? = null,
        adapter: String? = "caddyfile",
        servers: List<SiteCaddyServer>? = listOf(SiteCaddyServer(setOf(443), setOf("vpn.example.com"), false)),
        listeners: List<SiteListeningSocket> = listOf(
            SiteListeningSocket(443, setOf("caddy")),
            SiteListeningSocket(80, setOf("caddy")),
            SiteListeningSocket(2053, setOf("x-ui")),
        ),
        firewall: SiteFirewallObservation = SiteFirewallObservation(SiteFirewallState.INACTIVE, true, emptyList()),
        tlsPairs: List<SiteCaddyTlsFilePair> = emptyList(),
    ) = SiteWebServerInventory(
        caddy = SiteCaddyObservation(caddyBin, caddyState, "/etc/caddy/Caddyfile", sha, adapter, servers, false, "caddy", tlsPairs),
        nginx = SiteNginxObservation(nginxBin, nginxState),
        listeners = listeners,
        firewall = firewall,
        requestedPortTls = SitePortTlsState.UNKNOWN,
    )

    @Test
    fun `backend selection never puts nginx next to a running caddy`() {
        assertEquals(SiteServingBackend.CADDY, SiteServingBackendPolicy.select(inventory(nginxBin = "/usr/sbin/nginx")).backend)
        assertEquals(
            SiteServingBackend.NGINX,
            SiteServingBackendPolicy.select(
                inventory(caddyState = SiteServiceState.INACTIVE, caddyBin = null, nginxState = SiteServiceState.ACTIVE, nginxBin = "/usr/sbin/nginx"),
            ).backend,
        )
        val stopped = SiteServingBackendPolicy.select(inventory(caddyState = SiteServiceState.INACTIVE))
        assertNull(stopped.backend)
        assertEquals(SiteServingFailureCategory.BACKEND_INCOMPATIBLE, stopped.blockedCategory)
        assertNull(SiteServingBackendPolicy.select(inventory(adapter = "json")).backend)
        assertNull(SiteServingBackendPolicy.select(inventory(servers = null)).backend)
        assertNull(SiteServingBackendPolicy.select(inventory(caddyState = SiteServiceState.INACTIVE, caddyBin = null)).backend)
        val reloading = SiteServingBackendPolicy.select(inventory(caddyState = SiteServiceState.RELOADING))
        assertNull(reloading.backend)
        assertEquals(SiteServingFailureCategory.RELOAD_FAILED, reloading.blockedCategory)
    }

    @Test
    fun `caddy endpoint shares 443 by host but not foreign ports`() {
        val inv = inventory()
        assertFalse(SiteServingBackendPolicy.caddyEndpoint(inv, "site.example.com", 443, false).portInUse)
        assertTrue(SiteServingBackendPolicy.caddyEndpoint(inv, "vpn.example.com", 443, false).portInUse)
        assertTrue(SiteServingBackendPolicy.caddyEndpoint(inv, "site.example.com", 2053, false).portInUse)
        assertFalse(SiteServingBackendPolicy.caddyEndpoint(inv, "site.example.com", 8443, false).portInUse)
        val ours = SiteServingBackendPolicy.caddyEndpoint(
            inventory(servers = listOf(SiteCaddyServer(setOf(443), setOf("site.example.com"), false))),
            "site.example.com",
            443,
            true,
        )
        assertTrue(ours.configPresent && ours.portInUse)
    }

    @Test
    fun `ufw rules are parsed for tcp ports and ranges`() {
        val active = SiteFirewallObservation(
            SiteFirewallState.ACTIVE,
            false,
            listOf(
                "22/tcp                     ALLOW IN    Anywhere",
                "80,443/tcp                 ALLOW IN    Anywhere",
                "2000:2100/tcp              ALLOW IN    Anywhere",
                "8080/udp                   ALLOW IN    Anywhere",
                "9000                       DENY IN     Anywhere",
                "443/tcp (v6)               ALLOW IN    Anywhere (v6)",
            ),
        )
        assertEquals(true, SiteFirewallPolicy.allowsTcpPort(active, 443))
        assertEquals(true, SiteFirewallPolicy.allowsTcpPort(active, 2053))
        assertEquals(false, SiteFirewallPolicy.allowsTcpPort(active, 8080))
        assertEquals(false, SiteFirewallPolicy.allowsTcpPort(active, 9000))
        assertEquals(false, SiteFirewallPolicy.allowsTcpPort(active, 8443))
        assertEquals(true, SiteFirewallPolicy.allowsTcpPort(active.copy(defaultIncomingAllow = true), 8443))
        assertEquals(true, SiteFirewallPolicy.allowsTcpPort(SiteFirewallObservation(SiteFirewallState.INACTIVE, true, emptyList()), 8443))
        assertNull(SiteFirewallPolicy.allowsTcpPort(SiteFirewallObservation(SiteFirewallState.UNKNOWN, false, emptyList()), 8443))
    }

    @Test
    fun `ufw unknown or port 8443 closed blocks publication before any upload`() {
        val closed = SiteFirewallObservation(
            SiteFirewallState.ACTIVE,
            false,
            listOf("22/tcp                     ALLOW IN    Anywhere", "443/tcp                    ALLOW IN    Anywhere"),
        )
        assertTrue(SiteFirewallPolicy.publicationBlock(closed, 8443)!!.contains("sudo ufw allow 8443/tcp"))
        assertNull(SiteFirewallPolicy.publicationBlock(closed, 443))
        val unknown = SiteFirewallObservation(SiteFirewallState.UNKNOWN, false, emptyList())
        assertTrue(SiteFirewallPolicy.publicationBlock(unknown, 8443)!!.contains("Не удалось прочитать состояние UFW"))
        val open = closed.copy(ruleLines = closed.ruleLines + "8443/tcp                   ALLOW IN    Anywhere")
        assertNull(SiteFirewallPolicy.publicationBlock(open, 8443))
    }

    @Test
    fun `caddy adapt json yields loaded certificate file pairs`() {
        val json = """
            {"apps":{"tls":{"certificates":{"load_files":[
              {"certificate":"/etc/caddy/certs/fullchain.pem","key":"/etc/caddy/certs/privkey.pem","tags":["cert0"]},
              {"certificate":"/etc/caddy/certs/fullchain.pem","key":"/etc/caddy/certs/privkey.pem","tags":["cert1"]}
            ]}}}}
        """.trimIndent()
        assertEquals(
            listOf(SiteCaddyTlsFilePair("/etc/caddy/certs/fullchain.pem", "/etc/caddy/certs/privkey.pem")),
            SiteCaddyConfigReader.tlsFilePairs(json),
        )
        assertTrue(SiteCaddyConfigReader.tlsFilePairs("{\"apps\":{}}").isEmpty())
    }

    @Test
    fun `caddy adapt json yields ports hosts and catch all routes`() {
        val json = """
            {"apps":{"http":{"servers":{
              "srv0":{"listen":[":443"],"routes":[
                {"match":[{"host":["vpn.example.com","VPN2.example.com"]}],"handle":[{"handler":"reverse_proxy"}]},
                {"handle":[{"handler":"static_response","body":"A \"q\""}]}
              ]},
              "srv1":{"listen":["tcp/0.0.0.0:8080"],"routes":[]}
            }}}}
        """.trimIndent()
        val servers = SiteCaddyConfigReader.servers(json)
        assertEquals(setOf(443), servers[0].ports)
        assertEquals(setOf("vpn.example.com", "vpn2.example.com"), servers[0].hosts)
        assertTrue(servers[0].hasCatchAllRoute)
        assertEquals(setOf(8080), servers[1].ports)
        assertThrows(IllegalArgumentException::class.java) { SiteCaddyConfigReader.servers("{\"apps\":") }
    }

    @Test
    fun `caddy plan renders a deterministic managed site block`() {
        val inv = inventory()
        assertEquals(SiteCaddyTlsMode.AUTOMATIC, SiteCaddyServingPlanner.tlsModeFor(inv, "site.example.com", false))
        assertEquals(
            SiteCaddyTlsMode.NONE,
            SiteCaddyServingPlanner.tlsModeFor(inventory(listeners = listOf(SiteListeningSocket(443, setOf("xray")))), "site.example.com", false),
        )
        val plan = SiteCaddyServingPlanner.prepare(
            remoteHostIdentity = "198.51.100.10",
            domain = "Site.Example.com",
            port = 8443,
            targetRoot = "/var/www/velum-site",
            tlsMode = SiteCaddyTlsMode.AUTOMATIC,
            caddy = inv.caddy,
            indexSha256 = sha,
            preservedListeningPorts = inv.listeningPorts,
        )
        assertEquals("https://site.example.com:8443/", plan.plannedUrl)
        assertTrue(plan.siteBlockUtf8.contains("site.example.com:8443 {"))
        assertTrue(plan.siteBlockUtf8.contains("root * /var/www/velum-site"))
        assertEquals("/etc/caddy/velum-sites", plan.managedDirectory)
        assertEquals("import /etc/caddy/velum-sites/*.caddy", plan.importLine)
        assertFalse(plan.dnsMutationAuthorized || plan.firewallMutationAuthorized || plan.packageInstallAuthorized)
        SiteCaddyServingPlanner.validate(plan)
        assertThrows(IllegalArgumentException::class.java) { SiteCaddyServingPlanner.validate(plan.copy(siteBlockUtf8 = "x")) }

        val http = SiteCaddyServingPlanner.prepare(
            "198.51.100.10", "site.example.com", 8080, "/var/www/velum-site", SiteCaddyTlsMode.NONE,
            inv.caddy, sha, inv.listeningPorts,
        )
        assertEquals("http://site.example.com:8080/", http.plannedUrl)
        assertTrue(http.siteBlockUtf8.contains("http://site.example.com:8080 {"))

        val cert = SiteServerCertificateFileReference(
            "198.51.100.10", sha, listOf("other.example.com"), "/root/cert/fullchain.pem", "/root/cert/privkey.pem", true, true,
        )
        assertThrows(IllegalArgumentException::class.java) {
            SiteCaddyServingPlanner.prepare(
                "198.51.100.10", "site.example.com", 8443, "/var/www/velum-site",
                SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE, inv.caddy, sha, inv.listeningPorts, cert,
            )
        }
    }

    @Test
    fun `serving outcome cannot claim reachability without a verified url`() {
        assertThrows(IllegalArgumentException::class.java) {
            SiteServingOutcome(SiteServingBackend.CADDY, "https://a.example/", null, true, true, false, null, null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteServingOutcome(SiteServingBackend.CADDY, "https://a.example/", null, true, false, false, null, "x")
        }
    }
}
