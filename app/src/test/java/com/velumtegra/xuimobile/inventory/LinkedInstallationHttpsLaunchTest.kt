package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LinkedInstallationHttpsLaunchTest {
    @Test fun `uses explicit host and exact saved port and base path`() {
        assertEquals(
            "https://panel.example.com:54321/secure-slug/",
            linkedInstallationHttpsUrl("panel.example.com", 54321, "/secure-slug/"),
        )
        assertEquals("https://192.0.2.12:443/", linkedInstallationHttpsUrl("192.0.2.12", 443, "/"))
        assertEquals("https://[2001:db8::1]:8443/private/", linkedInstallationHttpsUrl("[2001:db8::1]", 8443, "/private/"))
    }

    @Test fun `never accepts URL credentials host substitutions or a guessed port`() {
        for (invalidHost in listOf(
            "", " panel.example.com", "panel.example.com ", "https://panel.example.com",
            "panel.example.com:443", "u:p@panel.example.com", "panel.example.com/elsewhere",
            "panel.example.com?token=x", "panel.example.com#fragment", "0.0.0.0",
            "[::]", "*.example.com", "exa mple.com", "example.com\\evil",
        )) assertNull("Rejected host $invalidHost", linkedInstallationHttpsUrl(invalidHost, 2053, "/secret/"))
        assertNull(linkedInstallationHttpsUrl("panel.example.com", 0, "/secret/"))
        assertNull(linkedInstallationHttpsUrl("panel.example.com", 65536, "/secret/"))
    }

    @Test fun `rejects malformed saved path and refuses to fabricate path`() {
        for (badPath in listOf(
            "", "secret/", "//secret", "/secret//path", "/../admin", "/./admin",
            "/secret?token=abc", "/secret#fragment", "/secret\\next", "/secret with space",
        )) assertNull("Rejected saved path $badPath", linkedInstallationHttpsUrl("panel.example.com", 443, badPath))
    }
}
