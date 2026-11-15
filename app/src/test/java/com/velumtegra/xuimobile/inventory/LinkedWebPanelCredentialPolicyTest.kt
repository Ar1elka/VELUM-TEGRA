package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class LinkedWebPanelCredentialPolicyTest {
    @Test fun `valid exact host and saved installation require explicit approval`() {
        assertNull(LinkedPanelCredentialPolicy.preflight(
            "server-id", "installation-id", "panel.example.com", "admin", 18, true,
            54321, "/secret/"))
        assertNotNull(LinkedPanelCredentialPolicy.preflight(
            "server-id", "installation-id", "panel.example.com", "admin", 18, false,
            54321, "/secret/"))
    }

    @Test fun `rejects host injection and untrusted port or path`() {
        for (host in listOf("", "https://panel.example.com", "panel.example.com:443",
            "user@panel.example.com", "panel.example.com/path", "  panel.example.com", "0.0.0.0")) {
            assertNotNull(LinkedPanelCredentialPolicy.preflight(
                "s", "i", host, "admin", 8, true, 12345, "/secret/"))
        }
        assertNotNull(LinkedPanelCredentialPolicy.preflight("s", "i", "panel.example.com",
            "admin", 8, true, 0, "/secret/"))
        assertNotNull(LinkedPanelCredentialPolicy.preflight("s", "i", "panel.example.com",
            "admin", 8, true, 443, "/../admin"))
    }

    @Test fun `missing target invalid username and absent password fail closed`() {
        assertNotNull(LinkedPanelCredentialPolicy.preflight("", "i", "panel.example.com", "u", 1, true, 443, "/"))
        assertNotNull(LinkedPanelCredentialPolicy.preflight("s", "i", "panel.example.com", " u", 1, true, 443, "/"))
        assertNotNull(LinkedPanelCredentialPolicy.preflight("s", "i", "panel.example.com", "u", 0, true, 443, "/"))
        assertNotNull(LinkedPanelCredentialPolicy.preflight("s", "i", "panel.example.com", "u", 4097, true, 443, "/"))
    }
}
