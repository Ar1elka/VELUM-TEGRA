package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EmbeddedHttpsWebPanelPolicyTest {
    private val origin = "https://panel.example.org:2053/secret/"

    @Test fun allowsSameExactHttpsOriginAndInternalNavigation() {
        assertTrue(isSameAuthorizedHttpsPanelOrigin(origin, "https://panel.example.org:2053/secret/login?lang=ru"))
        assertTrue(isSameAuthorizedHttpsPanelOrigin(origin, "https://PANEL.EXAMPLE.ORG:2053/xui/inbounds/#top"))
        assertTrue(isSameAuthorizedHttpsPanelOrigin("https://panel.example.org/", "https://panel.example.org:443/xui"))
    }

    @Test fun rejectsHostPortSchemeAndCredentialEscapes() {
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "http://panel.example.org:2053/secret/"))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "https://panel.example.org/secret/"))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "https://panel.example.org.evil.invalid:2053/secret/"))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "https://user:secret@panel.example.org:2053/secret/"))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "intent://panel.example.org:2053/secret/"))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "javascript:alert(1)"))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(origin, "https://panel.example.org:65536/"))
    }

    @Test fun rejectsUnvalidatedInitialAddresses() {
        assertFalse(isSameAuthorizedHttpsPanelOrigin("http://panel.example.org:2053/secret/", origin))
        assertFalse(isSameAuthorizedHttpsPanelOrigin("https://user@panel.example.org:2053/secret/", origin))
        assertFalse(isSameAuthorizedHttpsPanelOrigin("https://panel.example.org:2053/secret/?token=abc", origin))
        assertFalse(isSameAuthorizedHttpsPanelOrigin("https://panel.example.org:2053/secret/#token", origin))
        assertFalse(isSameAuthorizedHttpsPanelOrigin(" https://panel.example.org:2053/secret/", origin))
    }
}
