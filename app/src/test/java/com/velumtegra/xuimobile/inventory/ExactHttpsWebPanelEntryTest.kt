package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExactHttpsWebPanelEntryTest {
    @Test fun `accepts exact HTTPS panel host port and private path`() {
        val url = "https://panel.example.com:54321/secretBase/"
        assertEquals(url, exactHttpsPanelUrl(url))
        assertEquals("https://127.0.0.1:8443/", exactHttpsPanelUrl("https://127.0.0.1:8443/"))
        assertEquals("https://[::1]:8443/", exactHttpsPanelUrl("https://[::1]:8443/"))
    }

    @Test fun `rejects credential exfiltration via URI and non HTTPS schemes`() {
        for (url in listOf(
            "", "http://example.com:8080/", "intent://panel.example.com/",
            "javascript:alert(1)", "https://user:password@example.com/",
            "https://panel.example.com/login?token=secret",
            "https://panel.example.com/path#access_token=secret",
            "https://panel.example.com:0/", "https://panel.example.com:65536/",
            "https://panel.example.com/../admin", "https://panel.example.com/%2F/",
            "https://panel.example.com/%5c/", "https://panel.example.com\\evil",
            " https://panel.example.com/", "https://panel.example.com/ ",
            "https://", "https:///path", "https://panel.example.com/with space",
        )) assertNull("Must not open: $url", exactHttpsPanelUrl(url))
    }
}
