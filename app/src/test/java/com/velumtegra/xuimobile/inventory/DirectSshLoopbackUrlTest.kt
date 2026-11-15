package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectSshLoopbackUrlTest {
    @Test fun `SSH HTTPS browser uses allocated local port and original secret path`() {
        assertEquals("https://127.0.0.1:53421/private-xyz/",
            directSshLoopbackUrl(WebPanelScheme.HTTPS, 53421, "/private-xyz/"))
        assertEquals("http://127.0.0.1:19388/private-xyz/",
            directSshLoopbackUrl(WebPanelScheme.HTTP, 19388, "/private-xyz/"))
    }

    @Test fun `never build direct route without validated loopback and private path`() {
        assertNull(directSshLoopbackUrl(WebPanelScheme.HTTPS, 0, "/secret/"))
        assertNull(directSshLoopbackUrl(WebPanelScheme.HTTPS, 65536, "/secret/"))
        assertNull(directSshLoopbackUrl(WebPanelScheme.HTTPS, 54321, "http://evil/"))
        assertNull(directSshLoopbackUrl(WebPanelScheme.HTTPS, 54321, "/a/../b"))
        assertNull(directSshLoopbackUrl(WebPanelScheme.HTTPS, 54321, "/a?pw=secret"))
    }

    @Test fun `same loopback origin works for assets login api and redirect within panel`() {
        val start = "https://127.0.0.1:53421/secret/"
        for (url in listOf("https://127.0.0.1:53421/login", "https://127.0.0.1:53421/css/main.css",
            "https://127.0.0.1:53421/api/inbounds?key=abc")) {
            assertTrue(isSameDirectSshLoopbackOrigin(start, url))
        }
    }

    @Test fun `rejects all public hostname loopback aliases port changes and protocol downgrade`() {
        val start = "https://127.0.0.1:53421/secret/"
        for (url in listOf("https://example.com:53421/secret/", "https://localhost:53421/secret/",
            "https://127.0.0.2:53421/secret/", "https://127.0.0.1:53422/secret/",
            "http://127.0.0.1:53421/secret/", "https://user@127.0.0.1:53421/secret/",
            "intent://127.0.0.1:53421/secret/", "https://127.0.0.1:53421\\escape")) {
            assertFalse("Unexpectedly allowed $url", isSameDirectSshLoopbackOrigin(start, url))
        }
    }
}
