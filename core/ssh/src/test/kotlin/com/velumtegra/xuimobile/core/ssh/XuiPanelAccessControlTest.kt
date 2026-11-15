package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiPanelAccessControlTest {
    @Test fun `open panel with tls and installer result`() {
        val s = requireNotNull(XuiPanelAccessControl.parse("LISTEN=\nPORT=43210\nBASE=/abc/\nTLS=1\nRESULT=1\nBOUND=*:43210\n"))
        assertEquals(XuiPanelExposure.PUBLIC, s.exposure)
        assertEquals(43210, s.panelPort)
        assertEquals("/abc/", s.webBasePath)
        assertTrue(s.tlsEnabled && s.installResultPresent)
        assertEquals(listOf("*:43210"), s.boundAddresses)
        assertFalse(s.boundAddresses.all(XuiPanelAccessControl::isLoopbackBinding))
    }

    @Test fun `closed panel bound to loopback only`() {
        val s = requireNotNull(XuiPanelAccessControl.parse("LISTEN=127.0.0.1\nPORT=2053\nBASE=/\nBOUND=127.0.0.1:2053\n"))
        assertEquals(XuiPanelExposure.LOOPBACK, s.exposure)
        assertFalse(s.tlsEnabled || s.installResultPresent)
        assertTrue(s.boundAddresses.all(XuiPanelAccessControl::isLoopbackBinding))
    }

    @Test fun `listen address classification`() {
        assertEquals(XuiPanelExposure.PUBLIC, XuiPanelAccessControl.exposureOf("0.0.0.0"))
        assertEquals(XuiPanelExposure.PUBLIC, XuiPanelAccessControl.exposureOf("::"))
        assertEquals(XuiPanelExposure.LOOPBACK, XuiPanelAccessControl.exposureOf("[::1]"))
        assertEquals(XuiPanelExposure.SPECIFIC, XuiPanelAccessControl.exposureOf("10.0.0.5"))
        assertTrue(XuiPanelAccessControl.isLoopbackBinding("[::1]:2053"))
        assertFalse(XuiPanelAccessControl.isLoopbackBinding("0.0.0.0:2053"))
    }

    @Test fun `missing port is not a state`() {
        assertNull(XuiPanelAccessControl.parse("LISTEN=\nBASE=/\n"))
    }

    @Test fun `generated sign-in is shell safe and never printed`() {
        repeat(50) {
            val c = XuiGeneratedPanelCredentials.generate()
            assertTrue(XuiGeneratedPanelCredentials.isSafe(c.username) && XuiGeneratedPanelCredentials.isSafe(c.password))
            assertEquals(24, c.password.length)
            assertFalse(c.password in c.toString() || c.username in c.toString())
        }
        assertFalse(XuiGeneratedPanelCredentials.isSafe("a'b; rm"))
    }
}
