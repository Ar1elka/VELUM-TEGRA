package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivateSshWebPanelProxyPolicyTest {
    @Test fun `HTTP is only for the exact local browser authority`() {
        assertTrue(isSamePrivateSshOrigin("http://127.0.0.1:19444/private/",
            "http://127.0.0.1:19444/login", true))
        assertFalse(isSamePrivateSshOrigin("http://127.0.0.1:19444/private/",
            "http://127.0.0.1:19445/login", true))
        assertNull(exactPrivateSshPanelUrl("http://127.0.0.1:19444/private/", false))
        assertNotNull(exactPrivateSshPanelUrl("http://127.0.0.1:19444/private/", true))
        assertNull(exactPrivateSshPanelUrl("http://evil.example:19444/private/", true))
    }
}
