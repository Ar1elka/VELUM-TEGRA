package com.velumtegra.xuimobile.core.webpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class WebPanelClientQuotaExpiryParserTest {
    private val now = 1800000000000L
    private val day = 86400000L

    @Test fun `counts quotas and expiry groups per inbound without leaking secrets`() {
        val body = """{"success":true,"obj":[{"id":11,"remark":"SECRET_REMARK", "settings":{"clients":[{"email":"SECRET_EMAIL","id":"SECRET_UUID","password":"SECRET_PASSWORD","totalGB":0,"expiryTime":0},{"email":"USER2","totalGB":1000000000,"expiryTime":1799999999999},{"totalGB":2048,"expiryTime":1800086400000},{"totalGB":null,"expiryTime":1800864000000},{"expiryTime":-259200000}]}}]}"""
        val items = requireNotNull(WebPanelClientQuotaExpiryParser.parse(body, now))
        assertEquals(listOf(WebPanelClientQuotaExpiryOverview(11, 5, 2, 1, 2, 1, 1, 1, 1, 1, 0)), items)
        for (secret in listOf("SECRET_REMARK", "SECRET_EMAIL", "SECRET_UUID", "SECRET_PASSWORD", "USER2")) {
            assertFalse(items.toString().contains(secret))
        }
    }

    @Test fun `supports stringified settings, explicit empty and unknown`() {
        val encoded = """{"success":true,"obj":[{"id":1,"settings":"{\"clients\":[{\"totalGB\":0,\"expiryTime\":0}]}","clientStats":[{"email":"secret","up":15}]},{"id":2,"settings":{"clients":[]}},{"id":3},{"id":4,"settings":null}]}"""
        val result = requireNotNull(WebPanelClientQuotaExpiryParser.parse(encoded, now))
        assertEquals(WebPanelClientQuotaExpiryOverview(1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0), result[0])
        assertEquals(0, result[1].assignments)
        assertEquals(null, result[2].assignments)
        assertEquals(null, result[3].unknownExpiry)
    }

    @Test fun `rejects malformed, negative quota, overflow and duplicate inbound`() {
        listOf(
            """{"success":true,"obj":[{"id":1,"settings":{"clients":[{"totalGB":-1,"expiryTime":0}]}}]}""",
            """{"success":true,"obj":[{"id":1,"settings":{"clients":[{"totalGB":"500","expiryTime":0}]}}]}""",
            """{"success":true,"obj":[{"id":1,"settings":{"clients":[{"totalGB":9223372036854775808,"expiryTime":0}]}}]}""",
            """{"success":true,"obj":[{"id":1,"settings":{"clients":[{"totalGB":0,"expiryTime":1.5}]}}]}""",
            """{"success":true,"obj":[{"id":1,"settings":{"clients":[{"totalGB":0,"expiryTime":"0"}]}}]}""",
            """{"success":true,"obj":[{"id":1,"settings":{"clients":{}}}]}""",
            """{"success":true,"obj":[{"id":1},{"id":1}]}""",
            """{"success":false,"obj":[]}""", "<html>login</html>",
        ).forEach { assertNull(WebPanelClientQuotaExpiryParser.parse(it, now)) }
        assertNull(WebPanelClientQuotaExpiryParser.parse("""{"success":true,"obj":[]}""", -1L))
    }
}
