package com.velumtegra.xuimobile.core.webpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class WebPanelInboundDetailsParserTest {
    @Test fun `reads safe inbound fields, count and interface classification without secrets`() {
        val body = """{"success":true,"obj":[{"id":3,"port":443,"protocol":"vless","enable":true,"listen":"0.0.0.0","remark":"SECRET_REMARK","settings":{"clients":[{"id":"SECRET_UUID","email":"SECRET_EMAIL","password":"SECRET_PASSWORD"},{}]}},{"id":5,"port":8388,"protocol":"shadowsocks","enable":false,"listen":"127.0.0.1","settings":"{\"clients\":[]}"},{"id":9,"port":9100,"protocol":"custom","enable":true,"listen":"10.2.3.4"}]}"""
        val items = requireNotNull(WebPanelInboundDetailsParser.parse(body))
        assertEquals(WebPanelInboundDetails(3, 443, "vless", true, WebPanelInboundListenScope.ALL_INTERFACES, 2), items[0])
        assertEquals(WebPanelInboundDetails(5, 8388, "shadowsocks", false, WebPanelInboundListenScope.LOOPBACK, 0), items[1])
        assertEquals(WebPanelInboundDetails(9, 9100, "other", true, WebPanelInboundListenScope.SPECIFIC_INTERFACE, null), items[2])
        listOf("SECRET_REMARK", "SECRET_UUID", "SECRET_EMAIL", "SECRET_PASSWORD", "10.2.3.4").forEach {
            assertFalse(items.toString().contains(it))
        }
    }

    @Test fun `missing listen and settings are unknown, not all interfaces or zero clients`() {
        val body = """{"success":true,"obj":[{"id":1,"port":80,"protocol":"http","enable":false}]}"""
        assertEquals(WebPanelInboundDetails(1, 80, "http", false, WebPanelInboundListenScope.UNKNOWN, null),
            requireNotNull(WebPanelInboundDetailsParser.parse(body)).single())
    }

    @Test fun `rejects malformed and unsupported data without returning config`() {
        val valid = """{"id":1,"port":443,"protocol":"vless","enable":true}"""
        listOf(
            """{"success":false,"obj":[]}""",
            """{"success":true,"obj":[{"id":1,"port":0,"protocol":"vless","enable":true}]}""",
            """{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","enable":1}]}""",
            """{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","enable":true,"listen":2}]}""",
            """{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","enable":true,"settings":{"clients":{}}}]}""",
            """{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","enable":true,"settings":"not-json"}]}""",
            """{"success":true,"obj":[$valid,$valid]}""",
            """{"success":true,"obj":[{"id":2147483648,"port":443,"protocol":"vless","enable":true}]}""",
            """{"success":true,"obj":{}}""",
            "<html>login</html>",
        ).forEach { assertNull(WebPanelInboundDetailsParser.parse(it)) }
    }
}
