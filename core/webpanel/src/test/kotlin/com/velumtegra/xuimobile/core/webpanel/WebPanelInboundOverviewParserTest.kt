package com.velumtegra.xuimobile.core.webpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WebPanelInboundOverviewParserTest {
    @Test fun `read-only projection excludes client secrets`() {
        val value = WebPanelInboundOverviewParser.parse("""{"success":true,"obj":[{"id":7,"port":443,"protocol":"vless","remark":"Main","enable":true,"settings":{"clients":[{"id":"SECRET_UUID","password":"SECRET_PASS"}]}}]}""")
        requireNotNull(value)
        assertEquals(1, value.size)
        assertEquals(WebPanelInboundOverview(7, 443, "vless", "Main", true), value.single())
        assertEquals(false, value.toString().contains("SECRET_UUID"))
        assertEquals(false, value.toString().contains("SECRET_PASS"))
    }
    @Test fun `rejects login html and unauthenticated envelopes`() {
        assertNull(WebPanelInboundOverviewParser.parse("<html>login</html>"))
        assertNull(WebPanelInboundOverviewParser.parse("""{"success":false,"obj":[]}"""))
    }
    @Test fun `rejects malformed metadata rather than presenting a partial list`() {
        assertNull(WebPanelInboundOverviewParser.parse("""{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","remark":"ok","enable":true},{"id":2,"port":0,"protocol":"vless","remark":"bad","enable":true}]}"""))
        assertNull(WebPanelInboundOverviewParser.parse("""{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","remark":"ok","enable":"yes"}]}"""))
    }
}
