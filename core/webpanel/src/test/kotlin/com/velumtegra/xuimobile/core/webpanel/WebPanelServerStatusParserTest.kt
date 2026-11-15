package com.velumtegra.xuimobile.core.webpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Test

class WebPanelServerStatusParserTest {
    @Test fun `returns allowlisted metrics and never leaks secrets`() {
        val response = """{"success":true,"obj":{"cpu":12.5,"mem":{"current":2147483648,"total":8589934592},"netIO":{"up":1073741824,"down":2147483648},"xray":{"state":"running","version":"PRIVATE"},"ip":"SECRET_IP","config":"SECRET_KEY"}}"""
        val value = requireNotNull(WebPanelServerStatusParser.parse(response))
        assertEquals(12.5, value.cpuPercent!!, 0.001)
        assertEquals(2147483648L, value.memoryUsedBytes)
        assertEquals(8589934592L, value.memoryTotalBytes)
        assertEquals(1073741824L, value.networkUploadedBytes)
        assertEquals("running", value.xrayState)
        assertFalse(value.toString().contains("SECRET_KEY"))
        assertFalse(value.toString().contains("SECRET_IP"))
        assertFalse(value.toString().contains("PRIVATE"))
    }
    @Test fun `rejects login pages and failures`() {
        assertNull(WebPanelServerStatusParser.parse("<html>login</html>"))
        assertNull(WebPanelServerStatusParser.parse("""{"success":false,"obj":{"cpu":12}}"""))
        assertNull(WebPanelServerStatusParser.parse("""{"success":true,"obj":{}}"""))
    }
    @Test fun `rejects invalid or partial measurements`() {
        assertNull(WebPanelServerStatusParser.parse("""{"success":true,"obj":{"cpu":101}}"""))
        assertNull(WebPanelServerStatusParser.parse("""{"success":true,"obj":{"mem":{"current":300,"total":100}}}"""))
        assertNull(WebPanelServerStatusParser.parse("""{"success":true,"obj":{"netIO":{"up":-1,"down":0}}}"""))
        assertNull(WebPanelServerStatusParser.parse("""{"success":true,"obj":{"xray":{"state":"ok\nSECRET"}}}"""))
    }
    @Test fun `supports limited status response with missing optional metrics`() {
        val status = requireNotNull(WebPanelServerStatusParser.parse("""{"success":true,"obj":{"xray":{"state":"running"}}}"""))
        assertNull(status.cpuPercent)
        assertNull(status.networkUploadedBytes)
        assertEquals("running", status.xrayState)
    }
}
