package com.velumtegra.xuimobile.core.webpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class WebPanelClientTrafficParserTest {
    @Test fun `sums clientStats per inbound and never exposes secrets`() {
        val body = """{"success":true,"obj":[{"id":7,"remark":"SECRET_REMARK","settings":{"clients":[{"id":"SECRET_UUID","password":"SECRET_PASSWORD"}]},"clientStats":[{"email":"SECRET_EMAIL","uuid":"SECRET_STATS_UUID","up":1024,"down":2048},{"email":"OTHER_EMAIL","up":4096,"down":8192}]},{"id":8,"clientStats":[]}]}"""
        val parsed = requireNotNull(WebPanelClientTrafficParser.parse(body))
        assertEquals(listOf(WebPanelClientTrafficOverview(7, 2, 5120, 10240),
            WebPanelClientTrafficOverview(8, 0, 0, 0)), parsed)
        val output = parsed.toString()
        listOf("SECRET_REMARK", "SECRET_UUID", "SECRET_PASSWORD", "SECRET_EMAIL", "SECRET_STATS_UUID", "OTHER_EMAIL").forEach {
            assertFalse(output.contains(it))
        }
    }
    @Test fun `unknown is not treated as zero`() {
        val body = """{"success":true,"obj":[{"id":1},{"id":2,"clientStats":null},{"id":3,"clientStats":[{"up":5},{"down":9}]}]}"""
        assertEquals(listOf(WebPanelClientTrafficOverview(1, null, null, null),
            WebPanelClientTrafficOverview(2, null, null, null),
            WebPanelClientTrafficOverview(3, 2, null, null)), WebPanelClientTrafficParser.parse(body))
    }
    @Test fun `rejects malformed negative overflow and duplicate inbound`() {
        listOf(
            """{"success":true,"obj":[{"id":1,"clientStats":[{"up":-1,"down":2}]}]}""",
            """{"success":true,"obj":[{"id":1,"clientStats":[{"up":1.5,"down":2}]}]}""",
            """{"success":true,"obj":[{"id":1,"clientStats":[{"up":"123","down":2}]}]}""",
            """{"success":true,"obj":[{"id":1,"clientStats":[{"up":9223372036854775807,"down":0},{"up":1,"down":0}]}]}""",
            """{"success":true,"obj":[{"id":1,"clientStats":[]},{"id":1,"clientStats":[]}]}""",
            """{"success":true,"obj":[{"id":1,"clientStats":{}}]}""",
            """{"success":false,"obj":[]}""", "<html>login</html>",
        ).forEach { assertNull(WebPanelClientTrafficParser.parse(it)) }
    }
}
