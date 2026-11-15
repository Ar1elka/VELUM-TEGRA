package com.velumtegra.xuimobile.core.webpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class WebPanelClientCountParserTest {
    @Test fun `object settings calculate counts without leaking secrets`() {
        val response = """{"success":true,"obj":[{"id":7,"remark":"Main","settings":{"clients":[{"id":"SECRET_UUID","password":"SECRET_PASSWORD","email":"SECRET_EMAIL","enable":true},{"id":"OTHER_SECRET_UUID","enable":false}]},"clientStats":[{"email":"STATS_SECRET"}]}]}"""
        val value = requireNotNull(WebPanelClientCountParser.parse(response))
        assertEquals(listOf(WebPanelClientCountOverview(7, "Main", 2, 1, 1)), value)
        val text = value.toString()
        listOf("SECRET_UUID", "SECRET_PASSWORD", "SECRET_EMAIL", "STATS_SECRET", "settings").forEach {
            assertFalse(text.contains(it))
        }
    }
    @Test fun `legacy JSON string settings are accepted`() {
        val response = """{"success":true,"obj":[{"id":2,"remark":"legacy","settings":"{\"clients\":[{\"email\":\"SECRET\",\"enable\":true}]}"}]}"""
        assertEquals(listOf(WebPanelClientCountOverview(2, "legacy", 1, 1, 0)), WebPanelClientCountParser.parse(response))
    }
    @Test fun `empty and unknown clients stay distinct`() {
        val response = """{"success":true,"obj":[{"id":1,"remark":"empty","settings":{"clients":[]}},{"id":2,"remark":"other","settings":{}}]}"""
        assertEquals(listOf(WebPanelClientCountOverview(1, "empty", 0, 0, 0),
            WebPanelClientCountOverview(2, "other", null, null, null)), WebPanelClientCountParser.parse(response))
    }
    @Test fun `unknown enabled flags do not invent state`() {
        val response = """{"success":true,"obj":[{"id":1,"remark":"a","settings":{"clients":[{"email":"hidden"}]}}]}"""
        assertEquals(listOf(WebPanelClientCountOverview(1, "a", 1, null, null)), WebPanelClientCountParser.parse(response))
    }
    @Test fun `malformed client values and login pages fail closed`() {
        assertNull(WebPanelClientCountParser.parse("<html>login</html>"))
        assertNull(WebPanelClientCountParser.parse("""{"success":false,"obj":[]}"""))
        assertNull(WebPanelClientCountParser.parse("""{"success":true,"obj":[{"id":1,"settings":{"clients":[{"enable":"false"}]}}]}"""))
        assertNull(WebPanelClientCountParser.parse("""{"success":true,"obj":[{"id":1,"settings":"broken"}]}"""))
        assertNull(WebPanelClientCountParser.parse("""{"success":true,"obj":[{"id":1,"settings":{"clients":"not an array"}}]}"""))
    }
}
