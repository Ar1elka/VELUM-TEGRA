package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiInstallResultProbeTest {
    private val sample = """
        XUI_USERNAME=abcDEF1234
        XUI_PASSWORD=Zx9\ y\'q
        XUI_PANEL_PORT=54321
        XUI_WEB_BASE_PATH=panelBasePathXyz12
        XUI_ACCESS_URL=http://1.2.3.4:54321/panelBasePathXyz12
        XUI_API_TOKEN=''
        XUI_DB_TYPE=sqlite
    """.trimIndent()

    @Test fun `installer result file is parsed and printf q escapes are undone`() {
        val read = XuiInstallResultProbe.parse(sample) as XuiInstallResultRead.Observed
        assertEquals("abcDEF1234", read.credentials.username)
        assertEquals("Zx9 y'q", read.credentials.password)
        assertEquals(54321, read.credentials.panelPort)
        assertEquals("/panelBasePathXyz12/", read.credentials.webBasePath)
    }

    @Test fun `secrets never appear in toString`() {
        val read = XuiInstallResultProbe.parse(sample) as XuiInstallResultRead.Observed
        assertFalse(read.toString().contains("Zx9"))
        assertFalse(read.toString().contains("abcDEF1234"))
    }

    @Test fun `malformed or incomplete files are unavailable`() {
        listOf(
            sample.replace("XUI_PANEL_PORT=54321", "XUI_PANEL_PORT=99999"),
            sample.replace("XUI_PASSWORD=Zx9\\ y\\'q", "XUI_PASSWORD=$'a\\nb'"),
            sample + "\nXUI_USERNAME=again",
            sample.replace("XUI_USERNAME=abcDEF1234\n", ""),
            "garbage",
        ).forEach { assertTrue(it, XuiInstallResultProbe.parse(it) is XuiInstallResultRead.Unavailable) }
    }
}
