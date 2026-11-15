package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SavedWebPanelLoginPageTest {
    private val panel = "https://127.0.0.1:23000/private-panel/"

    @Test
    fun allowsOnlyTheExactSavedLoginLocation() {
        assertTrue(isSavedPanelLoginPage(panel, panel))
        assertTrue(isSavedPanelLoginPage(panel, panel.trimEnd('/')))
        assertTrue(isSavedPanelLoginPage(panel, panel + "login"))
        assertTrue(isSavedPanelLoginPage("https://panel.example/", "https://panel.example/"))
    }

    @Test
    fun refusesOtherOriginsRoutesAndPlainHttp() {
        listOf(
            "http://127.0.0.1:23000/private-panel/",
            "https://127.0.0.1:23001/private-panel/",
            "https://127.0.0.1.evil.example:23000/private-panel/",
            "https://user@127.0.0.1:23000/private-panel/",
            panel + "panel/",
            panel + "../login",
            panel + "?next=other",
            panel + "#login",
            panel.replace("private-panel", "another-panel"),
        ).forEach { assertFalse(it, isSavedPanelLoginPage(panel, it)) }
    }
}
