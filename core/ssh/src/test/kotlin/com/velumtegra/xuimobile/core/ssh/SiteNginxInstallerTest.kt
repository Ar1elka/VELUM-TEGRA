package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteNginxInstallerTest {
    @Test fun `exit codes map to distinct outcomes`() {
        assertEquals(SiteNginxInstallOutcome.NO_APT, SiteNginxInstaller.outcomeForExitCode(69))
        assertEquals(SiteNginxInstallOutcome.INSTALL_FAILED, SiteNginxInstaller.outcomeForExitCode(70))
        assertEquals(SiteNginxInstallOutcome.START_FAILED, SiteNginxInstaller.outcomeForExitCode(71))
        assertEquals(SiteNginxInstallOutcome.UNSUPPORTED_OS, SiteNginxInstaller.outcomeForExitCode(72))
        assertEquals(SiteNginxInstallOutcome.UNKNOWN, SiteNginxInstaller.outcomeForExitCode(1))
    }

    @Test fun `end of life message says what to do and that sources were not touched`() {
        val text = SiteNginxInstallOutcome.UNSUPPORTED_OS.message
        assertTrue("Debian 12/13" in text && "не меняло" in text)
    }

    @Test fun `command diagnoses old releases read-only and never edits apt sources`() {
        val c = SiteNginxInstaller.COMMAND
        assertTrue("exit 72" in c && "/etc/os-release" in c)
        assertTrue("sources.list" !in c && "sed -i" !in c)
    }
}
