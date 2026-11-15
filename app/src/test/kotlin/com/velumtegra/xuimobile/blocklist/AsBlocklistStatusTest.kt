package com.velumtegra.xuimobile.blocklist

import com.velumtegra.xuimobile.inventory.serverCardDetail
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AsBlocklistStatusTest {
    private val installed = """
        VELUM_BL_INFO:os=Ubuntu 26.04 LTS
        VELUM_BL_INFO:installed=1
        VELUM_BL_INFO:backend=nft
        VELUM_BL_INFO:active=1
        VELUM_BL_INFO:vk=1
        VELUM_BL_INFO:gov4=1151
        VELUM_BL_INFO:gov6=21
        VELUM_BL_INFO:vk4=204
        VELUM_BL_INFO:vk6=3
        VELUM_BL_INFO:updated=1794643912
        VELUM_BL_INFO:dropped=17
        VELUM_BL_INFO:auto=timer
        VELUM_BL_INFO:firewalls=ufw docker
        VELUM_BL_INFO:package_manager=apt-get
        VELUM_BL:INSTALLED
    """.trimIndent()

    @Test
    fun installedReplyIsParsedFromMarkerLines() {
        val status = AsBlocklistStatus.parse("motd noise\n$installed\n")!!

        assertEquals("INSTALLED", AsBlocklistStatus.replyCode(installed))
        assertEquals("Ubuntu 26.04 LTS", status.os)
        assertTrue(status.installed && status.active && status.blockVk)
        assertEquals("nftables", status.backendLabel)
        assertEquals(listOf(1151, 21, 204, 3), listOf(status.gov4, status.gov6, status.vk4, status.vk6))
        assertEquals(1794643912L, status.updatedEpochSeconds)
        assertEquals(17L, status.dropped)
        assertEquals(listOf("ufw", "docker"), status.otherFirewalls)
    }

    @Test
    fun freshServerWithoutFirewallToolsNamesWhatWillBeInstalled() {
        val status = AsBlocklistStatus.parse(
            "VELUM_BL_INFO:os=\nVELUM_BL_INFO:installed=0\nVELUM_BL_INFO:backend=none\n" +
                "VELUM_BL_INFO:updated=\nVELUM_BL_INFO:package_manager=dnf\nVELUM_BL:OK\n",
        )!!

        assertFalse(status.installed)
        assertNull(status.updatedEpochSeconds)
        assertEquals("nftables (будет установлен через dnf)", status.backendLabel)
        assertEquals("Linux (название не определено)", status.osLabel)
    }

    @Test
    fun foreignOrDuplicatedReplyIsNotTrusted() {
        assertNull(AsBlocklistStatus.replyCode("VELUM_BL:OK\nVELUM_BL:REMOVED\n"))
        assertNull(AsBlocklistStatus.replyCode("VELUM_BL:ok; rm -rf /\n"))
        assertNull(AsBlocklistStatus.replyCode("nothing here"))
        assertNull(AsBlocklistStatus.parse("VELUM_BL:OK\n"))
        assertEquals("ipset + iptables", AsBlocklistStatus.parse(installed.replace("backend=nft", "backend=ipset"))!!.backendLabel)
        assertEquals("none", AsBlocklistStatus.parse(installed.replace("backend=nft", "backend=\$(reboot)"))!!.backend)
    }

    @Test
    fun everyServerFailureCodeHasItsOwnExplanation() {
        val fallback = AsBlocklistStatus.failureText(null)
        val codes = listOf("ROOT_REQUIRED", "NO_FIREWALL", "NO_DOWNLOADER", "DOWNLOAD", "BAD_LIST",
            "YOUR_IP_LISTED", "APPLY", "BUSY", "NOT_INSTALLED", "STATE", "TEMP")

        codes.forEach { assertTrue(it, AsBlocklistStatus.failureText(it) != fallback) }
        // Every code the script can fail with must be known to the app.
        val script = File("src/main/assets/velum-as-blocklist.sh").readText()
        val emitted = Regex("""fail ([A-Z_]+)""").findAll(script).map { it.groupValues[1] }.toSet() - "INVALID"
        assertEquals(emptySet<String>(), emitted - codes.toSet())
        assertFalse("heredoc terminator must not occur inside the script", "VELUM_AS_BLOCKLIST_SCRIPT" in script)
        assertFalse("script must keep LF line endings", '\r' in script)
    }

    @Test
    fun serverCardLineShowsAddressAndNextStep() {
        assertEquals("SSH-доступ ещё не добавлен", serverCardDetail(emptyList(), 0, 0))
        assertEquals("203.0.113.7 · 3x-ui ещё не найдена", serverCardDetail(listOf("203.0.113.7"), 1, 0))
        assertEquals("203.0.113.7 · SSH-профилей: 2 · 3x-ui найдена", serverCardDetail(listOf("203.0.113.7"), 2, 1))
        assertEquals(
            "203.0.113.7 и ещё 1 · SSH-профилей: 2 · 3x-ui найдена",
            serverCardDetail(listOf("203.0.113.7", "example.org"), 2, 1),
        )
    }
}
