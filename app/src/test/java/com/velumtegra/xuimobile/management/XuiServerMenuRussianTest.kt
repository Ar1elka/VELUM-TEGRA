package com.velumtegra.xuimobile.management

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiServerMenuRussianTest {
    @Test fun everyOfficialMainActionIsTranslatedWithoutChangingItsNumber() {
        val labels = listOf(
            "Exit Script", "Install", "Update", "Update to Dev Channel (latest commit)", "Update Menu",
            "Legacy Version", "Uninstall", "Reset Username & Password", "Reset Web Base Path",
            "Reset Settings", "Change Port", "View Current Settings", "Start", "Stop", "Restart",
            "Restart Xray", "Check Status", "Logs Management", "Enable Autostart", "Disable Autostart",
            "SSL Certificate Management", "Cloudflare SSL Certificate", "IP Limit Management",
            "Firewall Management", "SSH Port Forwarding Management", "PostgreSQL Management",
            "Enable BBR", "Update Geo Files", "Speedtest by Ookla",
        )
        val raw = labels.mapIndexed { index, label -> "│  $index. $label │" }.joinToString("\n") +
            "\n29. Extension command\nPanel state: Running\nxray state: Not Running" +
            "\nStart automatically: Yes\nPlease enter your selection [0-29]: "
        val prompt = requireNotNull(xuiMenuPrompt(raw))
        val grouped = xuiMenuSections(prompt)

        assertTrue(xuiMainMenu(prompt))
        assertEquals("Службы и журналы", grouped.first().title)
        assertEquals(prompt.choices.toSet(), grouped.flatMap { it.choices }.toSet())
        assertEquals(30, grouped.sumOf { it.choices.size })
        assertTrue(prompt.choices.take(29).all { russianXuiChoice(it, true) != it.label })
        assertEquals("Extension command", russianXuiChoice(prompt.choices.last(), true))
        assertEquals(listOf("x-ui работает", "Xray остановлен", "автозапуск включён"), russianXuiStatus(raw))
    }

    @Test fun submenusKeepTheirContextAndExactServerChoice() {
        val prompt = requireNotNull(xuiMenuPrompt("1. Enable BBR\n2. Disable BBR\n0. Back to Main Menu\nChoose an option: "))
        assertFalse(xuiMainMenu(prompt))
        assertEquals(listOf("1", "2", "0"), xuiMenuSections(prompt).single().choices.map { it.number })
        assertEquals("Включить BBR", russianXuiChoice(prompt.choices.first(), false))
        assertEquals("Управление BBR", russianXuiChoice(prompt.choices.first(), true))
    }

    @Test fun translatesKnownPromptsAndMasksSecretsAndUnknownInputs() {
        assertEquals("Сбросить логин и пароль панели?", russianXuiPrompt(
            "Are you sure to reset the username and password of the panel? [Default n]:",
        ))
        assertEquals("Введите домен.", russianXuiPrompt("Please enter your domain name:"))
        assertFalse(xuiPromptMasksInput("Please enter your domain name:"))
        assertTrue(xuiPromptMasksInput("Input your token here:"))
        assertTrue(xuiPromptMasksInput("Custom input:"))
        assertEquals("Custom input:", russianXuiPrompt("Custom input:"))
        assertEquals("По умолчанию", xuiEmptyReplyLabel("Generate SSL certificate for IP now? [y/N]:"))
        assertEquals("Пустой ответ", xuiEmptyReplyLabel("Do you want to proceed? [y/n]:"))
        assertTrue(xuiMenuReturnPrompt("Press enter to return to the main menu:"))
    }
}
