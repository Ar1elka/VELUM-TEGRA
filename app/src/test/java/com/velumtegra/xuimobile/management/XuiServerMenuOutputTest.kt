package com.velumtegra.xuimobile.management

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiServerMenuOutputTest {
    @Test fun readsEveryServerChoiceInServerOrderIncludingNewChoices() {
        val raw = buildString {
            appendLine("╔════════════════╗")
            appendLine("│  3X-UI Panel Management Script │")
            (0..29).forEach { number ->
                if (number == 12) appendLine("│────────────────│")
                appendLine("│  \u001b[32m$number.\u001b[0m Action $number │")
            }
            appendLine("╚════════════════╝")
            appendLine()
            appendLine("Panel state: Running")
            appendLine("Xray state: Running")
            append("Please enter your selection [0-29]: ")
        }

        val choices = requireNotNull(xuiMenuPrompt(raw)).choices
        assertEquals((0..29).map(Int::toString), choices.map { it.number })
        assertEquals("Action 29", choices.last().label)
    }

    @Test fun readsCurrentSubmenuAndDropsOldChoicesAtTextPrompt() {
        val output = "1) Rule numbers\r\n2) Ports\r\nEnter your choice (1 or 2): "
        val choices = requireNotNull(xuiMenuPrompt(output)).choices
        assertEquals(listOf(XuiMenuChoice("1", "Rule numbers"), XuiMenuChoice("2", "Ports")), choices)

        val prompt = requireNotNull(xuiMenuPrompt("Please enter your domain name: "))
        assertTrue(prompt.choices.isEmpty())
        assertTrue(requireNotNull(xuiMenuPrompt("Enable firewall? [Y/n]: ")).yesNo)
        assertTrue(requireNotNull(xuiMenuPrompt("Continue? [Default n]: ")).yesNo)
        assertEquals(
            listOf("1", "2"),
            requireNotNull(xuiMenuPrompt("1. Install PostgreSQL\n2. Use an existing server\nChoose [1]: "))
                .choices.map { it.number },
        )
        assertNull(xuiMenuPrompt("Running…"))
    }

    @Test fun ambiguousChoicesAndControlSequencesCannotCreateButtons() {
        val ambiguous = "1. First\n1. Second\nChoose an option: "
        assertTrue(requireNotNull(xuiMenuPrompt(ambiguous)).choices.isEmpty())
        assertEquals("Answer:", cleanXuiMenuOutput("\u001b]0;title\u0007\u001b[32mAnswer:\u001b[0m\u202e"))
    }
}
