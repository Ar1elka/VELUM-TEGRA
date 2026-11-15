package com.velumtegra.xuimobile.management

internal data class XuiMenuChoice(val number: String, val label: String)
internal data class XuiMenuPrompt(
    val text: String,
    val choices: List<XuiMenuChoice> = emptyList(),
    val yesNo: Boolean = false,
)

private val terminalSequence = Regex(
    """\x1B(?:\][^\x07\x1B]*(?:\x07|\x1B\\|$)|[PX^_][^\x1B]*(?:\x1B\\|$)|\[[0-?]*[ -/]*(?:[@-~]|$)|[ -/]*[0-~])""",
)
private val menuOption = Regex("""^\s*[│|║]?\s*([0-9]{1,3})\s*[.)-]\s+(.+?)\s*[│|║]?\s*$""")
private val numberedPrompt = Regex(
    """(?i)^(?:(?:please\s+)?(?:enter (?:your )?(?:selection|choice)|(?:choose|select) (?:an? |your )?(?:option|choice))(?:\s+[^:]*)?|choose\s+\[[0-9]{1,3}\]):$""",
)
private val confirmationPrompt = Regex("""(?i)(?:\[\s*y\s*/\s*n\s*\]|\(\s*y\s*/\s*n\s*\)|\[default\s+[yn]\]):?$""")
private val separator = Regex("""^[\s│|║═─╔╗╚╝╟╢┌┐└┘+\-]+$""")

internal fun cleanXuiMenuOutput(raw: String): String =
    terminalSequence.replace(raw, "").replace("\r\n", "\n").replace('\r', '\n')
        .filter { it == '\n' || it == '\t' || (!it.isISOControl() && it !in '\u202A'..'\u202E' && it !in '\u2066'..'\u2069') }

internal fun xuiMenuPrompt(turnOutput: String): XuiMenuPrompt? {
    val lines = cleanXuiMenuOutput(turnOutput).trimEnd().lines()
    val text = lines.last().trim()
    if (!text.endsWith(':') && !confirmationPrompt.containsMatchIn(text)) return null
    if (!numberedPrompt.matches(text)) return XuiMenuPrompt(text, yesNo = confirmationPrompt.containsMatchIn(text))

    val choices = mutableListOf<XuiMenuChoice>()
    for (line in lines.dropLast(1).asReversed()) {
        val match = menuOption.matchEntire(line)
        if (match != null) {
            choices += XuiMenuChoice(match.groupValues[1], match.groupValues[2].trim())
        } else if (choices.isNotEmpty() && line.isNotBlank() && !separator.matches(line)) {
            break
        }
    }
    val unique = choices.distinctBy { it.number }
    return XuiMenuPrompt(text, if (unique.size == choices.size) unique.asReversed() else emptyList())
}
