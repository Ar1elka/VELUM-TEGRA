package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** A line of secondary text with an optional test tag. */
internal data class DetailLine(val text: String, val tag: String? = null)

private fun Modifier.tagged(tag: String?): Modifier = if (tag == null) this else testTag(tag)

/**
 * The top of every backup / restore screen: where the user is in the chain, one sentence about what
 * the step does, and the full fine print one tap away instead of four paragraphs before the button.
 */
@Composable
internal fun StepIntro(
    step: String?,
    summary: DetailLine,
    details: List<DetailLine> = emptyList(),
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        step?.let {
            Text(it, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        }
        Text(summary.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.tagged(summary.tag))
        if (details.isNotEmpty()) {
            TextButton(onClick = { expanded = !expanded }) { Text(if (expanded) "Скрыть подробности" else "Подробнее") }
            if (expanded) details.forEach {
                Text(it.text, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.tagged(it.tag))
            }
        }
    }
}

/** Server name with the SSH route underneath, replacing the «SSH: …» / «Установка: …» rows. */
@Composable
internal fun TargetLines(server: String, ssh: String, sshTag: String? = null) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(server, style = MaterialTheme.typography.titleMedium)
        Text(ssh, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.tagged(sshTag))
    }
}

/** Checksums, request ids and other values only needed for support, folded away by default. */
@Composable
internal fun TechDetails(lines: List<DetailLine>) {
    if (lines.isEmpty()) return
    var expanded by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        TextButton(onClick = { expanded = !expanded }) {
            Text(if (expanded) "Скрыть технические данные" else "Технические данные")
        }
        if (expanded) lines.forEach {
            Text(it.text, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.tagged(it.tag))
        }
    }
}

/** The local re-read is rarely needed: a quiet text button instead of a full-width outlined one. */
@Composable
internal fun QuietRefresh(onClick: () -> Unit, enabled: Boolean, tag: String) {
    TextButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().testTag(tag)) {
        Text("Обновить")
    }
}

internal fun humanBytes(bytes: Number): String {
    val value = bytes.toLong()
    return when {
        value < 1024 -> "$value Б"
        value < 1024 * 1024 -> String.format(Locale("ru"), "%.1f КБ", value / 1024.0)
        value < 1024L * 1024 * 1024 -> String.format(Locale("ru"), "%.1f МБ", value / (1024.0 * 1024))
        else -> String.format(Locale("ru"), "%.2f ГБ", value / (1024.0 * 1024 * 1024))
    }
}

private val humanClockFormat = DateTimeFormatter.ofPattern("HH:mm", Locale("ru"))

// Android formats "MMMM" as the nominative month ("14 ноябрь"), so the genitive names are spelled out.
private val monthsGenitive = listOf("января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря")

internal fun humanTime(time: Instant, zone: ZoneId = ZoneId.systemDefault()): String {
    val local = time.atZone(zone)
    return "${local.dayOfMonth} ${monthsGenitive[local.monthValue - 1]}, ${humanClockFormat.format(local)}"
}
