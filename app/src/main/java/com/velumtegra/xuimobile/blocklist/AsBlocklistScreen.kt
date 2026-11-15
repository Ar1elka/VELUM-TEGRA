package com.velumtegra.xuimobile.blocklist

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.sshport.SshPortProfile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.launch

@Composable
internal fun AsBlocklistScreen(manager: AsBlocklistManager, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var profiles by remember { mutableStateOf<List<SshPortProfile>?>(null) }
    var loaded by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<SshPortProfile?>(null) }
    var status by remember { mutableStateOf<AsBlocklistStatus?>(null) }
    var blockVk by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf<AsBlocklistAction?>(null) }
    var confirmation by remember { mutableStateOf<AsBlocklistAction?>(null) }

    LaunchedEffect(manager) {
        profiles = manager.profiles()
        selected = profiles?.singleOrNull()
        loaded = true
    }
    BackHandler { if (running == null) onBack() }

    fun run(action: AsBlocklistAction) {
        val profile = selected ?: return
        if (running != null) return
        confirmation = null
        notice = null
        error = null
        running = action
        scope.launch {
            try {
                when (val result = manager.run(profile, action, blockVk)) {
                    is AsBlocklistResult.Ready -> {
                        status = result.status
                        if (result.status.installed) blockVk = result.status.blockVk
                        notice = when (result.code) {
                            "INSTALLED" -> "Готово: защита включена, списки будут обновляться каждый день."
                            "REMOVED" -> "Защита удалена: правила, списки и расписание убраны с сервера."
                            else -> null
                        }
                    }
                    is AsBlocklistResult.Blocked -> error = result.reason
                }
            } finally {
                running = null
            }
        }
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag("as_blocklist_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack, enabled = running == null) { Text("← Назад") }
        Text("Защита от сканеров", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "Закрывает сервер от сетей российских госорганов по открытому списку AS_Network_List. " +
                "Приложение само определит систему сервера и настроит подходящий файрвол.",
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        val items = profiles
        when {
            !loaded -> LinearProgressIndicator(Modifier.fillMaxWidth())
            items == null -> Text("Не удалось прочитать сохранённые SSH-профили.", color = MaterialTheme.colorScheme.error)
            items.isEmpty() -> Text("Сначала добавьте сервер и SSH-доступ в разделе «Мои серверы».")
            else -> {
                if (items.size > 1) Text("Сервер", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                items.forEach { profile ->
                    val choose = {
                        if (selected != profile) { selected = profile; status = null; notice = null; error = null }
                    }
                    val label = profile.serverName + " · " + profile.target
                    if (profile == selected) Button(choose, enabled = running == null, modifier = Modifier.fillMaxWidth()) {
                        Text(label)
                    } else OutlinedButton(choose, enabled = running == null, modifier = Modifier.fillMaxWidth()) {
                        Text(label)
                    }
                }
            }
        }

        val profile = selected
        val current = status
        if (profile != null && current == null) {
            Button(
                onClick = { run(AsBlocklistAction.STATUS) }, enabled = running == null,
                modifier = Modifier.fillMaxWidth().testTag("as_blocklist_check"),
            ) { Text("Проверить сервер") }
        }

        if (current != null) {
            Card(
                modifier = Modifier.fillMaxWidth().testTag("as_blocklist_status"),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        when {
                            current.installed && current.active -> "Защита работает"
                            current.installed -> "Защита установлена, но правила сейчас не загружены"
                            else -> "Защита не установлена"
                        },
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
                        color = if (current.installed && !current.active) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    StatusLine("Система", current.osLabel)
                    StatusLine("Файрвол", current.backendLabel)
                    if (current.installed) {
                        StatusLine("Заблокировано сетей", "${current.gov4} IPv4 · ${current.gov6} IPv6")
                        if (current.blockVk) StatusLine("Сети VK и MAX", "${current.vk4} IPv4 · ${current.vk6} IPv6")
                        StatusLine("Отбито попыток подключения", current.dropped.toString())
                        StatusLine("Списки обновлены", current.updatedEpochSeconds?.let(::formatTime) ?: "нет данных")
                        StatusLine("Автообновление", when (current.autoUpdate) {
                            "timer", "cron" -> "каждый день"
                            "stopped" -> "таймер остановлен"
                            else -> "не настроено"
                        })
                    }
                    if (current.otherFirewalls.isNotEmpty()) {
                        Text(
                            "На сервере также работают: ${current.otherFirewalls.joinToString(", ")}. " +
                                "Защита ставится отдельной таблицей и их правила не меняет.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (current.installed && !current.active) Text(
                        "Нажмите «Обновить списки сейчас», чтобы загрузить правила заново.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text("Запретить связь с VK и MAX", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(
                        "Сервер и клиенты VPN через него не смогут открывать VK, OK и мессенджер MAX.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = blockVk, onCheckedChange = { blockVk = it }, enabled = running == null,
                    modifier = Modifier.testTag("as_blocklist_vk"))
            }

            val vkChanged = current.installed && blockVk != current.blockVk
            Button(
                onClick = { if (current.installed) run(AsBlocklistAction.INSTALL) else confirmation = AsBlocklistAction.INSTALL },
                enabled = running == null,
                modifier = Modifier.fillMaxWidth().testTag("as_blocklist_install"),
            ) {
                Text(when {
                    !current.installed -> "Включить защиту"
                    vkChanged -> "Применить настройку VK и MAX"
                    else -> "Обновить списки сейчас"
                })
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { run(AsBlocklistAction.STATUS) }, enabled = running == null,
                    modifier = Modifier.weight(1f).testTag("as_blocklist_refresh")) { Text("Проверить снова") }
                if (current.installed) {
                    OutlinedButton(onClick = { confirmation = AsBlocklistAction.REMOVE }, enabled = running == null,
                        modifier = Modifier.weight(1f).testTag("as_blocklist_remove")) {
                        Text("Удалить защиту", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }

        running?.let { action ->
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(when (action) {
                AsBlocklistAction.STATUS -> "Подключаемся и определяем систему сервера…"
                AsBlocklistAction.INSTALL -> "Скачиваем списки и настраиваем файрвол. Обычно это занимает меньше минуты…"
                AsBlocklistAction.REMOVE -> "Убираем правила и расписание…"
            })
        }
        notice?.let { Text(it, modifier = Modifier.testTag("as_blocklist_notice"), fontWeight = FontWeight.SemiBold) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("as_blocklist_error")) }
    }

    confirmation?.let { action ->
        val profile = selected
        val install = action == AsBlocklistAction.INSTALL
        AlertDialog(
            onDismissRequest = { confirmation = null },
            title = { Text(if (install) "Включить защиту?" else "Удалить защиту?") },
            text = {
                Text(
                    profile?.let { "${it.serverName} · ${it.target}\n\n" }.orEmpty() +
                        if (install) {
                            "На сервере появятся правила файрвола, которые отбрасывают новые подключения из сетей списка" +
                                (if (blockVk) ", и запрет исходящих соединений к VK и MAX" else "") +
                                ". Списки будут обновляться с GitHub раз в день. " +
                                "Если нужного пакета файрвола нет, он будет установлен. " +
                                "Ваш текущий адрес проверяется заранее: если он в списке, ничего не изменится."
                        } else {
                            "С сервера будут убраны правила, скачанные списки и ежедневное обновление. " +
                                "Остальные настройки файрвола не затрагиваются."
                        },
                )
            },
            confirmButton = { Button(onClick = { run(action) }) { Text(if (install) "Включить" else "Удалить") } },
            dismissButton = { TextButton(onClick = { confirmation = null }) { Text("Отмена") } },
        )
    }
}

@Composable
private fun StatusLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
    }
}

private fun formatTime(epochSeconds: Long): String =
    SimpleDateFormat("d MMMM, HH:mm", Locale("ru")).format(Date(epochSeconds * 1000))
