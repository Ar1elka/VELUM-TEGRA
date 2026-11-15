package com.velumtegra.xuimobile.sshport

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

private sealed interface SshPortConfirmation {
    data class Switch(val profile: SshPortProfile, val port: Int) : SshPortConfirmation
    data class Close(val profile: SshPortProfile) : SshPortConfirmation
}

@Composable
internal fun SshPortScreen(migration: SshPortMigration, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var profiles by remember { mutableStateOf<List<SshPortProfile>?>(null) }
    var loaded by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<SshPortProfile?>(null) }
    var proposed by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf<SshPortConfirmation?>(null) }
    var outcome by remember { mutableStateOf<SshPortResult?>(null) }
    var running by remember { mutableStateOf(false) }
    val parsed = SshPortPolicy.parse(proposed)

    LaunchedEffect(migration) {
        profiles = migration.profiles()
        selected = profiles?.singleOrNull { it.access.port == STANDARD_SSH_PORT } ?: profiles?.singleOrNull()
        loaded = true
    }
    BackHandler { if (!running) onBack() }

    fun run(action: SshPortConfirmation) {
        if (running) return
        confirmation = null
        outcome = null
        running = true
        scope.launch {
            try {
                val result = when (action) {
                    is SshPortConfirmation.Switch -> migration.switch(action.profile, action.port)
                    is SshPortConfirmation.Close -> migration.closeStandardPort(action.profile)
                }
                outcome = result
                if (result is SshPortResult.Switched) {
                    selected = result.profile
                    profiles = migration.profiles()
                }
            } finally {
                running = false
            }
        }
    }

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag("ssh_port_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack, enabled = !running) { Text("Назад") }
        Text("Смена SSH-порта", style = MaterialTheme.typography.headlineSmall)
        Text("Выберите сохранённый SSH-профиль VPS.", style = MaterialTheme.typography.bodyMedium)
        val items = profiles
        when {
            !loaded -> LinearProgressIndicator(Modifier.fillMaxWidth())
            items == null -> Text("Не удалось прочитать сохранённые SSH-профили.")
            items.isEmpty() -> Text("Добавьте VPS и SSH-профиль в разделе «Мои серверы».")
            else -> items.forEach { profile ->
                val choose = {
                    selected = profile
                    proposed = ""
                    outcome = null
                }
                val label = profile.serverName + " · " + profile.target
                if (profile == selected) Button(choose, enabled = !running, modifier = Modifier.fillMaxWidth()) {
                    Text(label)
                } else OutlinedButton(choose, enabled = !running, modifier = Modifier.fillMaxWidth()) {
                    Text(label)
                }
            }
        }

        val profile = selected
        if (profile != null && profile.access.port == STANDARD_SSH_PORT) {
            Text("Текущий порт 22. Новый вход будет проверен до переключения профиля.")
            OutlinedTextField(
                value = proposed,
                onValueChange = { proposed = it.take(5).filter { digit -> digit in '0'..'9' } },
                label = { Text("Новый SSH-порт") },
                supportingText = { Text("От 1 до 65535, кроме 22") },
                isError = proposed.isNotEmpty() && parsed == null,
                singleLine = true,
                enabled = !running,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth().testTag("ssh_port_input"),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { proposed = SshPortPolicy.randomPort().toString() }, enabled = !running) {
                    Text("Случайный порт")
                }
                Button(
                    onClick = { parsed?.let { confirmation = SshPortConfirmation.Switch(profile, it) } },
                    enabled = !running && parsed != null,
                ) { Text("Проверить и перейти") }
            }
        } else if (profile != null && outcome != SshPortResult.Closed) {
            val hasOriginal = items.orEmpty().any {
                it.serverId == profile.serverId && it.access.port == STANDARD_SSH_PORT &&
                    it.access.host == profile.access.host && it.access.username == profile.access.username &&
                    it.access.savedFingerprint == profile.access.savedFingerprint &&
                    it.access.credentialRefDigest == profile.access.credentialRefDigest
            }
            if (hasOriginal) {
                Text("Порт 22 можно закрыть после подтверждения нового входа.")
                OutlinedButton(
                    onClick = { confirmation = SshPortConfirmation.Close(profile) },
                    enabled = !running,
                ) { Text("Закрыть порт 22") }
            } else {
                Text("Этот профиль использует порт ${profile.access.port}. Для перехода выберите профиль на порту 22.")
            }
        }

        if (running) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text("Проверяем SSH и состояние служб VPS…")
        }
        when (val result = outcome) {
            is SshPortResult.Switched -> Text(
                "Вход через ${result.profile.access.port} проверен. Порт 22 доступен как резервный.",
                modifier = Modifier.testTag("ssh_port_switched"),
            )
            SshPortResult.Closed -> Text("Порт 22 закрыт. Вход через новый порт проверен повторно.")
            is SshPortResult.Blocked -> Text(result.reason, color = MaterialTheme.colorScheme.error)
            null -> Unit
        }
    }

    confirmation?.let { action ->
        val title: String
        val detail: String
        when (action) {
            is SshPortConfirmation.Switch -> {
                title = "Перейти на порт ${action.port}?"
                detail = "${action.profile.serverName} · ${action.profile.target}\n\n" +
                    "Проверьте, что TCP-порт ${action.port} разрешён в файрволе VPS и у провайдера. " +
                    "После проверки нового входа связанные профили X-UI и веб-панели перейдут на новый порт. " +
                    "Если веб-панель попросит подтвердить сертификат для нового SSH-маршрута, сверьте отпечаток."
            }
            is SshPortConfirmation.Close -> {
                title = "Закрыть SSH-порт 22?"
                detail = "${action.profile.serverName} · ${action.profile.target}\n\n" +
                    "Это отключит вход через 22 для всех клиентов. Если проверка нового входа не завершится, " +
                    "сервер попытается вернуть доступ на 22 через две минуты."
            }
        }
        AlertDialog(
            onDismissRequest = { confirmation = null },
            title = { Text(title) },
            text = { Text(detail) },
            confirmButton = { Button(onClick = { run(action) }) { Text("Подтвердить") } },
            dismissButton = { TextButton(onClick = { confirmation = null }) { Text("Отмена") } },
        )
    }
}
