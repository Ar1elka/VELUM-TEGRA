package com.velumtegra.xuimobile.readiness

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

@Composable
private fun ServerProfileCard(p: com.velumtegra.xuimobile.core.ssh.ServerProfile) {
    androidx.compose.material3.Card(Modifier.fillMaxWidth().testTag("live_ssh_profile")) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Сервер", style = MaterialTheme.typography.titleMedium)
            @Composable fun row(label: String, value: String?) { if (!value.isNullOrBlank()) Text("$label: $value") }
            row("Система", p.osPrettyName ?: listOfNotNull(p.osId, p.osVersion).joinToString(" "))
            row("Архитектура", p.architecture)
            row("Вход", p.loginUser + " · " + when (p.privilege) {
                com.velumtegra.xuimobile.core.ssh.RemotePrivilegeMode.ROOT -> "root"
                com.velumtegra.xuimobile.core.ssh.RemotePrivilegeMode.SUDO_NOPASSWD -> "права root через sudo"
                com.velumtegra.xuimobile.core.ssh.RemotePrivilegeMode.SUDO_PASSWORD -> "sudo с паролем"
                com.velumtegra.xuimobile.core.ssh.RemotePrivilegeMode.UNPRIVILEGED -> "без прав root"
            })
            row("Хостинг", p.provider ?: p.virtualization?.let { "виртуальная машина ($it)" })
            row("Пакеты", p.packageManager)
            row("Память", p.memoryMb?.let { "$it МБ" })
            row("Свободно на диске", p.freeDiskMb?.let { if (it >= 2048) "${it / 1024} ГБ" else "$it МБ" })
            if (p.blockers.isEmpty()) {
                Text("✓ Подходит для установки 3x-ui и сайта", fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
            } else {
                Text("Установка через приложение невозможна:", color = MaterialTheme.colorScheme.error)
                p.blockers.forEach { Text("• $it", color = MaterialTheme.colorScheme.error) }
            }
            p.notes.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** A distinct opt-in ONLINE screen. The existing SshReadinessScreen stays entirely offline. */
@Composable
fun LiveSshConnectionScreen(
    serverId: String,
    serverName: String,
    readinessPort: SshReadinessPort,
    connectionPort: LiveSshConnectionPort,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    var generation by remember(serverId, readinessPort, connectionPort) { mutableStateOf(0L) }
    var loaded by remember(serverId, readinessPort) { mutableStateOf<LocalSshAccessList?>(null) }
    var selected by remember(serverId, readinessPort) { mutableStateOf<LocalSshAccessSummary?>(null) }
    var consent by remember(serverId, readinessPort) { mutableStateOf(false) }
    var connecting by remember(serverId, readinessPort) { mutableStateOf(false) }
    var result by remember(serverId, readinessPort) { mutableStateOf<LiveSshConnectionResult?>(null) }
    var job by remember(serverId, readinessPort) { mutableStateOf<Job?>(null) }

    fun revoke() {
        ++generation
        job?.cancel()
        job = null
        connecting = false
        consent = false
        result = null
    }
    fun reload() {
        revoke()
        selected = null
        loaded = null
        val request = ++generation
        scope.launch {
            val latest = try { readinessPort.listForExactServer(serverId) }
            catch (c: CancellationException) { throw c }
            catch (_: Exception) { LocalSshAccessList.Unavailable("Не удалось прочитать SSH-доступы.") }
            if (request == generation && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                loaded = latest
            }
        }
    }
    DisposableEffect(lifecycleOwner, serverId, readinessPort, connectionPort) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> reload()
                Lifecycle.Event.ON_STOP -> { revoke(); selected = null; loaded = null }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        if (lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) reload()
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            revoke()
        }
    }
    fun close() { revoke(); onBack() }
    BackHandler { close() }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp)
            .testTag("live_ssh_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Реальное SSH-подключение", style = MaterialTheme.typography.titleLarge)
        Text("Сервер: $serverName")
        Text("Подключение использует сохранённый секрет и закреплённый SSH-ключ. " +
            "После входа приложение только читает сведения о сервере (система, права, облако, ресурсы) " +
            "и закрывает сессию. Ничего на VPS не меняется.")
        OutlinedButton(onClick = { reload() }, enabled = !connecting,
            modifier = Modifier.testTag("live_ssh_refresh")) { Text("Обновить SSH-доступы") }
        when (val state = loaded) {
            null -> Text("Читаем сохранённые SSH-доступы…")
            is LocalSshAccessList.Unavailable -> Text(state.reason, color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("live_ssh_error"))
            is LocalSshAccessList.Available -> {
                if (state.items.isEmpty()) Text("SSH-доступ ещё не сохранён. Вернитесь к карточке сервера.")
                state.items.forEach { item ->
                    OutlinedButton(
                        onClick = {
                            revoke()
                            selected = null
                            val request = ++generation
                            scope.launch {
                                val check = try { readinessPort.previewExact(serverId, item.accessId) }
                                catch (c: CancellationException) { throw c }
                                catch (_: Exception) { LocalSshReadinessResult.Blocked("Нет доступа к локальным данным.") }
                                if (request == generation &&
                                    lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                    when (check) {
                                        is LocalSshReadinessResult.MetadataPresent -> {
                                            if (check.summary.copy(authLabel = item.authLabel) == item) selected = check.summary
                                            else result = LiveSshConnectionResult.Blocked("Подмена SSH-доступа. Обновите список.")
                                        }
                                        is LocalSshReadinessResult.Blocked -> {
                                            result = LiveSshConnectionResult.Blocked("SSH-доступ изменился. Обновите список.")
                                        }
                                    }
                                }
                            }
                        }, enabled = !connecting,
                        modifier = Modifier.fillMaxWidth().testTag("live_ssh_select_${item.accessId}"),
                    ) { Text("${item.username}@${item.host}:${item.port} · ${item.authLabel}") }
                }
            }
        }
        val choice = selected
        if (choice != null) {
            Text("Выбранный доступ: ${LiveSshConnectionPolicy.exactTarget(choice)}")
            Text("Сохранённый отпечаток: ${choice.savedFingerprint}")
            Text("Проверьте SSH-адрес, имя пользователя и отпечаток по независимому источнику.")
            Row {
                Checkbox(checked = consent, enabled = !connecting,
                    onCheckedChange = { consent = it; result = null },
                    modifier = Modifier.testTag("live_ssh_consent"))
                Text("Разрешаю одно SSH-подключение с сохранёнными данными. Только чтение, без изменений VPS.")
            }
            Button(
                enabled = !connecting && consent,
                modifier = Modifier.testTag("live_ssh_connect"),
                onClick = {
                    if (connecting || !consent || selected != choice ||
                        !lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@Button
                    val requested = ++generation
                    val chosen = choice
                    val exactTarget = LiveSshConnectionPolicy.exactTarget(chosen)
                    consent = false
                    connecting = true
                    result = null
                    job = scope.launch {
                        val answer = try {
                            connectionPort.connectExact(serverId, chosen.accessId, chosen, exactTarget, true)
                        } catch (c: CancellationException) { throw c }
                          catch (_: Exception) { LiveSshConnectionResult.Blocked("Ошибка попытки подключения.") }
                        if (requested == generation && selected == chosen &&
                            lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                            connecting = false
                            consent = false
                            result = answer
                        }
                    }
                },
            ) { Text(if (connecting) "Подключение…" else "Подключиться и проверить SSH") }
            if (connecting) OutlinedButton(
                onClick = { revoke() }, modifier = Modifier.testTag("live_ssh_cancel"),
            ) { Text("Отменить подключение") }
        }
        when (val outcome = result) {
            is LiveSshConnectionResult.Verified -> {
                Text(
                    "SSH-подключение подтверждено: ${outcome.target}. " +
                        "Ключ ${outcome.fingerprint}. Сессия закрыта, VPS не изменялся.",
                    modifier = Modifier.testTag("live_ssh_verified"),
                )
                outcome.profile?.let { ServerProfileCard(it) }
                    ?: Text("Сведения о сервере прочитать не удалось.", style = MaterialTheme.typography.bodySmall)
            }
            is LiveSshConnectionResult.Blocked -> Text(outcome.message,
                color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("live_ssh_blocked"))
            null -> Unit
        }
        OutlinedButton(onClick = { close() }, modifier = Modifier.testTag("live_ssh_back")) { Text("К серверам") }
    }
}
