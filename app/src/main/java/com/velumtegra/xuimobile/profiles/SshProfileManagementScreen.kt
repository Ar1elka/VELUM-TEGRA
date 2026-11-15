package com.velumtegra.xuimobile.profiles

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
import androidx.compose.material3.OutlinedTextField
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
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Local profile maintenance. Never opens a socket or accepts a new host key automatically. */
@Composable
fun SshProfileManagementScreen(
    serverId: String, serverName: String,
    readinessPort: SshReadinessPort,
    profiles: SshProfileManagementPort,
    onAddAccess: () -> Unit,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val sweeper = androidx.compose.ui.platform.LocalContext.current.applicationContext
        as? com.velumtegra.xuimobile.VelumTegraApplication
    val lifecycleOwner = LocalLifecycleOwner.current
    var generation by remember(serverId, readinessPort, profiles) { mutableStateOf(0L) }
    var entries by remember(serverId, readinessPort) { mutableStateOf<LocalSshAccessList?>(null) }
    var selected by remember(serverId, profiles) { mutableStateOf<SshProfileReview?>(null) }
    var typed by remember(serverId, profiles) { mutableStateOf("") }
    var consent by remember(serverId, profiles) { mutableStateOf(false) }
    var busy by remember(serverId, profiles) { mutableStateOf(false) }
    var notice by remember(serverId, profiles) { mutableStateOf("") }
    var job by remember(serverId, profiles) { mutableStateOf<Job?>(null) }

    fun revoke() {
        ++generation
        job?.cancel()
        job = null
        selected = null
        typed = ""
        consent = false
        busy = false
    }
    fun refresh() {
        revoke()
        notice = ""
        entries = null
        val request = ++generation
        job = scope.launch {
            val read = try { readinessPort.listForExactServer(serverId) }
                catch (cancel: CancellationException) { throw cancel }
                catch (_: Exception) { LocalSshAccessList.Unavailable("Не удалось прочитать SSH-профили.") }
            if (request == generation && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) entries = read
        }
    }
    DisposableEffect(lifecycleOwner, serverId, readinessPort, profiles) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> refresh()
                Lifecycle.Event.ON_STOP -> { revoke(); entries = null }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        if (lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) refresh()
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer); revoke() }
    }
    fun close() { revoke(); onBack() }
    BackHandler { close() }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp)
            .testTag("ssh_profiles_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("SSH-профили", style = MaterialTheme.typography.titleLarge)
        Text("VPS: $serverName")
        Text("Смена реквизитов: добавьте новый профиль, проверьте подключение, затем удалите старый. " +
            "Закреплённый ключ не переносится на другой адрес автоматически.")
        Button(onClick = { revoke(); onAddAccess() }, enabled = !busy,
            modifier = Modifier.testTag("ssh_profiles_add")) { Text("Добавить новый SSH-профиль") }
        OutlinedButton(onClick = { refresh() }, enabled = !busy,
            modifier = Modifier.testTag("ssh_profiles_refresh")) { Text("Обновить профили") }
        if (notice.isNotEmpty()) Text(notice, modifier = Modifier.testTag("ssh_profiles_notice"))
        when (val state = entries) {
            null -> Text("Читаем локальные профили…")
            is LocalSshAccessList.Unavailable -> Text(state.reason, color = MaterialTheme.colorScheme.error)
            is LocalSshAccessList.Available -> {
                if (state.items.isEmpty()) Text("SSH-профилей пока нет.")
                state.items.forEach { item ->
                    OutlinedButton(
                        enabled = !busy,
                        onClick = {
                            revoke()
                            notice = ""
                            val request = ++generation
                            job = scope.launch {
                                val read = try { profiles.reviewExact(serverId, item.accessId) }
                                    catch (cancel: CancellationException) { throw cancel }
                                    catch (_: Exception) { SshProfileReviewResult.Blocked("Не удалось проверить профиль.") }
                                if (request == generation && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                    when (read) {
                                        is SshProfileReviewResult.Ready -> {
                                            if (read.review.metadata == item.copy(authLabel = read.review.metadata.authLabel) && read.review.serverId == serverId) {
                                                selected = read.review
                                            } else notice = "Профиль изменился, обновите список."
                                        }
                                        is SshProfileReviewResult.Blocked -> notice = read.message
                                    }
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth().testTag("ssh_profiles_select_${item.accessId}"),
                    ) { Text("${item.username}@${item.host}:${item.port} · ${item.authLabel}") }
                }
            }
        }
        val profile = selected
        if (profile != null) {
            val summary = profile.metadata
            Text("Выбран: ${LiveSshConnectionPolicy.exactTarget(summary)}")
            Text("Сохранённый SHA-256 ключа сервера: ${summary.savedFingerprint}")
            Text("Связи X-UI: ${profile.managementLinks} · SSH-туннели WebPanel: ${profile.webPanelTunnelLinks}",
                modifier = Modifier.testTag("ssh_profiles_links"))
            if (profile.hasLinks) {
                Text("Удаление заблокировано: сначала разберите связи с X-UI или веб-панелями.")
            } else {
                Text("Удаляется только локальная запись SSH-доступа. Секрет останется зашифрованным до " +
                    "отдельной безопасной очистки неиспользуемых секретов. VPS не изменится.")
                OutlinedTextField(
                    value = typed, onValueChange = { typed = it; consent = false; notice = "" },
                    label = { Text("Повторите user@host:port") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("ssh_profiles_target"), enabled = !busy,
                )
                Row {
                    Checkbox(checked = consent, onCheckedChange = { consent = it }, enabled = !busy,
                        modifier = Modifier.testTag("ssh_profiles_consent"))
                    Text("Подтверждаю удаление именно этого локального SSH-профиля.")
                }
                Button(
                    enabled = !busy && consent && typed == LiveSshConnectionPolicy.exactTarget(summary),
                    modifier = Modifier.testTag("ssh_profiles_delete"),
                    onClick = {
                        busy = true
                        val request = ++generation
                        val confirmedTarget = typed
                        job = scope.launch {
                            val result = try {
                                profiles.deleteUnused(serverId, summary.accessId, profile, confirmedTarget, true)
                            } catch (cancel: CancellationException) { throw cancel }
                                catch (_: Exception) { SshProfileDeleteResult.Blocked("Удаление не удалось.") }
                            if (request == generation && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                busy = false
                                when (result) {
                                    SshProfileDeleteResult.Removed -> {
                                        refresh(); notice = "Локальный SSH-профиль удалён. VPS не затронут."
                                        // The profile's encrypted secret is now unreferenced (unless a migrated profile shares it).
                                        sweeper?.sweepLocalStorageInBackground()
                                    }
                                    is SshProfileDeleteResult.Blocked -> { revoke(); notice = result.message }
                                }
                            }
                        }
                    },
                ) { Text(if (busy) "Удаляем…" else "Удалить локальный SSH-профиль") }
            }
        }
        OutlinedButton(onClick = { close() }, modifier = Modifier.testTag("ssh_profiles_back")) {
            Text("К серверам")
        }
    }
}
