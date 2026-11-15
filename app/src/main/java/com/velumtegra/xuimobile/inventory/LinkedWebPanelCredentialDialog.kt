package com.velumtegra.xuimobile.inventory

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.TextButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import com.velumtegra.xuimobile.ui.RevealablePasswordField
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.ServerAccess

/** Explicit local-only Web Panel credential enrollment; no network activity on save. */
@Composable
internal fun LinkedWebPanelCredentialDialog(
    serverId: String,
    installationId: String,
    port: LinkedWebPanelCredentialPort,
    sshAccesses: ServerAccessRepository,
    onDismiss: () -> Unit,
    onSaved: () -> Unit,
) {
    var host by remember(serverId, installationId) { mutableStateOf("") }
    var username by remember(serverId, installationId) { mutableStateOf("") }
    // Never rememberSaveable: Android should not persist plaintext password across restoration.
    var password by remember(serverId, installationId) { mutableStateOf("") }
    var approved by remember(serverId, installationId) { mutableStateOf(false) }
    var busy by remember(serverId, installationId) { mutableStateOf(false) }
    var notice by remember(serverId, installationId) { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    var throughSsh by remember(serverId, installationId) { mutableStateOf(false) }
    var selectedSshId by remember(serverId, installationId) { mutableStateOf<String?>(null) }
    var sshProfiles by remember(serverId) { mutableStateOf<List<ServerAccess>>(emptyList()) }
    var sshLoadError by remember(serverId) { mutableStateOf(false) }
    LaunchedEffect(serverId, sshAccesses) {
        when (val result = withContext(Dispatchers.IO) { sshAccesses.listForServer(ServerId(serverId)) }) {
            is RepositoryResult.Success -> {
                sshProfiles = result.value.filter { it.serverId.value == serverId }
                selectedSshId = sshProfiles.singleOrNull()?.id?.value
                sshLoadError = false
            }
            else -> { sshProfiles = emptyList(); sshLoadError = true }
        }
    }
    AlertDialog(
        onDismissRequest = { if (!busy) { password = ""; onDismiss() } },
        title = { Text("Сохранить вход в панель") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                androidx.compose.foundation.layout.Row {
                    Checkbox(throughSsh, { throughSsh = it; approved = false; notice = "" },
                        enabled = !busy, modifier = Modifier.testTag("webpanel_linked_ssh_mode"))
                    Text("Через сохранённый SSH-профиль")
                }
                if (throughSsh) {
                    if (sshLoadError) Text("SSH-профили не удалось прочитать. Проверьте локальную базу.")
                    else if (sshProfiles.isEmpty()) Text("Нет SSH-профилей этого сервера. Добавьте SSH-доступ во вкладке «Серверы».")
                    else {
                        if (sshProfiles.size > 1) Text("Выберите SSH-профиль")
                        sshProfiles.forEach { profile ->
                            TextButton(
                                onClick = { selectedSshId = profile.id.value; approved = false; notice = "" },
                                enabled = !busy,
                                modifier = Modifier.fillMaxWidth().testTag("webpanel_ssh_access_${profile.id.value}"),
                            ) { Text((if (selectedSshId == profile.id.value) "✓ " else "") +
                                "${profile.username}@${profile.endpoint.host}:${profile.endpoint.port}") }
                        }
                    }
                } else {
                    OutlinedTextField(host, { host = it; approved = false; notice = "" },
                        label = { Text("Точный HTTPS-хост без порта") }, singleLine = true,
                        enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("webpanel_linked_credential_host"))
                }
                OutlinedTextField(username, { username = it; approved = false; notice = "" },
                    label = { Text("Логин панели") }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("webpanel_linked_credential_username"))
                RevealablePasswordField(password, { password = it; approved = false; notice = "" },
                    label = { Text("Пароль панели") },
                    enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("webpanel_linked_credential_password"))
                androidx.compose.foundation.layout.Row {
                    Checkbox(approved, { approved = it }, enabled = !busy,
                        modifier = Modifier.testTag("webpanel_linked_credential_consent"))
                    Text("Сохранить вход на этом телефоне")
                }
                if (notice.isNotBlank()) Text(notice, modifier = Modifier.testTag("webpanel_linked_credential_notice"))
            }
        },
        confirmButton = {
            Button(onClick = {
                if (busy || !approved || password.isEmpty()) return@Button
                val bytes = password.toByteArray(Charsets.UTF_8)
                password = ""
                busy = true
                scope.launch {
                    try {
                        val result = if (throughSsh) {
                            port.saveViaSsh(serverId, installationId, requireNotNull(selectedSshId),
                                username, bytes, approved)
                        } else {
                            port.save(serverId, installationId, host, username, bytes, approved)
                        }
                        when (result) {
                            is LinkedPanelCredentialResult.Saved -> {
                                notice = "Доступ сохранён локально. Авторизация на VPS не проверялась."
                                onSaved()
                            }
                            is LinkedPanelCredentialResult.Rejected -> notice = result.reason
                        }
                    } catch (cancel: CancellationException) { throw cancel }
                    catch (_: Exception) { notice = "Сохранение отклонено. Результат неизвестен; обновите список перед повтором." }
                    finally { bytes.fill(0); busy = false }
                }
            }, enabled = !busy && approved &&
                (if (throughSsh) selectedSshId != null && !sshLoadError else host.isNotBlank()) &&
                username.isNotBlank() && password.isNotEmpty(),
                modifier = Modifier.testTag("webpanel_linked_credential_save")) { Text(if (busy) "Сохраняем…" else "Сохранить локально") }
        },
        dismissButton = {
            OutlinedButton(onClick = { password = ""; onDismiss() }, enabled = !busy,
                modifier = Modifier.testTag("webpanel_linked_credential_cancel")) { Text("Отмена") }
        },
    )
}
