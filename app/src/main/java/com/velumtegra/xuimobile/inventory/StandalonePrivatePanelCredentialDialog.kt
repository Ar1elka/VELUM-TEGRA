package com.velumtegra.xuimobile.inventory

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
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
import com.velumtegra.xuimobile.ui.RevealablePasswordField
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.ServerAccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Manual access to a private panel when discovery does not recognize a custom 3x-ui path. */
@Composable
internal fun StandalonePrivatePanelCredentialDialog(
    servers: ServerRepository,
    sshAccesses: ServerAccessRepository,
    port: LinkedWebPanelCredentialPort,
    onDismiss: () -> Unit,
    onSaved: () -> Unit,
) {
    var profiles by remember { mutableStateOf<List<ServerAccess>>(emptyList()) }
    var readError by remember { mutableStateOf<String?>(null) }
    var selectedId by remember { mutableStateOf<String?>(null) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmed by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    LaunchedEffect(servers, sshAccesses) {
        withContext(Dispatchers.IO) {
            val found = when (val read = servers.list()) {
                is RepositoryResult.Success -> {
                    val output = mutableListOf<ServerAccess>()
                    for (server in read.value) {
                        val ssh = when (val accessRead = sshAccesses.listForServer(server.value.id)) {
                            is RepositoryResult.Success -> accessRead.value
                            else -> { withContext(Dispatchers.Main) { readError = "Не удалось прочитать SSH-профили." }; return@withContext }
                        }
                        output.addAll(ssh.filter { it.serverId == server.value.id })
                    }
                    output
                }
                else -> { withContext(Dispatchers.Main) { readError = "Не удалось прочитать список серверов." }; return@withContext }
            }
            withContext(Dispatchers.Main) {
                profiles = found
                selectedId = found.singleOrNull()?.id?.value
                readError = null
            }
        }
    }
    AlertDialog(
        onDismissRequest = { if (!busy) { password = ""; onDismiss() } },
        title = { Text("Закрытая панель — добавить вручную") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.verticalScroll(rememberScrollState())) {
                Text("Порт и путь панели понадобятся при первом открытии.")
                if (readError != null) Text(requireNotNull(readError))
                else if (profiles.isEmpty()) Text("Сначала добавь SSH-доступ в разделе «Мои серверы».")
                profiles.forEach { profile ->
                    TextButton(onClick = { selectedId = profile.id.value; confirmed = false },
                        enabled = !busy, modifier = Modifier.fillMaxWidth()
                            .testTag("manual_panel_ssh_${profile.id.value}")) {
                        Text((if (selectedId == profile.id.value) "✓ " else "") +
                            "${profile.username}@${profile.endpoint.host}:${profile.endpoint.port}")
                    }
                }
                OutlinedTextField(username, { username = it; confirmed = false },
                    label = { Text("Логин панели 3x-ui") }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("manual_panel_username"))
                RevealablePasswordField(password, { password = it; confirmed = false },
                    label = { Text("Пароль панели 3x-ui") }, enabled = !busy,
                    modifier = Modifier.fillMaxWidth().testTag("manual_panel_password"))
                Checkbox(confirmed, { confirmed = it }, enabled = !busy,
                    modifier = Modifier.testTag("manual_panel_consent"))
                Text("Сохранить вход на этом телефоне")
                if (notice.isNotBlank()) Text(notice, modifier = Modifier.testTag("manual_panel_notice"))
            }
        },
        confirmButton = {
            Button(onClick = {
                val id = selectedId ?: return@Button
                if (busy || !confirmed) return@Button
                val bytes = password.toByteArray(Charsets.UTF_8)
                password = ""
                busy = true
                scope.launch {
                    try {
                        when (val result = port.saveStandaloneViaSsh(id, username, bytes, confirmed)) {
                            is LinkedPanelCredentialResult.Saved -> onSaved()
                            is LinkedPanelCredentialResult.Rejected -> notice = result.reason
                        }
                    } catch (cancel: CancellationException) { throw cancel }
                    catch (_: Exception) { notice = "Сохранение не подтверждено. Обнови список." }
                    finally { bytes.fill(0); busy = false }
                }
            }, enabled = !busy && readError == null && selectedId != null &&
                StandalonePrivatePanelPolicy.credentialError(selectedId.orEmpty(), username,
                    password.length, confirmed) == null,
                modifier = Modifier.testTag("manual_panel_save")) { Text("Сохранить") }
        },
        dismissButton = { OutlinedButton(onClick = { password = ""; onDismiss() },
            enabled = !busy) { Text("Отмена") } },
    )
}
