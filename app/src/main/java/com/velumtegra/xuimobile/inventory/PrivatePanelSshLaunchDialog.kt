package com.velumtegra.xuimobile.inventory

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.StandaloneWebPanelTargetDetails
import com.velumtegra.xuimobile.core.domain.WebPanelScheme

/** Separate transport chooser; no SSH/panel password is ever displayed or placed in a URL. */
@Composable
internal fun PrivatePanelSshLaunchDialog(
    accessId: String,
    standalone: Boolean = false,
    onDismiss: () -> Unit,
    onConnect: (PrivateWebPanelOpenRequest) -> Unit,
) {
    // HTTPS is the safe initial choice; HTTP remains an explicit, loopback-only option.
    var scheme by remember(accessId, standalone) { mutableStateOf(WebPanelScheme.HTTPS) }
    // Browser endpoint is always the app-owned local SSH forward.
    val host = "127.0.0.1"
    val context = LocalContext.current
    val preferences = remember(context, standalone) {
        if (standalone) context.getSharedPreferences("standalone_panel_targets", Context.MODE_PRIVATE) else null
    }
    val saved = remember(preferences, accessId) {
        preferences?.let { prefs ->
            val remote = prefs.getString("$accessId.host", null).orEmpty()
            val port = prefs.getString("$accessId.port", null).orEmpty()
            val path = prefs.getString("$accessId.path", null).orEmpty()
            if (StandalonePrivatePanelPolicy.targetError(remote, port, path) == null)
                StandaloneWebPanelTargetDetails.SshTunnel(remote, port.toInt(), path)
            else null
        }
    }
    var remoteHost by remember(accessId, standalone) {
        mutableStateOf(saved?.remoteHost ?: if (standalone) "127.0.0.1" else "")
    }
    var panelPort by remember(accessId, standalone) { mutableStateOf(saved?.port?.toString().orEmpty()) }
    var webPath by remember(accessId, standalone) { mutableStateOf(saved?.webBasePath ?: "/") }
    var advanced by remember(accessId, standalone) { mutableStateOf(standalone && saved == null) }
    val manualError = if (standalone) StandalonePrivatePanelPolicy.targetError(remoteHost, panelPort, webPath) else null
    val validHost = manualError == null && runCatching { WebPanelHost(host) }.isSuccess &&
        (remoteHost.isBlank() || remoteHost in setOf("127.0.0.1", "localhost", "[::1]"))
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Открыть панель") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(9.dp),
                modifier = Modifier.verticalScroll(rememberScrollState())) {
                Text("Через сохранённый SSH-профиль")
                Row {
                    RadioButton(selected = scheme == WebPanelScheme.HTTP,
                        onClick = { scheme = WebPanelScheme.HTTP },
                        modifier = Modifier.testTag("private_panel_http"))
                    Text("HTTP")
                }
                Row {
                    RadioButton(selected = scheme == WebPanelScheme.HTTPS,
                        onClick = { scheme = WebPanelScheme.HTTPS },
                        modifier = Modifier.testTag("private_panel_https"))
                    Text("HTTPS")
                }
                if (scheme == WebPanelScheme.HTTP) Text("HTTP защищён SSH-туннелем. У панели нет собственного TLS.")
                OutlinedButton(onClick = { advanced = !advanced }) {
                    Text(if (advanced) "Скрыть адрес панели" else "Настроить адрес панели")
                }
                if (advanced) {
                    OutlinedTextField(
                        value = remoteHost,
                        onValueChange = { remoteHost = it },
                        label = { Text("Хост на VPS") },
                        placeholder = { Text("127.0.0.1") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("private_panel_remote_host"),
                    )
                    if (standalone) {
                        OutlinedTextField(panelPort, { panelPort = it },
                            label = { Text("Порт панели") }, singleLine = true,
                            modifier = Modifier.fillMaxWidth().testTag("manual_panel_port"))
                        OutlinedTextField(webPath, { webPath = it },
                            label = { Text("Веб-путь, начиная с /") }, singleLine = true,
                            modifier = Modifier.fillMaxWidth().testTag("manual_panel_web_path"))
                    }
                }
                if (manualError != null) Text(manualError)
            }
        },
        confirmButton = {
            Button(
                enabled = validHost,
                onClick = {
                    if (validHost) {
                        val target = if (standalone) StandaloneWebPanelTargetDetails.SshTunnel(
                            remoteHost, requireNotNull(panelPort.toIntOrNull()), webPath,
                        ) else null
                        if (target != null && preferences != null) {
                            preferences.edit()
                                .putString("$accessId.host", target.remoteHost)
                                .putString("$accessId.port", target.port.toString())
                                .putString("$accessId.path", target.webBasePath)
                                .apply()
                        }
                        onConnect(PrivateWebPanelOpenRequest(
                            accessId, scheme, host,
                            remoteHostOverride = if (standalone) null else remoteHost.takeIf { it.isNotBlank() },
                            standaloneTarget = target,
                        ))
                    }
                },
                modifier = Modifier.testTag("private_panel_connect"),
            ) { Text("Подключиться") }
        },
        dismissButton = { OutlinedButton(onClick = onDismiss) { Text("Отмена") } },
    )
}
