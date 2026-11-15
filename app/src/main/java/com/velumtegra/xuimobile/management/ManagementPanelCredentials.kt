package com.velumtegra.xuimobile.management

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.XuiInstallResultProbe
import com.velumtegra.xuimobile.core.ssh.XuiInstallResultRead
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** One read-only SSH session that reads the installer's sign-in record for the exact selected installation. */
internal class ManagementPanelCredentialsReader(
    private val local: ManagementRestartLocalPort,
    private val factory: SshConnectionFactory,
) {
    suspend fun read(serverId: String, installationId: String, accessId: String): XuiInstallResultRead =
        withContext(Dispatchers.IO) {
            try {
                val review = (local.readExact(serverId, installationId, accessId) as? ManagementRestartLocalReview.Ready)?.review
                    ?: return@withContext XuiInstallResultRead.Unavailable
                if (!review.matches(serverId, installationId, accessId)) return@withContext XuiInstallResultRead.Unavailable
                val owner = SessionOwner.Management(review.installation.id, review.access.id)
                val connection = factory.connect(review.access, owner) as? SshConnectResult.Connected
                    ?: return@withContext XuiInstallResultRead.Unavailable
                connection.handle.use { session ->
                    val fresh = (local.readExact(serverId, installationId, accessId) as? ManagementRestartLocalReview.Ready)?.review
                    if (fresh != review || session.binding.owner != owner || session.binding.serverAccessId != review.access.id) {
                        XuiInstallResultRead.Unavailable
                    } else XuiInstallResultProbe.read(session)
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                XuiInstallResultRead.Unavailable
            }
        }
}

@Composable
internal fun ManagementPanelCredentialsDialog(
    serverHost: String,
    read: suspend () -> XuiInstallResultRead,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    var requested by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<XuiInstallResultRead?>(null) }
    var reveal by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf<String?>(null) }
    // The password is on screen: keep it out of screenshots, screen recording and the recents thumbnail.
    DisposableEffect(context) {
        val window = (context as? Activity)?.window
        val flag = WindowManager.LayoutParams.FLAG_SECURE
        val alreadySecure = window != null && (window.attributes.flags and flag) != 0
        if (!alreadySecure) window?.addFlags(flag)
        onDispose { if (!alreadySecure) window?.clearFlags(flag) }
    }
    LaunchedEffect(requested) {
        if (requested) result = read()
    }
    fun copy(label: String, value: String, sensitive: Boolean) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, value)
        if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE
                    else "android.content.extra.IS_SENSITIVE", true)
            }
        }
        clipboard.setPrimaryClip(clip)
        copied = label
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        // The dialog is its own window: the activity flag above does not cover it.
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text("Вход в панель 3x-ui") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (val observed = result) {
                    null -> if (requested) CircularProgressIndicator() else Text(
                        "Прочитать по SSH логин и пароль, которые установщик 3x-ui сохранил на сервере? " +
                            "Настройки VPS не меняются.",
                    )
                    XuiInstallResultRead.NotRecorded -> Text(
                        "На сервере нет записи установщика. Панель ставилась не через приложение или вручную. " +
                            "Задайте новый логин и пароль через «Все команды x-ui».",
                    )
                    XuiInstallResultRead.Unavailable -> Text("Не удалось прочитать данные входа с сервера.")
                    is XuiInstallResultRead.Observed -> {
                        val c = observed.credentials
                        Text("Логин", style = MaterialTheme.typography.labelMedium)
                        Text(c.username, fontFamily = FontFamily.Monospace,
                            modifier = Modifier.testTag("management_credentials_username"))
                        Text("Пароль", style = MaterialTheme.typography.labelMedium)
                        Text(if (reveal) c.password else "•".repeat(c.password.length.coerceIn(6, 16)),
                            fontFamily = FontFamily.Monospace)
                        Text("Порт и путь панели", style = MaterialTheme.typography.labelMedium)
                        Text(c.panelPort.toString() + " · " + c.webBasePath, fontFamily = FontFamily.Monospace)
                        Text("Адрес: http://$serverHost:${c.panelPort}${c.webBasePath}",
                            style = MaterialTheme.typography.bodySmall)
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            TextButton(onClick = { reveal = !reveal }) { Text(if (reveal) "Скрыть" else "Показать") }
                            TextButton(onClick = { copy("Логин", c.username, sensitive = false) }) { Text("Копировать логин") }
                        }
                        TextButton(onClick = { copy("Пароль", c.password, sensitive = true) }) { Text("Копировать пароль") }
                        copied?.let { Text("$it скопирован.", style = MaterialTheme.typography.bodySmall) }
                        Text(
                            "Это данные, заданные при установке. Если их меняли в панели, здесь будут старые.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        },
        confirmButton = {
            if (!requested) Button(onClick = { requested = true }, modifier = Modifier.testTag("management_credentials_read")) {
                Text("Прочитать")
            } else TextButton(onClick = onDismiss) { Text("Закрыть") }
        },
        dismissButton = {
            if (!requested) TextButton(onClick = onDismiss) { Text("Отмена") }
        },
    )
}
