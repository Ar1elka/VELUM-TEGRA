package com.velumtegra.xuimobile.management

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.velumtegra.xuimobile.core.ssh.XuiPanelExposure
import com.velumtegra.xuimobile.ui.RevealablePasswordField
import kotlinx.coroutines.launch

private enum class PanelAccessConfirm { CLOSE, OPEN, RESET }

/** «Доступ к панели»: shows whether the panel is open or closed and offers the three situations' actions. */
@Composable
internal fun ManagementPanelAccessDialog(
    port: ManagementPanelAccessPort,
    serverId: String,
    installationId: String,
    accessId: String,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var overview by remember { mutableStateOf<PanelAccessOverview?>(null) }
    var busy by remember { mutableStateOf(true) }
    var message by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<PanelAccessConfirm?>(null) }
    var resetTwoFactor by remember { mutableStateOf(false) }
    var manual by remember { mutableStateOf(false) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var newSignIn by remember { mutableStateOf<PanelAccessOutcome.NewSignIn?>(null) }

    fun apply(outcome: PanelAccessOutcome) {
        when (outcome) {
            is PanelAccessOutcome.Done -> {
                outcome.overview?.let { overview = it }
                message = outcome.message.ifBlank { null }; error = null
            }
            is PanelAccessOutcome.NewSignIn -> {
                outcome.overview?.let { overview = it }
                newSignIn = outcome; message = outcome.message; error = null
            }
            is PanelAccessOutcome.Failed -> error = outcome.reason
        }
    }
    fun run(refresh: Boolean = true, block: suspend () -> PanelAccessOutcome) {
        if (busy && overview != null) return
        busy = true
        scope.launch {
            try {
                apply(block())
                if (refresh) {
                    val now = port.inspect(serverId, installationId, accessId)
                    (now as? PanelAccessOutcome.Done)?.overview?.let { overview = it }
                }
            } finally { busy = false }
        }
    }
    LaunchedEffect(serverId, installationId, accessId) {
        try { apply(port.inspect(serverId, installationId, accessId)) } finally { busy = false }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) { password = ""; onDismiss() } },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text("Доступ к панели") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                val o = overview
                if (o == null) {
                    if (busy) Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        CircularProgressIndicator(); Text("Читаем настройки панели по SSH…")
                    }
                } else {
                    Text(ManagementPanelAccessPort.exposureLabel(o.server), fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.testTag("panel_access_exposure"))
                    Text(
                        when {
                            o.tunnelProfiles > 0 -> "✓ Вход через SSH-туннель сохранён на телефоне."
                            o.directProfiles > 0 -> "Сохранён только вход напрямую через интернет."
                            else -> "Вход в панель на телефоне ещё не сохранён."
                        },
                        modifier = Modifier.testTag("panel_access_profiles"),
                    )
                }
                newSignIn?.let { SignInCard(it) }
                message?.let { Text(it, modifier = Modifier.testTag("panel_access_message")) }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("panel_access_error")) }
                if (busy && o != null) CircularProgressIndicator()

                if (o != null && !busy) {
                    if (o.tunnelProfiles == 0) {
                        if (o.server.installResultPresent && !manual) {
                            Button(onClick = { run { port.saveTunnelFromInstaller(serverId, installationId, accessId) } },
                                modifier = Modifier.fillMaxWidth().testTag("panel_access_save_auto")) {
                                Text("Сохранить вход через SSH (данные установщика)")
                            }
                            TextButton(onClick = { manual = true }) { Text("Ввести логин и пароль вручную") }
                        } else {
                            Text("Логин и пароль панели", style = MaterialTheme.typography.titleSmall)
                            OutlinedTextField(username, { username = it }, label = { Text("Логин") }, singleLine = true,
                                modifier = Modifier.fillMaxWidth().testTag("panel_access_username"))
                            RevealablePasswordField(password, { password = it }, label = { Text("Пароль") },
                                modifier = Modifier.fillMaxWidth().testTag("panel_access_password"))
                            Button(
                                onClick = {
                                    val bytes = password.toByteArray(Charsets.UTF_8); password = ""
                                    val user = username.trim()
                                    run { port.saveTunnel(serverId, installationId, accessId, user, bytes) }
                                },
                                enabled = username.isNotBlank() && password.isNotEmpty(),
                                modifier = Modifier.fillMaxWidth().testTag("panel_access_save_manual"),
                            ) { Text("Сохранить вход через SSH") }
                            Text("Не помните пароль? Сбросьте его кнопкой ниже.", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    when (o.server.exposure) {
                        XuiPanelExposure.LOOPBACK -> OutlinedButton(onClick = { confirm = PanelAccessConfirm.OPEN },
                            modifier = Modifier.fillMaxWidth().testTag("panel_access_open")) { Text("Открыть панель в интернет") }
                        else -> Button(onClick = { confirm = PanelAccessConfirm.CLOSE },
                            modifier = Modifier.fillMaxWidth().testTag("panel_access_close")) { Text("Закрыть панель от интернета") }
                    }
                    OutlinedButton(onClick = { confirm = PanelAccessConfirm.RESET },
                        modifier = Modifier.fillMaxWidth().testTag("panel_access_reset")) { Text("Сбросить логин и пароль") }
                }
            }
        },
        confirmButton = { TextButton(onClick = { password = ""; onDismiss() }, enabled = !busy) { Text("Готово") } },
    )

    when (confirm) {
        PanelAccessConfirm.CLOSE -> ConfirmDialog(
            title = "Закрыть панель от интернета?",
            body = "Панель будет слушать только 127.0.0.1 и откроется через SSH-туннель в приложении. " +
                "Из браузера по адресу сервера она станет недоступна. x-ui перезапустится — VPN-клиенты переподключатся за пару секунд.",
            action = "Закрыть",
            onDismiss = { confirm = null },
        ) { confirm = null; run { port.closeToInternet(serverId, installationId, accessId) } }
        PanelAccessConfirm.OPEN -> ConfirmDialog(
            title = "Открыть панель в интернет?",
            body = "Панель снова будет доступна по адресу сервера всем, кто знает путь. Защиту дадут только логин, пароль и сертификат. " +
                "x-ui перезапустится.",
            action = "Открыть",
            onDismiss = { confirm = null },
        ) { confirm = null; run { port.openToInternet(serverId, installationId, accessId) } }
        PanelAccessConfirm.RESET -> AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("Сбросить логин и пароль панели?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Приложение задаст новый случайный логин и стойкий пароль и сразу сохранит их на телефоне. " +
                        "Протоколы, клиенты и подписки не меняются. Все открытые в браузерах сеансы панели завершатся, x-ui перезапустится.")
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(resetTwoFactor, { resetTwoFactor = it }, modifier = Modifier.testTag("panel_access_reset_2fa"))
                        Text("Также выключить двухфакторную защиту")
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    confirm = null
                    val twoFactor = resetTwoFactor
                    run { port.resetSignIn(serverId, installationId, accessId, twoFactor) }
                }, modifier = Modifier.testTag("panel_access_reset_confirm")) { Text("Сбросить") }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Отмена") } },
        )
        null -> Unit
    }
}

@Composable
private fun ConfirmDialog(title: String, body: String, action: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = { Button(onClick = onConfirm, modifier = Modifier.testTag("panel_access_confirm")) { Text(action) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun SignInCard(signIn: PanelAccessOutcome.NewSignIn) {
    val context = LocalContext.current
    var reveal by remember { mutableStateOf(false) }
    fun copy(label: String, value: String, sensitive: Boolean) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, value)
        if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) clip.description.extras = PersistableBundle().apply {
            putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
        }
        clipboard.setPrimaryClip(clip)
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Новый логин", style = MaterialTheme.typography.labelMedium)
        Text(signIn.username, fontFamily = FontFamily.Monospace)
        Text("Новый пароль", style = MaterialTheme.typography.labelMedium)
        Text(if (reveal) signIn.password else "•".repeat(16), fontFamily = FontFamily.Monospace)
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            TextButton(onClick = { reveal = !reveal }) { Text(if (reveal) "Скрыть" else "Показать") }
            TextButton(onClick = { copy("Логин", signIn.username, false) }) { Text("Логин") }
            TextButton(onClick = { copy("Пароль", signIn.password, true) }) { Text("Пароль") }
        }
    }
}
