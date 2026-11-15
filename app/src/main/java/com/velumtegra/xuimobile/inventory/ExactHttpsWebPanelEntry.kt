package com.velumtegra.xuimobile.inventory

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.net.URI

/**
 * Narrow, explicit direct browser target. No host, port, scheme or base path is guessed.
 * Username/password, query tokens and URI fragments are forbidden; user credentials are
 * never transported via an Android Intent or stored as a remembered Web Panel address.
 * No HTTP downgrade, implicit VPN/SSH tunneling, auto-login or hidden network retry.
 */
internal fun exactHttpsPanelUrl(candidate: String): String? {
    if (candidate.isBlank() || candidate != candidate.trim() ||
        candidate.any { it.isWhitespace() || Character.isISOControl(it) || it == '\\' }
    ) return null
    val parsed = try { URI(candidate) } catch (_: java.net.URISyntaxException) { return null }
    if (!parsed.isAbsolute || !parsed.scheme.equals("https", ignoreCase = true) ||
        parsed.host.isNullOrBlank() || parsed.rawUserInfo != null ||
        parsed.rawQuery != null || parsed.rawFragment != null ||
        parsed.rawAuthority?.contains('@') == true ||
        parsed.port > 65535 || parsed.port == 0 || parsed.port < -1
    ) return null
    val rawPath = parsed.rawPath.orEmpty()
    if (rawPath.split('/').any { it == "." || it == ".." } ||
        rawPath.contains("%2f", ignoreCase = true) || rawPath.contains("%5c", ignoreCase = true)
    ) return null
    return candidate
}

/** Direct HTTPS browser entry is a temporary honest route to the full existing Web Panel UI.
 * It does NOT imply that SSH tunnel / native Web Panel authentication is wired up. */
@Composable
internal fun ExactHttpsWebPanelEntry(onOpenInApp: (String) -> Unit) {
    val context = LocalContext.current
    var address by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    val validated = exactHttpsPanelUrl(address)
    Card(modifier = Modifier.fillMaxWidth().testTag("webpanel_exact_https_card")) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Открыть существующую веб-панель", fontWeight = FontWeight.Bold)
            Text(
                "Укажите полный HTTPS-адрес, включая реальный порт и секретный путь, " +
                    "если они настроены. Адрес не определяется по SSH автоматически.",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedTextField(
                value = address,
                onValueChange = { address = it; message = "" },
                label = { Text("HTTPS-адрес панели") },
                placeholder = { Text("https://panel.example.com:12345/your-path/") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("webpanel_exact_https_input"),
            )
            Button(
                onClick = {
                    // Revalidate inside onClick; never attempt to open stale or malformed data.
                    val url = exactHttpsPanelUrl(address)
                    if (url == null) {
                        message = "Нужен полный корректный HTTPS-адрес без логина, пароля и параметров URL."
                    } else {
                        val opened = runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }
                        message = if (opened.isSuccess) {
                            "Адрес передан браузеру. Вход в панель выполняется только в браузере."
                        } else {
                            "Не удалось открыть браузер. Проверьте наличие приложения для HTTPS-ссылок."
                        }
                    }
                },
                enabled = validated != null,
                modifier = Modifier.fillMaxWidth().testTag("webpanel_exact_https_open"),
            ) { Text("Открыть веб-панель в браузере") }
            Button(
                onClick = {
                    // The same strict address validator is applied at the moment of opening.
                    val url = exactHttpsPanelUrl(address)
                    if (url == null) {
                        message = "Нужен полный корректный HTTPS-адрес панели."
                    } else {
                        onOpenInApp(url)
                    }
                },
                enabled = validated != null,
                modifier = Modifier.fillMaxWidth().testTag("webpanel_exact_https_open_in_app"),
            ) { Text("Открыть в приложении") }
            if (message.isNotBlank()) {
                Text(message, modifier = Modifier.testTag("webpanel_exact_https_message"),
                    style = MaterialTheme.typography.bodySmall)
            }
            Text(
                "Откроется реальная веб-панель с её собственными функциями. " +
                    "Можно войти через обычный браузер или через встроенный HTTPS-просмотр. " +
                    "Это НЕ подключение через SSH-туннель или перенос сохранённой авторизации. " +
                    "Логин и пароль вводятся только на странице самой 3x-ui.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
