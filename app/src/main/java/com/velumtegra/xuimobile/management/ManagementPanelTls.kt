package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.XuiPanelTlsResult
import com.velumtegra.xuimobile.core.ssh.XuiReadOnlyPanelTlsProbe
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class ManagementPanelTlsReader(
    private val local: ManagementRestartLocalPort,
    private val factory: SshConnectionFactory,
) {
    suspend fun read(serverId: String, installationId: String, accessId: String): XuiPanelTlsResult =
        withContext(Dispatchers.IO) {
            try {
                val review = (local.readExact(serverId, installationId, accessId) as? ManagementRestartLocalReview.Ready)?.review
                    ?: return@withContext XuiPanelTlsResult.Unavailable
                if (!review.matches(serverId, installationId, accessId)) return@withContext XuiPanelTlsResult.Unavailable
                val owner = SessionOwner.Management(review.installation.id, review.access.id)
                val connection = factory.connect(review.access, owner) as? SshConnectResult.Connected
                    ?: return@withContext XuiPanelTlsResult.Unavailable
                connection.handle.use { session ->
                    val fresh = (local.readExact(serverId, installationId, accessId) as? ManagementRestartLocalReview.Ready)?.review
                    if (fresh != review || session.binding.owner != owner || session.binding.serverAccessId != review.access.id) {
                        XuiPanelTlsResult.Unavailable
                    } else XuiReadOnlyPanelTlsProbe.read(session, review.installation.identity.databasePath)
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                XuiPanelTlsResult.Unavailable
            }
        }
}

@Composable
internal fun ManagementPanelTlsDialog(read: suspend () -> XuiPanelTlsResult, onDismiss: () -> Unit) {
    var requested by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<XuiPanelTlsResult?>(null) }
    LaunchedEffect(requested) {
        if (requested) result = read()
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Сертификат TLS панели") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (val observed = result) {
                    null -> if (requested) CircularProgressIndicator() else Text("Прочитать срок и отпечаток сертификата по SSH?")
                    XuiPanelTlsResult.NotConfigured -> Text("У панели не задан файл TLS-сертификата.")
                    XuiPanelTlsResult.Unavailable -> Text("Не удалось прочитать сертификат выбранной установки.")
                    is XuiPanelTlsResult.Observed -> {
                        val date = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm z").withZone(ZoneId.systemDefault())
                        val label = if (observed.expiresAt.isAfter(Instant.now())) "Действует до" else "Срок истёк"
                        Text("$label · ${date.format(observed.expiresAt)}")
                        Text("SHA-256")
                        Text(observed.fingerprint)
                    }
                }
            }
        },
        confirmButton = {
            if (!requested) Button(onClick = { requested = true }) { Text("Проверить") }
            else TextButton(onClick = onDismiss) { Text("Закрыть") }
        },
        dismissButton = {
            if (!requested) TextButton(onClick = onDismiss) { Text("Отмена") }
        },
    )
}
