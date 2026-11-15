package com.velumtegra.xuimobile.enrollment

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import com.velumtegra.xuimobile.ui.RevealablePasswordField
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Enrollment: optional explicit host-key observation (no auth), then exact local save only. */
@Composable
fun ServerEnrollmentScreen(
    serverId: String?,
    serverName: String?,
    port: ServerEnrollmentPort,
    onBack: () -> Unit,
    onSaved: () -> Unit,
    // Test-only seam: fixture delivers fake in-memory bytes without opening Android's document UI.
    // Production always uses OpenDocument; the returned buffer is owned and wiped by this screen.
    privateKeyPickerOverride: (((ByteArray) -> Unit) -> Unit)? = null,
    hostKeyDiscoveryPort: ServerHostKeyDiscoveryPort? = null,
    onServerCreated: ((String, String) -> Unit)? = null,
) {
    val addingAccess = serverId != null
    var name by remember(serverId) { mutableStateOf("") }
    var host by remember(serverId) { mutableStateOf("") }
    var sshPort by remember(serverId) { mutableStateOf("22") }
    var username by remember(serverId) { mutableStateOf("") }
    var fingerprint by remember(serverId) { mutableStateOf("") }
    var discoveredIdentity by remember(serverId) { mutableStateOf<String?>(null) }
    var discoveredAlgorithm by remember(serverId) { mutableStateOf<String?>(null) }
    // Never saved/restored across process death. Never log, print or put in nav state.
    var password by remember(serverId) { mutableStateOf("") }
    var keyPassphrase by remember(serverId) { mutableStateOf("") }
    var usePrivateKey by remember(serverId) { mutableStateOf(false) }
    val selectedPrivateKey = remember(serverId) { TransientPrivateKeySelection() }
    var keySelected by remember(serverId) { mutableStateOf(false) }
    DisposableEffect(selectedPrivateKey) { onDispose { selectedPrivateKey.close() } }
    var verified by remember(serverId) { mutableStateOf(false) }
    var busy by remember(serverId) { mutableStateOf(false) }
    var error by remember(serverId) { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    fun acceptKey(bytes: ByteArray) {
        val failure = EnrollmentInputPolicy.validatePrivateKeyDocument(bytes)
        if (failure != null) {
            bytes.fill(0)
            selectedPrivateKey.clear()
            keySelected = false
            error = failure
        } else {
            // Ownership of bytes transfers to a zero-on-dispose buffer; never String/URI state.
            selectedPrivateKey.replace(bytes)
            keySelected = true
            verified = false
            error = null
        }
    }

    val keyPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !busy) {
            busy = true
            scope.launch {
                try {
                    val imported = withContext(Dispatchers.IO) {
                        context.contentResolver.openInputStream(uri)?.use {
                            BoundedPrivateKeyDocumentReader.read(it)
                        }
                    }
                    if (imported == null) {
                        selectedPrivateKey.clear()
                        keySelected = false
                        error = "Файл пуст, недоступен или превышает 1 МиБ."
                    } else {
                        acceptKey(imported)
                    }
                } catch (cancel: kotlinx.coroutines.CancellationException) {
                    throw cancel
                } catch (_: Exception) {
                    selectedPrivateKey.clear()
                    keySelected = false
                    error = "Не удалось прочитать выбранный SSH-ключ."
                } finally {
                    busy = false
                }
            }
        }
    }

    BackHandler(enabled = true) { if (!busy) onBack() }

    Column(
        modifier = Modifier.fillMaxSize().testTag("server_enrollment_root")
            .verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            if (addingAccess) "Шаг 2/2 · SSH-доступ" else "Шаг 1/2 · Добавить сервер",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
        if (addingAccess) {
            Text("Точный сервер: ${serverName.orEmpty()} (ID: $serverId)", modifier = Modifier.testTag("enrollment_exact_target"))
            Text("Получите публичный SSH host key по сети, затем обязательно сверьте его SHA-256 с независимым доверенным источником (например, консолью VPS-провайдера). Получение ключа НЕ означает доверие серверу.")
            OutlinedTextField(
                value = host, onValueChange = {
                    host = it; fingerprint = ""; discoveredIdentity = null; discoveredAlgorithm = null
                    verified = false; error = null
                },
                label = { Text("IP или домен сервера") },
                modifier = Modifier.fillMaxWidth().testTag("enrollment_host"),
                singleLine = true, enabled = !busy,
            )
            OutlinedTextField(
                value = sshPort, onValueChange = {
                    sshPort = it; fingerprint = ""; discoveredIdentity = null; discoveredAlgorithm = null
                    verified = false; error = null
                },
                label = { Text("SSH-порт") },
                modifier = Modifier.fillMaxWidth().testTag("enrollment_port"),
                singleLine = true, enabled = !busy,
            )
            OutlinedTextField(
                value = username, onValueChange = { username = it; verified = false; error = null },
                label = { Text("SSH-пользователь") },
                modifier = Modifier.fillMaxWidth().testTag("enrollment_username"),
                singleLine = true, enabled = !busy,
            )
            OutlinedButton(
                onClick = {
                    if (busy || hostKeyDiscoveryPort == null) return@OutlinedButton
                    val invalid = EnrollmentInputPolicy.validateHostAndPort(host, sshPort)
                    if (invalid != null) { error = invalid; return@OutlinedButton }
                    fingerprint = ""; discoveredIdentity = null; discoveredAlgorithm = null
                    verified = false; error = null; busy = true
                    val requestedHost = host
                    val requestedPort = sshPort
                    scope.launch {
                        try {
                            when (val result = withContext(Dispatchers.IO) {
                                hostKeyDiscoveryPort.discover(requestedHost, requestedPort)
                            }) {
                                is HostKeyDiscoveryResult.Unverified -> {
                                    if (host == requestedHost && sshPort == requestedPort &&
                                        result.host == requestedHost && result.port == requestedPort &&
                                        com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint.parse(
                                            com.velumtegra.xuimobile.core.model.HostKeyFingerprint(result.sha256),
                                        ) is com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult.Valid
                                    ) {
                                        fingerprint = result.sha256
                                        discoveredIdentity = "$requestedHost:$requestedPort"
                                        discoveredAlgorithm = result.algorithm
                                        verified = false // Observation is NEVER independent authentication.
                                    } else error = "Данные сервера изменились во время проверки. Повторите запрос."
                                }
                                is HostKeyDiscoveryResult.Failure -> error = result.message
                            }
                        } catch (cancel: kotlinx.coroutines.CancellationException) {
                            throw cancel
                        } catch (_: Exception) {
                            error = "Не удалось получить публичный SSH host key."
                        } finally { busy = false }
                    }
                },
                enabled = !busy && hostKeyDiscoveryPort != null,
                modifier = Modifier.fillMaxWidth().testTag("enrollment_discover_host_key"),
            ) { Text(if (busy) "Получаем публичный ключ…" else "Получить отпечаток с сервера") }
            if (discoveredIdentity != null) {
                Text(
                    "Получен НЕПРОВЕРЕННЫЙ ключ $discoveredAlgorithm для $discoveredIdentity. Сверьте SHA-256 по независимому каналу.",
                    modifier = Modifier.testTag("enrollment_discovered_warning"),
                    color = MaterialTheme.colorScheme.error,
                )
            }
            OutlinedTextField(
                value = fingerprint, onValueChange = {
                    fingerprint = it; discoveredIdentity = null; discoveredAlgorithm = null
                    verified = false; error = null
                },
                label = { Text("SHA256 отпечаток SSH host key") },
                modifier = Modifier.fillMaxWidth().testTag("enrollment_fingerprint"),
                singleLine = true, enabled = !busy,
            )
            androidx.compose.foundation.layout.Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        usePrivateKey = false
                        selectedPrivateKey.clear(); keySelected = false; keyPassphrase = ""
                        verified = false; error = null
                    },
                    enabled = !busy && usePrivateKey,
                    modifier = Modifier.testTag("enrollment_auth_password"),
                ) { Text("Пароль") }
                OutlinedButton(
                    onClick = {
                        usePrivateKey = true
                        password = ""; verified = false; error = null
                    },
                    enabled = !busy && !usePrivateKey,
                    modifier = Modifier.testTag("enrollment_auth_private_key"),
                ) { Text("SSH-ключ") }
            }
            if (usePrivateKey) {
                Text("Импортируйте приватный PEM/OpenSSH-ключ через системный выбор файла. Копия файла хранится только в памяти до сохранения и очищается; размер до 1 МиБ.")
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth().testTag("enrollment_pick_private_key"),
                    enabled = !busy,
                    onClick = {
                        selectedPrivateKey.clear(); keySelected = false; verified = false; error = null
                        keyPassphrase = ""
                        val override = privateKeyPickerOverride
                        if (override != null) override { bytes -> acceptKey(bytes) }
                        else keyPicker.launch(arrayOf("*/*"))
                    },
                ) { Text("Выбрать приватный ключ") }
                Text(
                    if (keySelected) "Приватный ключ выбран (содержимое не отображается)." else "Приватный ключ не выбран.",
                    modifier = Modifier.testTag("enrollment_key_selection_status"),
                )
                RevealablePasswordField(
                    value = keyPassphrase,
                    onValueChange = { keyPassphrase = it; error = null },
                    label = { Text("Парольная фраза ключа (если есть)") },
                    modifier = Modifier.fillMaxWidth().testTag("enrollment_key_passphrase"),
                    enabled = !busy,
                )
            } else {
                RevealablePasswordField(
                    value = password, onValueChange = { password = it; error = null },
                    label = { Text("SSH-пароль") },
                    modifier = Modifier.fillMaxWidth().testTag("enrollment_password"),
                    enabled = !busy,
                )
            }
            androidx.compose.foundation.layout.Row {
                Checkbox(
                    checked = verified, onCheckedChange = { verified = it; error = null },
                    enabled = !busy && fingerprint.isNotBlank(), modifier = Modifier.testTag("enrollment_pin_verified"),
                )
                Text(
                    "Я лично сверил этот SHA-256 отпечаток с независимым доверенным источником.",
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        } else {
            Text("Сначала создадим локальную карточку, затем откроем настройку SSH для этого же сервера. Если выйти на втором шаге, карточка сохранится и SSH можно добавить позже.")
            OutlinedTextField(
                value = name, onValueChange = { name = it; error = null },
                label = { Text("Название сервера") },
                modifier = Modifier.fillMaxWidth().testTag("enrollment_server_name"),
                singleLine = true, enabled = !busy,
            )
        }
        if (error != null) Text(
            requireNotNull(error),
            modifier = Modifier.testTag("enrollment_error"),
            color = MaterialTheme.colorScheme.error,
        )
        Button(
            modifier = Modifier.fillMaxWidth().testTag("enrollment_save"),
            enabled = !busy,
            onClick = {
                if (busy) return@Button
                val keyBytes = if (addingAccess && usePrivateKey) selectedPrivateKey.copyForSubmission() else null
                val passphraseBytes = if (keyBytes != null && keyPassphrase.isNotEmpty()) {
                    keyPassphrase.toByteArray(Charsets.UTF_8)
                } else null
                val failure = when {
                    !addingAccess -> EnrollmentInputPolicy.validateName(name)
                    usePrivateKey && keyBytes == null -> "Сначала выберите приватный SSH-ключ."
                    usePrivateKey -> EnrollmentInputPolicy.validatePrivateKeyAccess(
                        requireNotNull(serverId), host, sshPort, username, fingerprint, verified,
                        requireNotNull(keyBytes), passphraseBytes?.size ?: 0,
                    )
                    else -> EnrollmentInputPolicy.validateAccess(
                        requireNotNull(serverId), host, sshPort, username, fingerprint, verified,
                        password.toByteArray(Charsets.UTF_8).size,
                    )
                }
                if (failure != null) {
                    keyBytes?.fill(0); passphraseBytes?.fill(0)
                    error = failure
                    return@Button
                }
                val passwordBytes = if (addingAccess && !usePrivateKey) {
                    password.toByteArray(Charsets.UTF_8)
                } else null
                password = ""; keyPassphrase = "" // Never retain submitted text in UI state.
                if (keyBytes != null) { selectedPrivateKey.clear(); keySelected = false }
                busy = true
                error = null
                scope.launch(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        val result = when {
                            !addingAccess -> port.addServer(name)
                            usePrivateKey -> port.addPrivateKeyAccess(
                                requireNotNull(serverId), host, sshPort, username, fingerprint,
                                verified, requireNotNull(keyBytes), passphraseBytes,
                            )
                            else -> port.addPasswordAccess(
                                requireNotNull(serverId), host, sshPort, username, fingerprint,
                                verified, requireNotNull(passwordBytes),
                            )
                        }
                        when (result) {
                            is EnrollmentResult.Saved -> {
                                if (!addingAccess && onServerCreated != null) {
                                    onServerCreated(result.recordId, name.trim())
                                } else onSaved()
                            }
                            is EnrollmentResult.Rejected -> error = result.message
                        }
                    } catch (cancel: kotlinx.coroutines.CancellationException) {
                        throw cancel
                    } catch (_: Exception) {
                        error = "Не удалось подтвердить локальное сохранение. Обновите список."
                    } finally {
                        passwordBytes?.fill(0); keyBytes?.fill(0); passphraseBytes?.fill(0)
                        busy = false
                    }
                }
            },
        ) { Text(if (busy) "Сохраняем…" else if (addingAccess) "Сохранить SSH-доступ" else "Создать сервер") }
        OutlinedButton(
            onClick = onBack, enabled = !busy,
            modifier = Modifier.fillMaxWidth().testTag("enrollment_cancel"),
        ) { Text("Назад без сохранения") }
        Text(
            "Проверка host key делает только SSH handshake и всегда отвергает неизвестный ключ до аутентификации. Сохранение — локальное; команд на VPS нет.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
